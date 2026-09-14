import asyncio
import ipaddress
import json
import os
from typing import Optional, List, Dict, Any, Union
import psutil
from ..config import resolve_tool, TEMP_DIR
from ..helpers import run_powershell_async, run_command_async, launch_gui_app, launch_gui_app_proc, safe_truncate
from ..security import wrap_untrusted_data, validate_output_path

FAKENET_STATE_FILE = TEMP_DIR / "fakenet_state.json"


def is_public_ioc_ip(ip_str: str) -> bool:
    """Check if an IPv4/IPv6 string is a valid, publicly-routable global IP (not private, loopback, or multicast)."""
    try:
        obj = ipaddress.ip_address(ip_str.strip())
        return (
            obj.is_global
            and not obj.is_multicast
            and not obj.is_reserved
            and not obj.is_link_local
            and not obj.is_loopback
            and not obj.is_private
        )
    except ValueError:
        return False


async def monitor_network(duration: int = 30) -> str:
    """Monitor active TCP/UDP connections and DNS cache entries for a specified duration in seconds using socket tuple tracking."""
    duration = max(1, min(300, int(duration)))
    def _snapshot_sockets() -> dict[tuple, dict]:
        snaps = {}
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "*:*"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*:*"
                key = (c.pid or 0, laddr, raddr, c.status or "")
                pname = "System" if c.pid == 4 else ""
                if c.pid and c.pid > 4:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pname = "unknown"
                proto = "TCP" if c.type == 1 else ("UDP" if c.type == 2 else str(c.type))
                snaps[key] = {
                    "proto": proto,
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": c.status or "",
                    "pid": c.pid or 0,
                    "pname": pname,
                }
        except Exception:
            pass
        return snaps

    baseline_sockets = _snapshot_sockets()
    new_sockets = {}

    poll_interval = 1
    iterations = max(1, duration // poll_interval)
    for _ in range(iterations):
        await asyncio.sleep(poll_interval)
        current = _snapshot_sockets()
        for k, v in current.items():
            if k not in baseline_sockets and k not in new_sockets:
                new_sockets[k] = v

    lines = [
        f"=== Network Socket Monitoring ({duration}s) ===",
        f"Baseline Sockets: {len(baseline_sockets)}",
        f"New Sockets Captured: {len(new_sockets)}\n",
        "--- New Socket Connections ---"
    ]

    if new_sockets:
        for s in list(new_sockets.values())[:40]:
            lines.append(f"  [{s['proto']}] {s['status']:<12} {s['laddr']} -> {s['raddr']} [PID: {s['pid']} {s['pname']}]")
        if len(new_sockets) > 40:
            lines.append(f"  ... and {len(new_sockets) - 40} more new sockets.")
    else:
        lines.append("  No new network connections detected during monitoring window.")

    # DNS Client Cache
    lines.append(f"\n--- Recent DNS Cache Entries ---")
    stdout, _, _ = await run_powershell_async(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 25 | ForEach-Object { \"$($_.Entry) -> $($_.Data) (Type: $($_.Type))\" }",
        timeout=15
    )
    if stdout.strip():
        for l in stdout.strip().splitlines():
            lines.append(f"  {l.strip()}")
    else:
        lines.append("  DNS cache empty or unchanged.")

    return safe_truncate("\n".join(lines))


# ── IN-MEMORY FAKENET AUTHORITATIVE STATE & VALIDATION ───────────────────────
_ACTIVE_FAKENET_SESSION: Optional[Dict[str, Any]] = None
FAKENET_ROUTE_ADDED = False


def validate_fakenet_recovery_state(data: Any) -> Optional[dict]:
    """Strictly validate fakenet crash recovery state dictionary against schema."""
    if not isinstance(data, dict):
        return None

    dns_list = data.get("dns_baseline")
    if not isinstance(dns_list, list) or not dns_list:
        return None

    valid_dns = []
    for entry in dns_list:
        if not isinstance(entry, dict):
            return None
        if_idx = entry.get("interface_index")
        if not isinstance(if_idx, int) or if_idx <= 0 or if_idx > 65535:
            return None
        mode = entry.get("mode")
        if mode not in ("dhcp", "static"):
            return None
        addrs = entry.get("server_addresses")
        if not isinstance(addrs, list):
            return None
        valid_addrs = []
        for a in addrs:
            if not isinstance(a, str):
                return None
            try:
                ip = ipaddress.IPv4Address(a.strip())
                valid_addrs.append(str(ip))
            except ValueError:
                return None
        if mode == "static" and not valid_addrs:
            return None
        valid_dns.append({
            "interface_index": if_idx,
            "mode": mode,
            "server_addresses": valid_addrs
        })

    route_obj = data.get("route")
    valid_route = {"created": False}
    if route_obj is not None:
        if not isinstance(route_obj, dict):
            return None
        created = route_obj.get("created")
        if not isinstance(created, bool):
            return None
        if created:
            dest = route_obj.get("destination")
            if dest != "0.0.0.0/0":
                return None
            if_idx = route_obj.get("interface_index")
            if not isinstance(if_idx, int) or if_idx <= 0 or if_idx > 65535:
                return None
            next_hop = str(route_obj.get("next_hop", "")).strip()
            try:
                ipaddress.IPv4Address(next_hop)
            except ValueError:
                return None
            metric = route_obj.get("metric")
            if not isinstance(metric, int) or metric <= 0 or metric > 9999:
                return None
            valid_route = {
                "created": True,
                "destination": dest,
                "interface_index": if_idx,
                "next_hop": next_hop,
                "metric": metric
            }

    return {
        "dns_baseline": valid_dns,
        "route": valid_route
    }


async def fakenet_start_structured() -> dict:
    """Start FakeNet-NG and return structured state dict: {ok: bool, pid: Optional[int], message: str, error: Optional[str]}."""
    global _ACTIVE_FAKENET_SESSION, FAKENET_ROUTE_ADDED
    import time
    fakenet_path = resolve_tool("fakenet")

    # Terminate prior tracked session if running; do not use wildcard process killing
    if _ACTIVE_FAKENET_SESSION and _ACTIVE_FAKENET_SESSION.get("pid"):
        prior_pid = _ACTIVE_FAKENET_SESSION["pid"]
        if psutil.pid_exists(prior_pid):
            try:
                psutil.Process(prior_pid).kill()
            except Exception:
                pass

    # 1. Capture exact authoritative DNS baseline for each IPv4 interface (including DHCP status)
    ps_capture_dns = r"""
$adapters = @()
$ipIfs = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue
foreach ($ipIf in $ipIfs) {
    $idx = $ipIf.InterfaceIndex
    $dhcpMode = if ($ipIf.Dhcp -eq 1) { 'dhcp' } else { 'static' }
    $dnsObj = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $addrs = if ($dnsObj -and $dnsObj.ServerAddresses) { @($dnsObj.ServerAddresses) } else { @() }
    $adapters += [PSCustomObject]@{
        InterfaceIndex = $idx
        Mode = $dhcpMode
        ServerAddresses = $addrs
    }
}
$adapters | ConvertTo-Json -Compress
"""
    dns_out, _, _ = await run_powershell_async(ps_capture_dns, timeout=15)
    dns_baseline = []
    try:
        raw_dns = json.loads(dns_out.strip())
        if isinstance(raw_dns, dict):
            raw_dns = [raw_dns]
        for entry in raw_dns:
            idx = entry.get("InterfaceIndex")
            mode = entry.get("Mode", "dhcp")
            addrs = entry.get("ServerAddresses") or []
            if isinstance(idx, int) and idx > 0:
                valid_ips = []
                for a in addrs:
                    try:
                        valid_ips.append(str(ipaddress.IPv4Address(str(a).strip())))
                    except ValueError:
                        pass
                dns_baseline.append({
                    "interface_index": idx,
                    "mode": mode if mode in ("dhcp", "static") else "dhcp",
                    "server_addresses": valid_ips
                })
    except Exception:
        pass

    if not dns_baseline:
        err_msg = "[-] Error: Failed to capture network interface baseline. FakeNet launch aborted for host safety."
        return {"ok": False, "pid": None, "message": err_msg, "error": err_msg}

    # 2. Provision default route only if completely missing
    route_info = {"created": False}
    ps_route = r"""
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
if (-not $gw -or $gw -eq '0.0.0.0') {
    $ipObj = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1
    if ($ipObj) {
        $ip = $ipObj.IPAddress
        $octets = $ip -split '\.'
        $lastOctet = if ($octets[3] -eq '1') { '2' } else { '1' }
        $fakeGw = "$($octets[0]).$($octets[1]).$($octets[2]).$lastOctet"
        $ifIdx = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1).InterfaceIndex
        $r = New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIdx -NextHop $fakeGw -RouteMetric 250 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        if ($r) {
            Write-Output "$ifIdx|$fakeGw"
        }
    }
} else {
    Write-Output "EXISTING_ROUTE"
}
"""
    route_out, _, _ = await run_powershell_async(ps_route, timeout=15)
    route_out_str = route_out.strip()
    if "|" in route_out_str:
        parts = route_out_str.split("|")
        try:
            r_idx = int(parts[0])
            r_gw = str(ipaddress.IPv4Address(parts[1].strip()))
            route_info = {
                "created": True,
                "destination": "0.0.0.0/0",
                "interface_index": r_idx,
                "next_hop": r_gw,
                "metric": 250
            }
            FAKENET_ROUTE_ADDED = True
        except Exception:
            pass

    # 3. Store authoritative in-memory state and write persistent recovery state file
    _ACTIVE_FAKENET_SESSION = {
        "dns_baseline": dns_baseline,
        "route": route_info,
        "started_at": time.time(),
        "pid": None
    }
    try:
        with open(FAKENET_STATE_FILE, "w", encoding="utf-8") as sf:
            json.dump(_ACTIVE_FAKENET_SESSION, sf, indent=2)
    except Exception:
        pass

    # 4. Launch FakeNet and capture exact PID
    launch_res, pid = await launch_gui_app_proc(fakenet_path)
    if not pid:
        if route_info.get("created"):
            clean_ps = (
                f"Remove-NetRoute -DestinationPrefix '0.0.0.0/0' "
                f"-InterfaceIndex {route_info['interface_index']} "
                f"-NextHop '{route_info['next_hop']}' "
                f"-RouteMetric 250 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
            )
            await run_powershell_async(clean_ps, timeout=10)
            FAKENET_ROUTE_ADDED = False
        return {
            "ok": False,
            "pid": None,
            "message": f"[-] FakeNet launch failed: {launch_res}",
            "error": f"Failed to spawn FakeNet process: {launch_res}"
        }

    # Readiness polling: verify specific fakenet process PID is alive and running
    alive = False
    for _ in range(8):
        await asyncio.sleep(1)
        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                    alive = True
                    break
            except Exception:
                pass

    if alive:
        _ACTIVE_FAKENET_SESSION["pid"] = pid
        msg = (
            f"=== FakeNet-NG Started ===\n"
            f"Executable:  {fakenet_path}\n"
            f"PID:         {pid}\n"
            f"Status:      [ACTIVE] Intercepting DNS, HTTP/HTTPS, and TCP/UDP traffic.\n"
            f"Route State: {'Temporary default route provisioned' if route_info.get('created') else 'Default route verified'}\n"
            f"DNS State:   Baseline saved ({len(dns_baseline)} adapter(s) tracked)"
        )
        return {
            "ok": True,
            "pid": pid,
            "message": msg,
            "error": None
        }

    # If it exited immediately, clean up route
    if route_info.get("created"):
        clean_ps = (
            f"Remove-NetRoute -DestinationPrefix '0.0.0.0/0' "
            f"-InterfaceIndex {route_info['interface_index']} "
            f"-NextHop '{route_info['next_hop']}' "
            f"-RouteMetric 250 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
        )
        await run_powershell_async(clean_ps, timeout=10)
        FAKENET_ROUTE_ADDED = False

    fail_msg = (
        f"[-] FakeNet-NG failed to start or exited immediately (PID: {pid}).\n"
        f"Launch status: {launch_res}\n"
        f"[!] FakeNet requires Administrator elevation to install WinDivert network packet filtering driver."
    )
    return {
        "ok": False,
        "pid": None,
        "message": fail_msg,
        "error": "FakeNet process exited immediately or driver initialization failed"
    }


async def fakenet_start() -> str:
    """Start FakeNet-NG network simulation tool in the background with baseline DNS capture, auto-gateway provisioning, and readiness verification."""
    res = await fakenet_start_structured()
    return res["message"]


async def network_connections_list(filter_pid: int = 0, state: str = "") -> str:
    """Instant point-in-time snapshot of active listening ports and established sockets with owning process names and paths."""
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as e:
        return f"Error querying network connections: {e}"

    lines = [
        "=== Active Network Sockets Snapshot ===",
        f"Total Sockets: {len(connections)}",
        f"{'Proto':<6} {'Local Address':<22} {'Remote Address':<22} {'State':<12} {'PID':<6} {'Process':<20}",
        "-" * 95
    ]

    count = 0
    for c in connections:
        if filter_pid and c.pid != filter_pid:
            continue
        if state and state.upper() not in (c.status or "").upper():
            continue

        proto = "TCP" if c.type == 1 else ("UDP" if c.type == 2 else str(c.type))
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "*:*"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*:*"
        status = c.status if c.status else "NONE"
        pid = c.pid or 0
        pname = "System" if pid == 4 else ("Idle" if pid == 0 else "")
        if pid > 4:
            try:
                pname = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pname = "unknown"

        lines.append(f"{proto:<6} {laddr:<22} {raddr:<22} {status:<12} {pid:<6} {pname:<20}")
        count += 1
        if count >= 80:
            break

    if count >= 80:
        lines.append(f"\n[... and {len(connections) - 80} more sockets omitted ...]")
    if count == 0:
        lines.append("  No sockets matching filter criteria.")

    return "\n".join(lines)


async def fakenet_stop_structured(start_time: Optional[float] = None) -> dict:
    """Stop FakeNet-NG, verify exact DNS and route baseline restoration, and return structured results."""
    global _ACTIVE_FAKENET_SESSION, FAKENET_ROUTE_ADDED
    import re

    # 1. Resolve state: prefer in-memory session; fallback to validated crash recovery file
    state = None
    if _ACTIVE_FAKENET_SESSION:
        state = _ACTIVE_FAKENET_SESSION
    elif os.path.isfile(FAKENET_STATE_FILE):
        try:
            with open(FAKENET_STATE_FILE, "r", encoding="utf-8") as sf:
                raw_data = json.load(sf)
            state = validate_fakenet_recovery_state(raw_data)
        except Exception:
            state = None

    # Terminate specific FakeNet PID only; avoid killing external/analyst processes
    target_pid = state.get("pid") if state else None
    if target_pid and psutil.pid_exists(target_pid):
        try:
            psutil.Process(target_pid).kill()
        except Exception:
            pass

    # 2. Exact route teardown matching created route parameters
    route_verified = True
    if state and state.get("route", {}).get("created"):
        r_info = state["route"]
        rm_route_cmd = (
            f"Remove-NetRoute -DestinationPrefix '{r_info.get('destination', '0.0.0.0/0')}' "
            f"-InterfaceIndex {int(r_info['interface_index'])} "
            f"-NextHop '{r_info['next_hop']}' "
            f"-RouteMetric {int(r_info['metric'])} "
            f"-PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue"
        )
        await run_powershell_async(rm_route_cmd, timeout=10)
        FAKENET_ROUTE_ADDED = False

        # Verify route is actually gone
        v_route_cmd = (
            f"Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
            f"-InterfaceIndex {int(r_info['interface_index'])} "
            f"-NextHop '{r_info['next_hop']}' -ErrorAction SilentlyContinue"
        )
        v_rout, _, _ = await run_powershell_async(v_route_cmd, timeout=10)
        route_verified = (len(v_rout.strip()) == 0)

    # 3. Exact DNS restoration based on validated baseline mode (DHCP vs Static)
    if state and state.get("dns_baseline"):
        restore_cmds = []
        for entry in state["dns_baseline"]:
            idx = int(entry["interface_index"])
            mode = entry.get("mode", "dhcp")
            addrs = entry.get("server_addresses") or []
            if mode == "static" and addrs:
                valid_ips = [f"'{str(ipaddress.IPv4Address(a))}'" for a in addrs]
                restore_cmds.append(
                    f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({', '.join(valid_ips)}) -ErrorAction SilentlyContinue"
                )
            else:
                restore_cmds.append(
                    f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses -ErrorAction SilentlyContinue"
                )
        restore_cmds.append("Clear-DnsClientCache -ErrorAction SilentlyContinue")
        await run_powershell_async("\n".join(restore_cmds), timeout=15)
    else:
        fallback_cmd = r"""
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
"""
        await run_powershell_async(fallback_cmd, timeout=15)

    # 4. Verify effective DNS configuration against pre-launch baseline
    dns_verified = True
    if state and state.get("dns_baseline"):
        ps_check_dns = r"""
$adapters = @()
$ipIfs = Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue
foreach ($ipIf in $ipIfs) {
    $idx = $ipIf.InterfaceIndex
    $dhcpMode = if ($ipIf.Dhcp -eq 1) { 'dhcp' } else { 'static' }
    $dnsObj = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $addrs = if ($dnsObj -and $dnsObj.ServerAddresses) { @($dnsObj.ServerAddresses) } else { @() }
    $adapters += [PSCustomObject]@{
        InterfaceIndex = $idx
        Mode = $dhcpMode
        ServerAddresses = $addrs
    }
}
$adapters | ConvertTo-Json -Compress
"""
        chk_out, _, _ = await run_powershell_async(ps_check_dns, timeout=15)
        try:
            curr_data = json.loads(chk_out.strip())
            if isinstance(curr_data, dict):
                curr_data = [curr_data]
            curr_by_idx = {c.get("InterfaceIndex"): c for c in curr_data}
            for base in state["dns_baseline"]:
                b_idx = base["interface_index"]
                c_entry = curr_by_idx.get(b_idx)
                if not c_entry:
                    continue
                b_mode = base.get("mode", "dhcp")
                b_addrs = sorted(base.get("server_addresses") or [])
                c_mode = c_entry.get("Mode", "dhcp")
                c_raw_addrs = c_entry.get("ServerAddresses") or []
                c_addrs = sorted([str(a).strip() for a in c_raw_addrs if str(a).strip()])
                if b_mode == "static":
                    if b_addrs != c_addrs:
                        dns_verified = False
                        break
                elif b_mode == "dhcp":
                    if c_mode != "dhcp" and b_addrs != c_addrs:
                        dns_verified = False
                        break
        except Exception:
            dns_verified = False

    # 5. Clean up state file and in-memory session only after verified teardown
    if dns_verified and route_verified and os.path.isfile(FAKENET_STATE_FILE):
        try:
            os.remove(FAKENET_STATE_FILE)
        except Exception:
            pass
    _ACTIVE_FAKENET_SESSION = None

    # Search for fakenet logs
    candidates = [
        r"C:\Tools\fakenet\fakenet3.5\fakenet.log",
        r"C:\Tools\fakenet\fakenet.log",
        str(TEMP_DIR / "fakenet.log"),
        os.path.expanduser(r"~\Desktop\fakenet.log"),
    ]
    raw_log = "Log file not found."
    log_dir = r"C:\Tools\fakenet\fakenet3.5"
    for c in candidates:
        if os.path.isfile(c):
            log_dir = os.path.dirname(c)
            with open(c, "r", encoding="utf-8", errors="replace") as f:
                raw_log = f.read()[-6000:]
            break

    # Harvest dumped HTTP POST requests belonging to the current run
    dumped_posts = []
    if os.path.isdir(log_dir):
        for fname in os.listdir(log_dir):
            if fname.startswith("http_") and fname.endswith(".txt"):
                fpath = os.path.join(log_dir, fname)
                try:
                    if start_time and os.path.getmtime(fpath) < (start_time - 2.0):
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        raw_body = fh.read(1000)
                        dumped_posts.append(wrap_untrusted_data(f"[{fname}]\n{raw_body}", max_chars=1200, label=f"HTTP POST {fname}"))
                except Exception:
                    pass

    # Extract domains and IP IOCs from FakeNet log
    domains = set(re.findall(r"(?:Query|Request|Host|Domain)[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", raw_log))
    raw_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_log))
    ips = {ip for ip in raw_ips if is_public_ioc_ip(ip)}

    res = [
        "=== FakeNet-NG Stopped ===",
        f"Restoration Status: [{'SUCCESS: Exact DNS & Route Restored' if (dns_verified and route_verified) else 'WARNING: Baseline Verification Incomplete'}]",
        f"  - DNS Configuration Match: {dns_verified}",
        f"  - Temporary Route Removed:  {route_verified}",
        ""
    ]

    if domains or ips:
        res.append("--- Extracted Network IOCs (from Simulation) ---")
        if domains:
            res.append("Contacted Domains:")
            for d in sorted(domains)[:20]:
                res.append(f"  - {d.replace('.', '[.]')}")
        if ips:
            res.append("\nRemote IP Addresses:")
            for ip in sorted(ips)[:20]:
                res.append(f"  - {ip.replace('.', '[.]')}")
        res.append("")

    if dumped_posts:
        res.append(f"--- Harvested HTTP POST Exfiltration Dumps ({len(dumped_posts)} Captured) ---")
        for dp in dumped_posts[:5]:
            res.append(dp)
            res.append("-" * 40)
        res.append("")

    res.append("--- Simulation Log Summary ---")
    res.append(wrap_untrusted_data(raw_log, max_chars=4000, label="FAKENET ACTIVITY LOG"))

    report_str = safe_truncate("\n".join(res))
    return {
        "ok": bool(dns_verified and route_verified),
        "dns_verified": dns_verified,
        "route_verified": route_verified,
        "report": report_str,
        "error": None if (dns_verified and route_verified) else "DNS or Route baseline restoration verification failed"
    }


async def fakenet_stop(start_time: Optional[float] = None) -> str:
    """Stop FakeNet-NG, restore network routing and exact adapter DNS baseline, extract recent activity logs, and harvest exfiltrated HTTP payloads."""
    res = await fakenet_stop_structured(start_time=start_time)
    return res["report"]


async def wireshark_capture(duration: int = 20, output_pcap: str = r"C:\temp\mal_mcp\capture.pcap") -> str:
    """Capture network packets using tshark for a specified duration."""
    duration = max(1, min(300, int(duration)))
    output_pcap = str(validate_output_path(output_pcap))
    tshark_path = resolve_tool("tshark")
    os.makedirs(os.path.dirname(output_pcap), exist_ok=True)

    cmd = [tshark_path, "-a", f"duration:{duration}", "-w", output_pcap]
    stdout, stderr, code = await run_command_async(cmd, timeout=duration + 15)

    if os.path.isfile(output_pcap):
        size = os.path.getsize(output_pcap)
        return (
            f"=== TShark Packet Capture Complete ===\n"
            f"File:     {output_pcap}\n"
            f"Size:     {size} bytes ({round(size/1024, 2)} KB)\n"
            f"Duration: {duration}s\n\n"
            f"Next: Call 'pcap_analyze' to extract DNS queries, HTTP requests, and TLS SNI domains."
        )
    return f"TShark capture failed:\n{stderr}\n{stdout}"


async def pcap_analyze(pcap_path: str = r"C:\temp\mal_mcp\capture.pcap") -> str:
    """Analyze a PCAP packet capture with tshark: extract DNS queries, HTTP requests, TLS SNI, endpoints, and structured Network IOCs."""
    try:
        pcap_path = str(validate_output_path(pcap_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    if not os.path.isfile(pcap_path):
        return f"PCAP file not found: {pcap_path}"

    tshark_path = resolve_tool("tshark")
    file_size = os.path.getsize(pcap_path)
    if file_size == 0:
        return f"PCAP file is empty (0 bytes): {pcap_path}"

    report = [
        "=" * 65,
        "NETWORK PACKET CAPTURE (PCAP) ANALYSIS REPORT",
        "=" * 65,
        f"File: {pcap_path} ({round(file_size/1024, 2)} KB)\n"
    ]

    # 1. DNS Queries
    cmd_dns = [tshark_path, "-r", pcap_path, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"]
    stdout_dns, _, _ = await run_command_async(cmd_dns, timeout=30)
    dns_queries = set(filter(None, [q.strip() for q in stdout_dns.splitlines()]))

    report.append(f"--- 1. DNS Queries ({len(dns_queries)} Unique Domains) ---")
    if dns_queries:
        for domain in sorted(dns_queries)[:30]:
            report.append(f"  [DNS] {domain}")
        if len(dns_queries) > 30:
            report.append(f"  ... and {len(dns_queries) - 30} more domains")
    else:
        report.append("  No DNS queries found in capture.")
    report.append("")

    # 2. HTTP Requests
    cmd_http = [
        tshark_path, "-r", pcap_path, "-Y", "http.request",
        "-T", "fields",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.user_agent"
    ]
    stdout_http, _, _ = await run_command_async(cmd_http, timeout=30)
    http_requests = []
    for line in stdout_http.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            method = parts[0]
            host = parts[1]
            uri = parts[2]
            ua = parts[3] if len(parts) > 3 else "None"
            http_requests.append({"method": method, "host": host, "uri": uri, "ua": ua})

    report.append(f"--- 2. HTTP Web Requests ({len(http_requests)} Requests) ---")
    if http_requests:
        for req in http_requests[:25]:
            report.append(f"  [{req['method']}] http://{req['host']}{req['uri']}")
            if req['ua'] and req['ua'] != "None":
                report.append(f"       User-Agent: {req['ua']}")
        if len(http_requests) > 25:
            report.append(f"  ... and {len(http_requests) - 25} more HTTP requests")
    else:
        report.append("  No cleartext HTTP requests found.")
    report.append("")

    # 3. TLS / HTTPS Server Name Indication (SNI)
    cmd_tls = [
        tshark_path, "-r", pcap_path,
        "-Y", "tls.handshake.extension.type == 0",
        "-T", "fields",
        "-e", "tls.handshake.extensions_server_name"
    ]
    stdout_tls, _, _ = await run_command_async(cmd_tls, timeout=30)
    tls_snis = set(filter(None, [s.strip() for s in stdout_tls.splitlines()]))

    report.append(f"--- 3. Encrypted TLS / HTTPS Handshakes ({len(tls_snis)} SNI Domains) ---")
    if tls_snis:
        for sni in sorted(tls_snis)[:30]:
            report.append(f"  [TLS-SNI] {sni}")
    else:
        report.append("  No TLS Client Hello SNI domains identified.")
    report.append("")

    # 4. Remote IP Endpoints & Ports
    cmd_endpoints = [
        tshark_path, "-r", pcap_path,
        "-T", "fields",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "udp.dstport"
    ]
    stdout_ep, _, _ = await run_command_async(cmd_endpoints, timeout=30)
    endpoints = set()
    for line in stdout_ep.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            ip = parts[0].strip()
            port = (parts[1].strip() or (parts[2].strip() if len(parts) > 2 else "")).strip()
            if ip and port and is_public_ioc_ip(ip):
                endpoints.add(f"{ip}:{port}")

    report.append(f"--- 4. Contacted Remote Endpoints ({len(endpoints)} Destinations) ---")
    if endpoints:
        for ep in sorted(endpoints)[:35]:
            report.append(f"  [External Endpoint Candidate] {ep}")
    else:
        report.append("  No external IP endpoints contacted.")
    report.append("")

    # 5. Structured Network IOC Summary
    report.append("--- 5. Extracted Network Indicators of Compromise (IOCs) ---")
    all_domains = sorted(dns_queries | tls_snis | {r['host'] for r in http_requests if r.get('host')})
    if all_domains:
        report.append("Domains:")
        for d in all_domains[:25]:
            defanged = d.replace(".", "[.]")
            report.append(f"  - {defanged}")
    if endpoints:
        report.append("\nRemote Sockets / External IP Endpoints:")
        for ep in sorted(endpoints)[:25]:
            defanged_ep = ep.replace(".", "[.]")
            report.append(f"  - {defanged_ep}")

    report.append("=" * 65)
    return wrap_untrusted_data(safe_truncate("\n".join(report)), label="PCAP ANALYSIS REPORT")
