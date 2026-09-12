import asyncio
import ipaddress
import json
import os
from typing import Optional
import psutil
from ..config import resolve_tool, TEMP_DIR
from ..helpers import run_powershell_async, run_command_async, launch_gui_app, safe_truncate

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


# Track whether a temporary default route was added for FakeNet interception
FAKENET_ROUTE_ADDED = False


async def fakenet_start() -> str:
    """Start FakeNet-NG network simulation tool in the background with baseline DNS capture, auto-gateway provisioning, and readiness verification."""
    global FAKENET_ROUTE_ADDED
    import time
    fakenet_path = resolve_tool("fakenet")

    # Stop any running instance
    await run_powershell_async("Stop-Process -Name fakenet* -Force -ErrorAction SilentlyContinue", timeout=10)

    # 1. Capture exact DNS baseline for each adapter
    dns_baseline = {}
    ps_capture_dns = r"Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceIndex, ServerAddresses | ConvertTo-Json -Compress"
    dns_out, _, _ = await run_powershell_async(ps_capture_dns, timeout=15)
    try:
        raw_dns = json.loads(dns_out.strip())
        if isinstance(raw_dns, dict):
            raw_dns = [raw_dns]
        for entry in raw_dns:
            idx = entry.get("InterfaceIndex")
            addrs = entry.get("ServerAddresses") or []
            if idx is not None:
                dns_baseline[str(idx)] = addrs
    except Exception:
        pass

    # 2. Provision default gateway only if missing
    route_added = False
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
            Write-Output "ROUTE_ADDED"
        }
    }
} else {
    Write-Output "EXISTING_ROUTE"
}
"""
    route_out, _, _ = await run_powershell_async(ps_route, timeout=15)
    if "ROUTE_ADDED" in route_out:
        route_added = True
        FAKENET_ROUTE_ADDED = True

    # 3. Persist run state to disk so crashes can recover baseline
    state_data = {
        "dns_baseline": dns_baseline,
        "route_added": route_added,
        "started_at": time.time()
    }
    try:
        with open(FAKENET_STATE_FILE, "w", encoding="utf-8") as sf:
            json.dump(state_data, sf, indent=2)
    except Exception:
        pass

    # 4. Launch FakeNet
    res = await launch_gui_app(fakenet_path)

    # Readiness polling: verify fakenet process is alive
    fakenet_proc = None
    for _ in range(8):
        await asyncio.sleep(1)
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if "fakenet" in p.info['name'].lower():
                    fakenet_proc = p
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if fakenet_proc:
            break

    if fakenet_proc:
        return (
            f"=== FakeNet-NG Started ===\n"
            f"Executable:  {fakenet_path}\n"
            f"PID:         {fakenet_proc.pid}\n"
            f"Status:      [ACTIVE] Intercepting DNS, HTTP/HTTPS, and TCP/UDP traffic.\n"
            f"Route State: {'Temporary default route provisioned' if route_added else 'Default route verified'}\n"
            f"DNS State:   Baseline saved ({len(dns_baseline)} adapter(s) tracked)"
        )

    # If it failed to start, clean up route
    if route_added:
        await run_powershell_async("Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -RouteMetric 250 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", timeout=10)
        FAKENET_ROUTE_ADDED = False

    return (
        f"[-] FakeNet-NG failed to start or exited immediately.\n"
        f"Launch status: {res}\n"
        f"[!] FakeNet requires Administrator elevation to install WinDivert network packet filtering driver."
    )


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


async def fakenet_stop(start_time: Optional[float] = None) -> str:
    """Stop FakeNet-NG, restore network routing and exact adapter DNS baseline, extract recent activity logs, and harvest exfiltrated HTTP payloads."""
    global FAKENET_ROUTE_ADDED
    import re

    # 1. Terminate FakeNet process
    await run_powershell_async("Stop-Process -Name fakenet* -Force -ErrorAction SilentlyContinue", timeout=15)

    # 2. Read persistent state if available
    state_data = {}
    if os.path.isfile(FAKENET_STATE_FILE):
        try:
            with open(FAKENET_STATE_FILE, "r", encoding="utf-8") as sf:
                state_data = json.load(sf)
        except Exception:
            pass

    route_added = state_data.get("route_added", FAKENET_ROUTE_ADDED)
    dns_baseline = state_data.get("dns_baseline", {})

    # 3. Revert provisional default route if one was added
    if route_added:
        await run_powershell_async("Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -RouteMetric 250 -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue", timeout=10)
        FAKENET_ROUTE_ADDED = False

    # 4. Restore adapter DNS settings: restore exact static IPs if baseline was static, or reset if DHCP
    if dns_baseline:
        restore_commands = []
        for if_idx, addrs in dns_baseline.items():
            if addrs:
                ip_list = ", ".join(f"'{a}'" for a in addrs)
                restore_commands.append(f"Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ServerAddresses @({ip_list}) -ErrorAction SilentlyContinue")
            else:
                restore_commands.append(f"Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ResetServerAddresses -ErrorAction SilentlyContinue")
        restore_commands.append("Clear-DnsClientCache -ErrorAction SilentlyContinue")
        await run_powershell_async("\n".join(restore_commands), timeout=15)
    else:
        # Fallback: reset active adapters
        ps_dns_restore = r"""
Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
    Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -ErrorAction SilentlyContinue
}
Clear-DnsClientCache -ErrorAction SilentlyContinue
"""
        await run_powershell_async(ps_dns_restore, timeout=15)

    # Clean up state file
    if os.path.isfile(FAKENET_STATE_FILE):
        try:
            os.remove(FAKENET_STATE_FILE)
        except Exception:
            pass

    # Search for fakenet logs
    candidates = [
        r"C:\Tools\fakenet\fakenet3.5\fakenet.log",
        r"C:\Tools\fakenet\fakenet.log",
        str(TEMP_DIR / "fakenet.log"),
        os.path.expanduser(r"~\Desktop\fakenet.log"),
    ]
    log_content = "Log file not found."
    log_dir = r"C:\Tools\fakenet\fakenet3.5"
    for c in candidates:
        if os.path.isfile(c):
            log_dir = os.path.dirname(c)
            with open(c, "r", encoding="utf-8", errors="replace") as f:
                log_content = f.read()[-6000:]
            break

    # Harvest dumped HTTP POST requests belonging to the current run
    dumped_posts = []
    if os.path.isdir(log_dir):
        for fname in os.listdir(log_dir):
            if fname.startswith("http_") and fname.endswith(".txt"):
                fpath = os.path.join(log_dir, fname)
                try:
                    # Filter out stale artifacts from previous runs if start_time is given
                    if start_time and os.path.getmtime(fpath) < (start_time - 2.0):
                        continue
                    with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                        dumped_posts.append(f"[{fname}]\n{fh.read(1000)}")
                except Exception:
                    pass

    # Extract domains and IP IOCs from FakeNet log
    domains = set(re.findall(r"(?:Query|Request|Host|Domain)[:\s]+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", log_content))
    raw_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_content))
    # Filter public IOCs
    ips = {ip for ip in raw_ips if is_public_ioc_ip(ip)}

    res = [
        "=== FakeNet-NG Stopped ===",
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

    res.append("--- Recent Activity Log ---")
    res.append(log_content)

    return safe_truncate("\n".join(res))


async def wireshark_capture(duration: int = 20, output_pcap: str = r"C:\temp\mal_mcp\capture.pcap") -> str:
    """Capture network packets using tshark for a specified duration."""
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
    return safe_truncate("\n".join(report))
