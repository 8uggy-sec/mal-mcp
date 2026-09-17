"""Dynamic analysis and process/registry monitoring tools for Flare-VM."""

import asyncio
import csv
import os
from pathlib import Path
from typing import Optional
import psutil
from ..config import resolve_tool, TEMP_DIR
from typing import Optional, Any, Dict
from ..helpers import run_command_async, run_powershell_async, launch_gui_app, launch_gui_app_proc, safe_truncate
from ..security import validate_output_path, wrap_untrusted_data, feature_enabled

_PROCMON_SESSION: Dict[str, Any] = {'pid': None, 'pml': None}


async def procmon_start(output_path: str = r"C:\temp\mal_mcp\procmon.pml") -> str:
    """Start Sysinternals Process Monitor capture in background with a backing PML file."""
    if not feature_enabled("MAL_MCP_ENABLE_DYNAMIC"):
        return (
            "Error: Refused. Feature 'MAL_MCP_ENABLE_DYNAMIC' is disabled by default for security.\n"
            "To enable this capability in your Flare-VM sandbox, set environment variable MAL_MCP_ENABLE_DYNAMIC=1."
        )
    try:
        output_path = str(validate_output_path(output_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        procmon_path = resolve_tool("procmon")
    except FileNotFoundError:
        return "[-] Tool Unavailable: Sysinternals procmon.exe was not found on Flare-VM."
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Terminate prior tracked session if running
    if _PROCMON_SESSION.get("pid") and psutil.pid_exists(_PROCMON_SESSION["pid"]):
        try:
            psutil.Process(_PROCMON_SESSION["pid"]).kill()
        except Exception:
            pass

    if os.path.isfile(output_path):
        try:
            os.remove(output_path)
        except Exception:
            pass

    args = ["/BackingFile", output_path, "/Quiet", "/Minimized", "/AcceptEula"]
    res, pid = await launch_gui_app_proc(procmon_path, args)
    _PROCMON_SESSION["pid"] = pid
    _PROCMON_SESSION["pml"] = output_path

    # Wait for backing file creation
    for _ in range(10):
        await asyncio.sleep(1)
        if os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
            size = os.path.getsize(output_path)
            return (
                f"=== ProcMon Started ===\n"
                f"Executable:   {procmon_path}\n"
                f"Backing PML:  {output_path} ({size} bytes allocated)\n"
                f"Status:       Capturing all system events in background.\n"
                f"Next:         Execute target, then call 'procmon_stop' to export summary."
            )

    return (
        f"ProcMon launched ({res}), but backing PML was not allocated at {output_path} within 10s.\n"
        f"[!] Note: Sysinternals ProcMon requires Administrator elevation to load PROCMON24.SYS driver.\n"
        f"    If running in non-elevated context, launch your terminal/IDE as Administrator or accept UAC prompt."
    )


KNOWN_SYSTEM_NOISE = {
    "SearchIndexer.exe", "SearchApp.exe", "TiWorker.exe", "TrustedInstaller.exe",
    "MpCmdRun.exe", "MsMpEng.exe", "taskhostw.exe", "System", "services.exe",
    "lsass.exe", "csrss.exe", "svchost.exe", "Registry"
}


async def procmon_stop(
    pml_path: str = r"C:\temp\mal_mcp\procmon.pml",
    csv_path: str = r"C:\temp\mal_mcp\procmon.csv",
    filter_process: str = "",
    ignore_noise: bool = True
) -> str:
    """Stop Process Monitor, convert captured PML to CSV, and analyze event operations with optional noise filtering."""
    if not feature_enabled("MAL_MCP_ENABLE_DYNAMIC"):
        return (
            "Error: Refused. Feature 'MAL_MCP_ENABLE_DYNAMIC' is disabled by default for security.\n"
            "To enable this capability in your Flare-VM sandbox, set environment variable MAL_MCP_ENABLE_DYNAMIC=1."
        )
    try:
        pml_path = str(validate_output_path(pml_path))
        csv_path = str(validate_output_path(csv_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        procmon_path = resolve_tool("procmon")
    except FileNotFoundError:
        return "[-] Tool Unavailable: Sysinternals procmon.exe was not found on Flare-VM."
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    # Terminate capturing instance gracefully
    await run_command_async([procmon_path, "/Terminate"], timeout=30)
    await asyncio.sleep(2)

    # Terminate specifically tracked PID
    tracked_pid = _PROCMON_SESSION.get("pid")
    if tracked_pid and psutil.pid_exists(tracked_pid):
        try:
            psutil.Process(tracked_pid).kill()
        except Exception:
            pass
    _PROCMON_SESSION["pid"] = None

    # Guard: Check if backing PML exists and has data before attempting conversion
    if not os.path.isfile(pml_path) or os.path.getsize(pml_path) == 0:
        pml_sz = os.path.getsize(pml_path) if os.path.isfile(pml_path) else 0
        return (
            f"[-] ProcMon capture file not found or empty ({pml_path}, size={pml_sz} bytes).\n"
            f"[!] Note: Sysinternals ProcMon requires Administrator elevation to load PROCMON24.SYS driver.\n"
            f"    If running in non-elevated context, launch your terminal/IDE as Administrator."
        )

    # Convert PML -> CSV asynchronously
    if os.path.isfile(csv_path):
        try:
            os.remove(csv_path)
        except Exception:
            pass

    conv_args = ["/OpenLog", pml_path, "/SaveAs", csv_path, "/AcceptEula"]
    _, conv_pid = await launch_gui_app_proc(procmon_path, conv_args)

    # Poll for CSV
    for _ in range(25):
        await asyncio.sleep(2)
        if os.path.isfile(csv_path) and os.path.getsize(csv_path) > 0:
            await asyncio.sleep(1)
            break

    if conv_pid and psutil.pid_exists(conv_pid):
        try:
            psutil.Process(conv_pid).kill()
        except Exception:
            pass

    if not os.path.isfile(csv_path):
        return f"ProcMon stopped, but CSV export was not generated at: {csv_path}. PML size: {os.path.getsize(pml_path) if os.path.isfile(pml_path) else 0} bytes"

    # Analyze CSV summary
    total_events = 0
    filtered_events = 0
    file_ops = 0
    reg_ops = 0
    net_ops = 0
    proc_ops = 0
    unique_procs = set()
    noise_count = 0

    # Read and sanitize CSV to handle UTF-16/UTF-8 BOM and prevent _csv.Error: line contains NUL
    with open(csv_path, "rb") as bf:
        raw_bytes = bf.read()

    if raw_bytes.startswith(b"\xff\xfe"):
        csv_text = raw_bytes.decode("utf-16", errors="replace")
    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
        csv_text = raw_bytes.decode("utf-8-sig", errors="replace")
    else:
        try:
            csv_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            csv_text = raw_bytes.decode("cp1252", errors="replace")

    sanitized_lines = [line.replace("\x00", "") for line in csv_text.splitlines() if line.strip()]
    reader = csv.reader(sanitized_lines)
    header = next(reader, None)
    for row in reader:
            if not row:
                continue
            total_events += 1
            if len(row) >= 4:
                proc_name = row[1].strip('" ')
                operation = row[3].strip('" ')

                if filter_process and filter_process.lower() not in proc_name.lower():
                    continue

                if ignore_noise and proc_name in KNOWN_SYSTEM_NOISE:
                    noise_count += 1
                    continue

                filtered_events += 1
                unique_procs.add(proc_name)

                if any(k in operation for k in ["CreateFile", "WriteFile", "ReadFile", "DeleteFile", "SetDispositionInformationFile"]):
                    file_ops += 1
                elif "Reg" in operation:
                    reg_ops += 1
                elif any(k in operation for k in ["TCP", "UDP"]):
                    net_ops += 1
                elif any(k in operation for k in ["Process Create", "Thread Create", "Load Image"]):
                    proc_ops += 1

            if total_events >= 100000:
                break

    lines = [
        "=== ProcMon Analysis Summary ===",
        f"PML Log:        {pml_path}",
        f"CSV Log:        {csv_path} ({os.path.getsize(csv_path)} bytes)",
        f"Raw Events:     {total_events}",
        f"Filtered Events:{filtered_events} (Noise filtered: {noise_count})",
        "",
        "--- Event Breakdown ---",
        f"File Operations:     {file_ops}",
        f"Registry Operations: {reg_ops}",
        f"Network Operations:  {net_ops}",
        f"Process Operations:  {proc_ops}",
        "",
        f"--- Active Monitored Processes ({len(unique_procs)}) ---",
    ]
    for p in sorted(unique_procs)[:30]:
        lines.append(f"  - {p}")
    if len(unique_procs) > 30:
        lines.append(f"  ... and {len(unique_procs) - 30} more")

    return "\n".join(lines)


async def procmon_export_csv(pml_path: str, csv_path: str) -> str:
    """Export an existing PML log file to CSV format safely without shell execution."""
    if not feature_enabled("MAL_MCP_ENABLE_DYNAMIC"):
        return (
            "Error: Refused. Feature 'MAL_MCP_ENABLE_DYNAMIC' is disabled by default for security.\n"
            "To enable this capability in your Flare-VM sandbox, set environment variable MAL_MCP_ENABLE_DYNAMIC=1."
        )
    try:
        pml_p = validate_output_path(pml_path)
        csv_p = validate_output_path(csv_path)
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    if not pml_p.is_file():
        return f"[-] Error: PML file does not exist: {pml_p}"

    try:
        procmon_path = resolve_tool("procmon")
    except FileNotFoundError:
        return "[-] Tool Unavailable: Sysinternals procmon.exe was not found on Flare-VM."
    cmd = [procmon_path, "/OpenLog", str(pml_p), "/SaveAs", str(csv_p), "/AcceptEula"]
    stdout, stderr, code = await run_command_async(cmd, timeout=90)
    if os.path.isfile(str(csv_p)):
        return f"Successfully exported CSV: {csv_p} ({os.path.getsize(str(csv_p))} bytes)"
    return f"Failed to export CSV: {stderr}\n{stdout}"


async def process_info(pid: int) -> str:
    """Inspect detailed information about a process: parent, modules, threads, handles, sockets."""
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return f"Process with PID {pid} not found."
    except psutil.AccessDenied:
        return f"Access denied for process PID {pid}."

    try:
        mem = proc.memory_info()
        threads = proc.threads()
        connections = proc.net_connections()
        parent = proc.parent()
        cmdline = " ".join(proc.cmdline())
        exe = proc.exe()
    except Exception as e:
        return f"Error retrieving info for PID {pid}: {e}"

    lines = [
        f"=== Process Details: {proc.name()} (PID: {pid}) ===",
        f"Path:          {exe}",
        f"Command Line:  {cmdline}",
        f"Parent PID:    {parent.pid if parent else 'None'} ({parent.name() if parent else ''})",
        f"Memory RSS:    {mem.rss // (1024*1024)} MB",
        f"Thread Count:  {len(threads)}",
        f"Open Sockets:  {len(connections)}",
        "",
        "--- Network Connections ---"
    ]
    for c in connections:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "*:*"
        lines.append(f"  {c.status:<12} {laddr} -> {raddr}")

    return "\n".join(lines)


async def regshot_snapshot(action: str = "compare", workspace_dir: Optional[str] = None) -> str:
    """Take a registry baseline ('before'), post-execution snapshot ('after'), or perform a differential comparison ('compare')."""
    base_dir = validate_output_path(workspace_dir) if workspace_dir else TEMP_DIR
    base_dir.mkdir(parents=True, exist_ok=True)
    before_hkcu = base_dir / "reg_hkcu_before.reg"
    before_hklm = base_dir / "reg_hklm_before.reg"
    after_hkcu = base_dir / "reg_hkcu_after.reg"
    after_hklm = base_dir / "reg_hklm_after.reg"
    tasks_before = base_dir / "tasks_before.txt"
    tasks_after = base_dir / "tasks_after.txt"
    services_before = base_dir / "services_before.txt"
    services_after = base_dir / "services_after.txt"

    if action == "before":
        ps = f"""
reg export HKCU "{before_hkcu}" /y | Out-Null
reg export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "{before_hklm}" /y | Out-Null
Get-ScheduledTask | Select-Object TaskName, State | Out-File "{tasks_before}" -Encoding UTF8
Get-Service | Select-Object Name, Status | Out-File "{services_before}" -Encoding UTF8
Write-Output "Registry and autostart baseline snapshot created."
"""
        stdout, _, _ = await run_powershell_async(ps, timeout=90)
        return stdout

    elif action == "after":
        ps = f"""
reg export HKCU "{after_hkcu}" /y | Out-Null
reg export HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "{after_hklm}" /y | Out-Null
Get-ScheduledTask | Select-Object TaskName, State | Out-File "{tasks_after}" -Encoding UTF8
Get-Service | Select-Object Name, Status | Out-File "{services_after}" -Encoding UTF8
Write-Output "Post-execution snapshot created."
"""
        stdout, _, _ = await run_powershell_async(ps, timeout=90)
        return stdout

    elif action == "compare":
        ps = f"""
Write-Output "=== Registry & System Diff ==="

# 1. Compare HKCU
if ((Test-Path "{before_hkcu}") -and (Test-Path "{after_hkcu}")) {{
    $before = Get-Content "{before_hkcu}" -Encoding Unicode -ErrorAction SilentlyContinue
    $after = Get-Content "{after_hkcu}" -Encoding Unicode -ErrorAction SilentlyContinue
    $diff = Compare-Object $before $after -ErrorAction SilentlyContinue | Select-Object -First 100
    if ($diff) {{
        Write-Output "--- HKCU Changes ($($diff.Count)) ---"
        $diff | ForEach-Object {{
            $ind = if ($_.SideIndicator -eq '=>') {{ '[+ADDED]' }} else {{ '[-REMOVED]' }}
            if ($_.InputObject -match '^\\[|^"') {{
                Write-Output "  $ind $($_.InputObject)"
            }}
        }}
    }} else {{
        Write-Output "No HKCU changes detected."
    }}
}}

# 2. Compare HKLM Run
if ((Test-Path "{before_hklm}") -and (Test-Path "{after_hklm}")) {{
    $bm = Get-Content "{before_hklm}" -Encoding Unicode -ErrorAction SilentlyContinue
    $am = Get-Content "{after_hklm}" -Encoding Unicode -ErrorAction SilentlyContinue
    $diff_m = Compare-Object $bm $am -ErrorAction SilentlyContinue | Select-Object -First 50
    if ($diff_m) {{
        Write-Output "`n--- HKLM Run Key Changes ($($diff_m.Count)) ---"
        $diff_m | ForEach-Object {{
            $ind = if ($_.SideIndicator -eq '=>') {{ '[+ADDED]' }} else {{ '[-REMOVED]' }}
            if ($_.InputObject -match '^\\[|^"') {{
                Write-Output "  $ind $($_.InputObject)"
            }}
        }}
    }} else {{
        Write-Output "`nNo HKLM Run changes detected."
    }}
}}

# 3. Compare Scheduled Tasks
if ((Test-Path "{tasks_before}") -and (Test-Path "{tasks_after}")) {{
    $tb = Get-Content "{tasks_before}"
    $ta = Get-Content "{tasks_after}"
    $tdiff = Compare-Object $tb $ta -ErrorAction SilentlyContinue
    if ($tdiff) {{
        Write-Output "`n--- Scheduled Task Changes ---"
        $tdiff | ForEach-Object {{ Write-Output "  $($_.SideIndicator) $($_.InputObject)" }}
    }}
}}

# 4. Compare Services
if ((Test-Path "{services_before}") -and (Test-Path "{services_after}")) {{
    $sb = Get-Content "{services_before}"
    $sa = Get-Content "{services_after}"
    $sdiff = Compare-Object $sb $sa -ErrorAction SilentlyContinue
    if ($sdiff) {{
        Write-Output "`n--- Service Status Changes ---"
        $sdiff | ForEach-Object {{ Write-Output "  $($_.SideIndicator) $($_.InputObject)" }}
    }}
}}
"""
        stdout, _, _ = await run_powershell_async(ps, timeout=90)
        return stdout

    else:
        return "Invalid action. Choose 'before', 'after', or 'compare'."


async def detect_dropped_files(
    since_seconds: int = 120,
    target_dirs: list[str] = None
) -> str:
    """Scan common drop directories (%TEMP%, %APPDATA%, %LOCALAPPDATA%, Public, ProgramData) for newly created or modified files."""
    import hashlib
    import time
    from pathlib import Path

    cutoff = time.time() - since_seconds
    default_dirs = [
        os.environ.get("TEMP"),
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        r"C:\Users\Public",
        r"C:\ProgramData"
    ]
    scan_dirs = target_dirs or [d for d in default_dirs if d and os.path.isdir(d)]

    SUSPICIOUS_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".scr", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".bat", ".cmd", ".ps1", ".hta", ".lnk", ".iso",
        ".vhd", ".zip", ".rar", ".7z", ".bin", ".dat"
    }

    discovered = []
    suspicious = []

    SKIP_DIR_NAMES = {
        "microsoft", "packages", "windowsapps", "chocolatey", "pip",
        "cache", "crashes", "inetcache", "history", "cookies"
    }

    for d in scan_dirs:
        base_depth = d.rstrip("\\/").count(os.sep)
        for root, dirs, files in os.walk(d):
            # Enforce max depth of 3 subdirectories
            current_depth = root.count(os.sep) - base_depth
            if current_depth >= 3:
                dirs.clear()
                continue

            # Prune noisy system cache directories
            dirs[:] = [subdir for subdir in dirs if subdir.lower() not in SKIP_DIR_NAMES]

            for f in files:
                full_path = os.path.join(root, f)
                try:
                    stat = os.stat(full_path)
                    mtime = max(stat.st_mtime, stat.st_ctime)
                    if mtime >= cutoff:
                        ext = Path(full_path).suffix.lower()
                        size = stat.st_size

                        # Calculate SHA256 if file is small enough (< 50MB)
                        sha256_hash = ""
                        if size < 50 * 1024 * 1024:
                            h = hashlib.sha256()
                            with open(full_path, "rb") as fh:
                                while chunk := fh.read(65536):
                                    h.update(chunk)
                            sha256_hash = h.hexdigest()

                        entry = {
                            "path": full_path,
                            "size": size,
                            "ext": ext,
                            "sha256": sha256_hash,
                            "mtime": mtime
                        }

                        if ext in SUSPICIOUS_EXTENSIONS:
                            suspicious.append(entry)
                        else:
                            discovered.append(entry)
                except (OSError, PermissionError):
                    continue

    lines = [
        "=== Dropped & Modified Files Detection ===",
        f"Time Window: Past {since_seconds} seconds",
        f"Scanned Directories: {len(scan_dirs)}",
        f"Total New/Modified Files: {len(suspicious) + len(discovered)}",
        f"Suspicious Extensions:    {len(suspicious)}",
        ""
    ]

    if suspicious:
        lines.append("--- Suspicious Dropped Executables / Scripts ---")
        for item in suspicious[:40]:
            lines.append(f"[!] Path:   {item['path']}")
            lines.append(f"    Size:   {item['size']} bytes ({round(item['size']/1024, 2)} KB)")
            lines.append(f"    SHA256: {item['sha256']}")
            lines.append("")

    if discovered:
        lines.append("--- Other Modified / Created Files ---")
        for item in discovered[:30]:
            lines.append(f"  [-] {item['path']} ({item['size']} bytes)")
        if len(discovered) > 30:
            lines.append(f"  ... and {len(discovered) - 30} more files")

    if not suspicious and not discovered:
        lines.append("No newly created or dropped files found in monitored directories.")

    return "\n".join(lines)

