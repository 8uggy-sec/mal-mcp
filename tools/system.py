"""System and host inspection tools for Flare-VM."""

import hashlib
import os
import platform
import socket
import psutil
from ..config import get_all_tool_status
from ..helpers import run_powershell_async, run_command_async, safe_truncate
from ..security import feature_enabled, require_sample_file


async def check_flarevm_status() -> str:
    """Check Flare-VM system information, OS details, resource usage, and installed RE tool status."""
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} ({platform.version()})"
    arch = platform.machine()
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("C:\\")

    tool_status = get_all_tool_status()
    avail_tools = [k for k, v in tool_status.items() if v["available"]]
    missing_tools = [k for k, v in tool_status.items() if not v["available"]]

    lines = [
        "=== Flare-VM Host Status ===",
        f"Hostname:       {hostname}",
        f"OS:             {os_info}",
        f"Architecture:   {arch}",
        f"Memory:         {mem.used // (1024*1024)}MB / {mem.total // (1024*1024)}MB ({mem.percent}% used)",
        f"C: Drive:       {disk.free // (1024*1024*1024)}GB free / {disk.total // (1024*1024*1024)}GB total",
        "",
        f"Installed RE Tools ({len(avail_tools)}):",
    ]
    for t in sorted(avail_tools):
        lines.append(f"  [+] {t:15s} -> {tool_status[t]['path']}")

    if missing_tools:
        lines.append(f"\nMissing Tools ({len(missing_tools)}):")
        for t in sorted(missing_tools):
            lines.append(f"  [-] {t}")

    return "\n".join(lines)


async def execute_powershell(command: str, timeout: int = 120) -> str:
    """Execute an arbitrary PowerShell command directly on Flare-VM."""
    if not feature_enabled("MAL_MCP_ENABLE_SHELL"):
        return (
            "[-] Arbitrary PowerShell execution is disabled by default for security.\n"
            "Set environment variable MAL_MCP_ENABLE_SHELL=1 on the Flare-VM host to enable this tool."
        )
    timeout = max(1, min(300, int(timeout)))
    stdout, stderr, code = await run_powershell_async(command, timeout=timeout)
    res = stdout or ""
    if stderr:
        res += f"\n--- STDERR ---\n{stderr}"
    res += f"\n--- Exit Code: {code} ---"
    return safe_truncate(res)


async def execute_cmd(command: str, timeout: int = 120) -> str:
    """Execute an arbitrary Windows CMD command directly on Flare-VM."""
    if not feature_enabled("MAL_MCP_ENABLE_SHELL"):
        return (
            "[-] Arbitrary CMD execution is disabled by default for security.\n"
            "Set environment variable MAL_MCP_ENABLE_SHELL=1 on the Flare-VM host to enable this tool."
        )
    timeout = max(1, min(300, int(timeout)))
    cmd = ["cmd.exe", "/c", command]
    stdout, stderr, code = await run_command_async(cmd, timeout=timeout)
    res = stdout or ""
    if stderr:
        res += f"\n--- STDERR ---\n{stderr}"
    res += f"\n--- Exit Code: {code} ---"
    return safe_truncate(res)


async def get_file_hash(file_path: str) -> str:
    """Calculate MD5, SHA1, and SHA256 hashes of a file on Flare-VM."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = os.path.getsize(file_path)

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return (
        f"=== File Hashes ===\n"
        f"File:   {file_path}\n"
        f"Size:   {size} bytes ({round(size / 1024, 2)} KB)\n"
        f"MD5:    {md5.hexdigest()}\n"
        f"SHA1:   {sha1.hexdigest()}\n"
        f"SHA256: {sha256.hexdigest()}"
    )


async def read_file_hex(file_path: str, offset: int = 0, length: int = 256) -> str:
    """Read a specific byte slice of a file and display formatted hex and ASCII dump."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        offset = int(offset)
        length = int(length)
    except (ValueError, TypeError):
        return "Offset and length must be integers."

    if offset < 0:
        return f"Invalid offset: {offset} (offset must be non-negative)."
    if length <= 0:
        return f"Invalid length: {length} (length must be positive)."

    total_size = os.path.getsize(file_path)
    if offset >= total_size:
        return f"Offset 0x{offset:X} ({offset}) exceeds file size ({total_size} bytes)."

    length = max(1, min(65536, length))
    with open(file_path, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    lines = [
        f"=== Hex Dump: {file_path} ===",
        f"Total Size: {total_size} bytes | Offset: 0x{offset:X} ({offset}) | Length: {len(data)} bytes\n",
        "Offset(h)  -- -- -- -- -- -- -- --  -- -- -- -- -- -- -- --  Decoded Text",
        "---------  -----------------------  -----------------------  ----------------"
    ]

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part1 = " ".join(f"{b:02X}" for b in chunk[:8])
        hex_part2 = " ".join(f"{b:02X}" for b in chunk[8:])
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset + i:08X}   {hex_part1:<23}  {hex_part2:<23}  {ascii_part}")

    return "\n".join(lines)


async def list_processes(filter_name: str = "") -> str:
    """List running processes on Flare-VM with optional name or PID filter."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "exe"]):
        try:
            info = p.info
            name = info.get("name") or ""
            pid = info.get("pid")
            mem = (info.get("memory_info").rss // (1024 * 1024)) if info.get("memory_info") else 0
            exe = info.get("exe") or ""

            if filter_name:
                if filter_name.lower() not in name.lower() and filter_name != str(pid):
                    continue

            procs.append((pid, name, mem, exe))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x[2], reverse=True)
    lines = [
        f"=== Running Processes ({len(procs)} matched) ===",
        f"{'PID':<8} {'Mem (MB)':<10} {'Process Name':<30} {'Executable Path'}",
        "-" * 80
    ]
    for pid, name, mem, exe in procs[:100]:
        lines.append(f"{pid:<8} {mem:<10} {name:<30} {exe}")

    return "\n".join(lines)
