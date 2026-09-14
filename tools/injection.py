"""Memory injection scanning, process dumping, and automated unpacking tools for Flare-VM."""

import hashlib
import math
import os
import psutil
from pathlib import Path
import pefile

from ..config import resolve_tool, TEMP_DIR
from ..helpers import run_command_async, safe_truncate
from ..security import require_sample_file, validate_output_path, wrap_untrusted_data, get_output_root
from .static import die_analyze, entropy_analysis


def _triage_dump_directory(output_dir: str) -> list[str]:
    """Inspect dumped memory artifacts (PE vs shellcode, hashes, size)."""
    triage_lines = []
    if not os.path.isdir(output_dir):
        return triage_lines

    dumps = []
    for root, _, files in os.walk(output_dir):
        for f in files:
            dumps.append(os.path.join(root, f))

    if not dumps:
        return triage_lines

    triage_lines.append(f"\n--- Carved In-Memory Artifacts ({len(dumps)} files) ---")
    for dpath in dumps[:25]:
        rel = os.path.relpath(dpath, output_dir)
        size = os.path.getsize(dpath)
        sha256 = ""
        file_type = "Raw Dump / Shellcode"
        try:
            with open(dpath, "rb") as fh:
                magic = fh.read(2)
                if magic == b"MZ":
                    file_type = "Carved PE Executable / DLL"
                fh.seek(0)
                h = hashlib.sha256()
                while chunk := fh.read(65536):
                    h.update(chunk)
                sha256 = h.hexdigest()
        except Exception:
            pass

        triage_lines.append(f"  [+] {rel} ({size} bytes, {file_type})")
        if sha256:
            triage_lines.append(f"      SHA256: {sha256}")

    if len(dumps) > 25:
        triage_lines.append(f"  ... and {len(dumps) - 25} more dumped files.")

    return triage_lines


async def pe_sieve_scan(pid: int, output_dir: str = r"C:\temp\mal_mcp\pe_sieve") -> str:
    """Scan a target process (PID) for code injection, hooks, shellcode, and replaced headers with pe-sieve."""
    try:
        resolved_out = str(validate_output_path(output_dir))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    if not psutil.pid_exists(pid):
        return f"Process with PID {pid} not found."

    os.makedirs(resolved_out, exist_ok=True)
    pe_sieve_path = resolve_tool("pe_sieve")
    cmd = [pe_sieve_path, "/pid", str(pid), "/dir", resolved_out, "/shellc", "3", "/iat", "3", "/data", "3"]

    stdout, stderr, code = await run_command_async(cmd, timeout=120)

    lines = [
        f"=== PE-sieve Injection Scan (PID: {pid}) ===",
        stdout,
    ]
    triage = _triage_dump_directory(resolved_out)
    lines.extend(triage)

    return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="PE-SIEVE INJECTION SCAN")


async def hollows_hunter_scan(
    output_dir: str = r"C:\temp\mal_mcp\hollows",
    process_name: str = "",
    pid: int = 0,
    recent_seconds: int = 0,
) -> str:
    """Scan running processes across the system for code injection, process hollowing, and hooks."""
    try:
        resolved_out = str(validate_output_path(output_dir))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    os.makedirs(resolved_out, exist_ok=True)
    hh_path = resolve_tool("hollows_hunter")
    cmd = [hh_path, "/dir", resolved_out, "/cache", "2"]

    has_filter = False
    if process_name and str(process_name).strip():
        cmd.extend(["/pname", str(process_name).strip()])
        has_filter = True
    if pid and pid > 0:
        cmd.extend(["/pid", str(pid)])
        has_filter = True
    if recent_seconds and recent_seconds > 0:
        cmd.extend(["/ptimes", str(recent_seconds)])
        has_filter = True

    if has_filter:
        # Targeted process scan: deep shellcode patterns/stats & full IAT hook detection (< 2s)
        cmd.extend(["/shellc", "3", "/iat", "3"])
    else:
        # Full-system scan: pattern shellcode scan (~31s) to complete reliably under MCP 60s timeout
        cmd.extend(["/shellc", "1"])

    stdout, stderr, code = await run_command_async(cmd, timeout=180)

    title = "=== Hollows Hunter Injection Scan ==="
    if process_name:
        title = f"=== Hollows Hunter Injection Scan (Process: {process_name}) ==="
    elif pid > 0:
        title = f"=== Hollows Hunter Injection Scan (PID: {pid}) ==="
    elif recent_seconds > 0:
        title = f"=== Hollows Hunter Injection Scan (Recent: {recent_seconds}s) ==="

    lines = [
        title,
        stdout,
    ]
    triage = _triage_dump_directory(resolved_out)
    lines.extend(triage)

    return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="HOLLOWS HUNTER SCAN")


async def procdump_process(pid: int, output_dir: str = r"C:\temp\mal_mcp\dumps", full_memory: bool = True) -> str:
    """Take a complete memory minidump (.dmp) of a target process using Sysinternals procdump64 for heap/stack analysis."""
    try:
        resolved_out = str(validate_output_path(output_dir))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    if not psutil.pid_exists(pid):
        return f"Process with PID {pid} not found."

    try:
        proc_name = psutil.Process(pid).name()
    except Exception:
        proc_name = f"pid_{pid}"

    os.makedirs(resolved_out, exist_ok=True)
    procdump_path = resolve_tool("procdump")

    dump_type = "-ma" if full_memory else "-mm"
    dump_filename = f"{proc_name}_{pid}.dmp"
    dump_file_path = os.path.join(resolved_out, dump_filename)

    cmd = [procdump_path, "-accepteula", dump_type, str(pid), dump_file_path]
    stdout, stderr, code = await run_command_async(cmd, timeout=60)

    created_dumps = [os.path.join(resolved_out, f) for f in os.listdir(resolved_out) if f.startswith(proc_name) and f.endswith(".dmp")]
    if created_dumps:
        latest = max(created_dumps, key=os.path.getmtime)
        size = os.path.getsize(latest)
        return (
            f"=== Process Memory Dump Created ===\n"
            f"Process:  {proc_name} (PID: {pid})\n"
            f"Dump File:{latest}\n"
            f"Size:     {size} bytes ({round(size / (1024*1024), 2)} MB)\n"
            f"Type:     {'Full Memory (Image + Heap + Stack)' if full_memory else 'Mini Dump'}\n\n"
            f"Next: Strings can be extracted with 'strings_extract' or opened in x64dbg/WinDbg for in-memory key/C2 config discovery."
        )

    return f"ProcDump completed but output dump not located:\n{stdout}\n{stderr}"


async def de4dot_deobfuscate(file_path: str, output_file: str = "") -> str:
    """Deobfuscate and unpack .NET assemblies (ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator, etc.) using de4dot."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        if output_file:
            out_resolved = str(validate_output_path(output_file))
        else:
            default_out = get_output_root() / f"{Path(resolved_path).stem}.cleaned{Path(resolved_path).suffix}"
            out_resolved = str(validate_output_path(default_out))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    de4dot_path = resolve_tool("de4dot")
    os.makedirs(os.path.dirname(os.path.abspath(out_resolved)), exist_ok=True)

    cmd = [de4dot_path, resolved_path, "-o", out_resolved]
    stdout, stderr, code = await run_command_async(cmd, timeout=120)

    lines = [
        "=== de4dot .NET Deobfuscation & Unpacking ===",
        f"Input File:  {resolved_path}",
    ]

    if os.path.isfile(out_resolved):
        size = os.path.getsize(out_resolved)
        lines.append(f"Output File: {out_resolved} ({size} bytes)")
        lines.append(f"Status:      Deobfuscation Successful\n")
        lines.append(f"Deobfuscator Log:\n{stdout}")
        lines.append(f"\nNext: Decompiled source code can now be exported cleanly using 'dnspy_decompile'.")
    else:
        lines.append(f"Status:      No changes made or deobfuscation failed (code {code})\n")
        lines.append(f"Log:\n{stdout}\n{stderr}")

    return "\n".join(lines)


async def extract_pe_overlay(file_path: str, output_path: str = "") -> str:
    """Detect and carve appended PE overlay data (encrypted payloads, hidden archives, or appended configs)."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        if output_path:
            out_resolved = str(validate_output_path(output_path))
        else:
            default_out = get_output_root() / f"{Path(resolved_path).stem}.overlay.bin"
            out_resolved = str(validate_output_path(default_out))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    pe = None
    try:
        pe = pefile.PE(resolved_path)
    except Exception as e:
        return f"Failed to parse PE: {e}"

    try:
        offset = pe.get_overlay_data_start_offset()
        overlay_data = pe.get_overlay()

        if not offset or not overlay_data:
            return f"=== PE Overlay Analysis ===\nFile: {resolved_path}\nResult: Clean PE. No overlay data detected (file ends at physical section boundary)."

        size = len(overlay_data)

        # Calculate Shannon entropy of the overlay
        counts = [0] * 256
        for b in overlay_data:
            counts[b] += 1
        ent = 0.0
        for count in counts:
            if count > 0:
                p = count / size
                ent -= p * math.log2(p)

        # Calculate SHA256 of overlay
        sha256 = hashlib.sha256(overlay_data).hexdigest()

        os.makedirs(os.path.dirname(os.path.abspath(out_resolved)), exist_ok=True)
        with open(out_resolved, "wb") as fh:
            fh.write(overlay_data)

        verdict = (
            "HIGH PROBABILITY OF ENCRYPTED / COMPRESSED PAYLOAD (Entropy > 7.0)"
            if ent > 7.0
            else ("POSSIBLY COMPRESSED OR OBFUSCATED (Entropy > 6.0)" if ent > 6.0 else "UNCOMPRESSED DATA / EMBEDDED CONFIG")
        )

        lines = [
            "=== PE Overlay Carving & Analysis ===",
            f"Input Binary:    {resolved_path}",
            f"Overlay Offset:  0x{offset:X} ({offset} bytes)",
            f"Overlay Size:    {size} bytes ({round(size/1024, 2)} KB)",
            f"Overlay Entropy: {ent:.2f} / 8.00",
            f"Overlay SHA256:  {sha256}",
            f"Verdict:         {verdict}",
            f"Carved Payload:  {out_resolved}",
            "",
            "Next: Analyze the carved payload with 'die_analyze', 'strings_extract', or 'get_file_hash'."
        ]

        return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="PE OVERLAY CARVE")
    finally:
        if pe:
            try:
                pe.close()
            except Exception:
                pass


async def upx_unpack(packed_file: str, output_file: str) -> str:
    """Decompress a UPX-packed executable into a new file."""
    try:
        resolved_path = str(require_sample_file(packed_file))
        resolved_out = str(validate_output_path(output_file))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    os.makedirs(os.path.dirname(os.path.abspath(resolved_out)), exist_ok=True)
    upx_path = resolve_tool("upx")
    cmd = [upx_path, "-d", resolved_path, "-o", resolved_out]

    stdout, stderr, code = await run_command_async(cmd, timeout=60)
    if os.path.isfile(resolved_out):
        return (
            f"=== UPX Unpack Successful ===\n"
            f"Source: {resolved_path}\n"
            f"Output: {resolved_out} ({os.path.getsize(resolved_out)} bytes)\n\n"
            f"{stdout}"
        )
    return f"UPX unpack failed (code {code}):\n{stderr}\n{stdout}"


async def unpack_detect_and_try_structured(file_path: str, output_file: str = "") -> dict:
    """Multi-engine unpacker returning structured metadata: {success: bool, engine: str, unpacked_file: str, report: str}."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return {
            "success": False,
            "engine": "none",
            "unpacked_file": "",
            "report": f"[-] Security Refusal: {e}"
        }

    try:
        if output_file:
            output_file = str(validate_output_path(output_file))
    except Exception as e:
        return {
            "success": False,
            "engine": "none",
            "unpacked_file": "",
            "report": f"[-] Security Refusal: {e}"
        }

    die_report = await die_analyze(resolved_path)
    entropy_report = await entropy_analysis(resolved_path)
    overlay_report = await extract_pe_overlay(resolved_path)

    lines = [
        "=== Multi-Engine Automated Unpacking Workflow ===",
        f"Target: {resolved_path}\n",
        "--- 1. Packer Detection (DIE) ---",
        die_report,
        "\n--- 2. Entropy & RWX Section Check ---",
        entropy_report,
        "\n--- 3. Overlay Detection ---",
        overlay_report,
    ]

    engine = "none"
    unpacked_path = ""
    success = False

    # Check 1: UPX
    if "upx" in die_report.lower() or "upx" in entropy_report.lower():
        lines.append("\n--- 4. Automated Unpack Attempt (UPX Engine) ---")
        out = output_file or str(validate_output_path(get_output_root() / f"{Path(resolved_path).stem}.unupx{Path(resolved_path).suffix}"))
        unpack_res = await upx_unpack(resolved_path, out)
        lines.append(unpack_res)
        if os.path.isfile(out) and os.path.getsize(out) > 0:
            success = True
            engine = "upx"
            unpacked_path = out

    # Check 2: .NET Obfuscators (ConfuserEx, Reactor, SmartAssembly, etc.)
    dot_net_indicators = ["confuser", "reactor", "smartassembly", "dotfuscator", "babel", "eazfuscator", ".net", "clr"]
    if not success and any(ind in die_report.lower() for ind in dot_net_indicators):
        lines.append("\n--- 4. Automated Deobfuscation Attempt (.NET de4dot Engine) ---")
        out_net = output_file or str(validate_output_path(get_output_root() / f"{Path(resolved_path).stem}.cleaned{Path(resolved_path).suffix}"))
        de4dot_res = await de4dot_deobfuscate(resolved_path, out_net)
        lines.append(de4dot_res)
        if os.path.isfile(out_net) and os.path.getsize(out_net) > 0:
            success = True
            engine = "de4dot"
            unpacked_path = out_net

    # Check 3: Appended Overlay Carving
    overlay_carved = str(get_output_root() / f"{Path(resolved_path).stem}.overlay.bin")
    if not success and os.path.isfile(overlay_carved) and os.path.getsize(overlay_carved) > 0:
        success = True
        engine = "overlay_carve"
        unpacked_path = overlay_carved
        lines.append("\n--- 4. Overlay Carved Payload Available ---")
        lines.append(f"Carved overlay payload detected: {overlay_carved} ({os.path.getsize(overlay_carved)} bytes)")

    if not success:
        lines.append("\n--- 4. Unpack Status ---")
        lines.append("No automated unpack engine produced an unpacked executable. Use 'x64dbg_load' or manual unpacking.")

    return {
        "success": success,
        "engine": engine,
        "unpacked_file": unpacked_path,
        "report": wrap_untrusted_data(safe_truncate("\n".join(lines)), label="UNPACKING REPORT")
    }


async def unpack_detect_and_try(file_path: str, output_file: str = "") -> str:
    """Multi-engine unpacker: detects UPX, .NET obfuscators (de4dot), and carved overlays in one automated workflow."""
    result = await unpack_detect_and_try_structured(file_path, output_file)
    return result["report"]


async def injection_scan_all(
    output_dir: str = r"C:\temp\mal_mcp\injections",
    process_name: str = "",
    pid: int = 0,
    recent_seconds: int = 0,
) -> str:
    """Perform a comprehensive system-wide memory injection scan combining Hollows Hunter and deep PE-sieve targeted scans."""
    try:
        resolved_out = str(validate_output_path(output_dir))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    os.makedirs(resolved_out, exist_ok=True)
    hh_res = await hollows_hunter_scan(
        output_dir=resolved_out,
        process_name=process_name,
        pid=pid,
        recent_seconds=recent_seconds,
    )

    import re
    flagged_pids = set(re.findall(r"(?:PID|Process):\s*(\d+)", hh_res))

    title = "=== Comprehensive System-Wide Injection Scan ==="
    if process_name:
        title = f"=== Comprehensive Injection Scan (Process: {process_name}) ==="
    elif pid > 0:
        title = f"=== Comprehensive Injection Scan (PID: {pid}) ==="
    elif recent_seconds > 0:
        title = f"=== Comprehensive Injection Scan (Recent: {recent_seconds}s) ==="

    lines = [
        title,
        hh_res,
    ]

    if flagged_pids:
        lines.append(f"\n--- In-Depth Targeted PE-sieve Scans on {len(flagged_pids)} Flagged PID(s) ---")
        for pid_str in sorted(flagged_pids)[:5]:
            try:
                pid = int(pid_str)
                pid_out = os.path.join(resolved_out, f"pid_{pid}")
                ps_res = await pe_sieve_scan(pid=pid, output_dir=pid_out)
                lines.append(f"\n[+] Deep Scan for PID {pid}:\n{ps_res}")
            except Exception:
                pass

    return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="INJECTION SCAN ALL")
