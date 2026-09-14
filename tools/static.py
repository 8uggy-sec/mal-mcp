"""Static analysis tools for Flare-VM."""

import math
import os
import pefile
from pathlib import Path
from typing import Optional
from ..config import resolve_tool
from ..helpers import run_command_async, safe_truncate
from ..security import require_sample_file, validate_output_path, wrap_untrusted_data


async def die_analyze(file_path: str) -> str:
    """Run DetectItEasy (DIE) CLI on a file for compiler, packer, and protector detection."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    diec_path = resolve_tool("diec")
    cmd = [diec_path, "-d", resolved_path]
    stdout, stderr, code = await run_command_async(cmd, timeout=120)
    res = f"=== DetectItEasy Analysis ===\nFile: {resolved_path}\n\n{stdout}"
    if code != 0 and not stdout.strip():
        res += f"\n[!] Error: DIE exited with non-zero status (Exit Code: {code})"
    if stderr:
        res += f"\n--- Warnings ---\n{stderr}"
    return wrap_untrusted_data(safe_truncate(res), label="DETECTITEASY ANALYSIS")


async def floss_extract_strings(file_path: str, min_length: int = 4, emulate_decoded: bool = False) -> str:
    """Run Mandiant FLOSS to extract static, stack, and tight strings (set emulate_decoded=True for deep emulation)."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    floss_path = resolve_tool("floss")
    cmd = [floss_path, "-q", "-n", str(min_length)]
    if not emulate_decoded:
        cmd.extend(["--no", "decoded", "--"])
    cmd.append(resolved_path)

    timeout = 300 if emulate_decoded else 60
    stdout, stderr, code = await run_command_async(cmd, timeout=timeout)
    res = f"=== FLOSS String Extraction ===\nFile: {resolved_path}\nMin Length: {min_length}\n\n{stdout}"
    if code != 0 and not stdout.strip():
        res += f"\n[!] Error: FLOSS exited with non-zero status (Exit Code: {code})"
    if stderr:
        res += f"\n--- Warnings ---\n{stderr}"
    return wrap_untrusted_data(safe_truncate(res), label="FLOSS EXTRACTION")


async def capa_analyze(file_path: str, verbose: bool = False) -> str:
    """Run Mandiant CAPA for capability detection and MITRE ATT&CK mapping."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    capa_path = resolve_tool("capa")
    cmd = [capa_path]
    if verbose:
        cmd.append("-v")
    cmd.append(resolved_path)

    stdout, stderr, code = await run_command_async(cmd, timeout=300)
    res = f"=== CAPA Capability Analysis ===\nFile: {resolved_path}\n\n{stdout}"
    if code != 0 and not stdout.strip():
        res += f"\n[!] Error: CAPA exited with non-zero status (Exit Code: {code})"
    if stderr:
        res += f"\n--- Warnings ---\n{stderr}"
    return wrap_untrusted_data(safe_truncate(res), label="CAPA ANALYSIS")


async def yara_scan(file_path: str, rules_path: Optional[str] = None, rule_string: Optional[str] = None) -> str:
    """Scan a target file with YARA rules by specifying a rules file or inline rule string."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    import yara

    try:
        if rule_string:
            rules = yara.compile(source=rule_string)
            label = "inline rule"
        elif rules_path and os.path.exists(rules_path):
            if os.path.isdir(rules_path):
                rule_files = {}
                for root, _, files in os.walk(rules_path):
                    for f in files:
                        if f.endswith((".yar", ".yara")):
                            rule_files[f] = os.path.join(root, f)
                if not rule_files:
                    return f"No .yar or .yara files found in {rules_path}"
                rules = yara.compile(filepaths=rule_files)
                label = f"directory {rules_path}"
            else:
                rules = yara.compile(filepath=rules_path)
                label = f"file {rules_path}"
        else:
            # Check default Flare-VM yara rules directory
            candidates = [
                r"C:\Tools\yara\rules",
                r"C:\ProgramData\chocolatey\lib\yara\rules",
            ]
            found = False
            for c in candidates:
                if os.path.isdir(c):
                    rules = yara.compile(filepaths={f: os.path.join(c, f) for f in os.listdir(c) if f.endswith((".yar", ".yara"))})
                    label = f"default rules {c}"
                    found = True
                    break
            if not found:
                return "No YARA rules specified, and default rules directory not found. Please provide 'rules_path' or 'rule_string'."

        matches = rules.match(resolved_path)
        lines = [
            f"=== YARA Scan Results ===",
            f"Target: {resolved_path}",
            f"Rules Source: {label}",
            f"Total Matches: {len(matches)}\n"
        ]
        for m in matches:
            lines.append(f"[MATCH] Rule: {m.rule}")
            if m.tags:
                lines.append(f"        Tags: {', '.join(m.tags)}")
            if m.meta:
                lines.append(f"        Meta: {m.meta}")
            if m.strings:
                lines.append(f"        Matched Strings: {len(m.strings)}")
                for s in m.strings[:5]:
                    if hasattr(s, "identifier"):
                        ident = s.identifier
                        offset = s.instances[0].offset if s.instances else 0
                        data_val = s.instances[0].matched_data if s.instances else b""
                    elif isinstance(s, (list, tuple)) and len(s) == 3:
                        offset, ident, data_val = s
                    else:
                        ident = str(s)
                        offset = 0
                        data_val = b""
                    data_preview = data_val[:40] if isinstance(data_val, (bytes, bytearray)) else str(data_val)[:40]
                    lines.append(f"          - 0x{offset:X}: {ident} = {data_preview!r}")
            lines.append("")

        return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="YARA SCAN")
    except Exception as e:
        return f"YARA scan error: {e}"


async def strings_extract(file_path: str, min_length: int = 6, encoding: str = "both") -> str:
    """Extract printable strings (ASCII/Unicode) using Sysinternals strings."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    strings_path = resolve_tool("strings")
    cmd = [strings_path, "-accepteula", "-n", str(min_length)]
    if encoding == "ascii":
        cmd.append("-a")
    elif encoding == "unicode":
        cmd.append("-u")
    cmd.append(resolved_path)

    stdout, stderr, code = await run_command_async(cmd, timeout=60)
    lines = stdout.splitlines()
    res = (
        f"=== Strings Extraction ===\n"
        f"File: {resolved_path} | Min Length: {min_length} | Encoding: {encoding}\n"
        f"Total Strings Extracted: {len(lines)}\n\n"
        f"{stdout}"
    )
    return wrap_untrusted_data(safe_truncate(res), label="STRINGS EXTRACTION")


SUSPICIOUS_APIS = {
    "Process Injection & Memory Manipulation": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread",
        "QueueUserAPC", "SetThreadContext", "GetThreadContext",
        "NtMapViewOfSection", "ZwMapViewOfSection", "MapViewOfFile",
        "SuspendThread", "ResumeThread"
    ],
    "Process & Shell Execution": [
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
        "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "CreateProcessWithLogonW", "CreateProcessWithTokenW"
    ],
    "Anti-Analysis & Evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "FindWindowA", "FindWindowW",
        "GetTickCount", "QueryPerformanceCounter", "timeGetTime",
        "NtSetInformationThread", "BlockInput"
    ],
    "Keylogging & Spyware / Hooks": [
        "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx",
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
        "RegisterHotKey", "AttachThreadInput"
    ],
    "Token & Privilege Escalation": [
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "LookupPrivilegeValueW", "DuplicateToken", "DuplicateTokenEx",
        "ImpersonateLoggedOnUser"
    ],
    "Persistence & Services / Registry": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "StartServiceA", "StartServiceW", "ChangeServiceConfigA"
    ],
    "Network & C2 Communication": [
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpOpenRequestW",
        "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "connect", "send", "recv", "socket", "WSASocketA", "WSASocketW"
    ],
    "Cryptography & Ransomware Primitives": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContextA",
        "CryptAcquireContextW", "CryptExportKey", "CryptImportKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey"
    ],
    "Dynamic API Resolvers (Stubs / Droppers)": [
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"
    ],
    "Resource Extraction / Droppers": [
        "FindResourceA", "FindResourceW", "FindResourceExA", "FindResourceExW",
        "LoadResource", "LockResource", "SizeofResource"
    ]
}


async def entropy_analysis(file_path: str) -> str:
    """Calculate per-section Shannon entropy, detect RWX (Writable+Executable) anomalies, and identify packed stubs."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    pe = None
    try:
        pe = pefile.PE(resolved_path)
    except Exception as e:
        return f"Failed to parse PE file: {e}"

    try:
        lines = [
            "=== PE Section Entropy & Anomaly Analysis ===",
            f"File: {resolved_path}\n",
            f"{'Section':<10} {'VirtSize':>12} {'RawSize':>12} {'Perms':>7} {'Entropy':>8} {'Status':>10}",
            "-" * 65
        ]

        total_entropy = 0
        section_count = len(pe.sections) if hasattr(pe, "sections") else 0
        anomalies = []

        IMAGE_SCN_MEM_EXECUTE = 0x20000000
        IMAGE_SCN_MEM_READ    = 0x40000000
        IMAGE_SCN_MEM_WRITE   = 0x80000000

        SUSPICIOUS_SECTION_NAMES = {
            "upx0", "upx1", "upx2", ".vmp0", ".vmp1", ".themida", ".aspack",
            ".nsp0", ".nsp1", ".tsu0", ".ndata", "mew", ".adata", ".enigma"
        }

        if hasattr(pe, "sections"):
            for s in pe.sections:
                raw_name = s.Name.decode(errors="replace").strip("\x00")
                name = raw_name if raw_name else "(unnamed)"
                data = s.get_data()
                ent = 0.0
                if data:
                    length = len(data)
                    counts = [0] * 256
                    for b in data:
                        counts[b] += 1
                    for count in counts:
                        if count > 0:
                            p = count / length
                            ent -= p * math.log2(p)

                is_exec = bool(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                is_read = bool(s.Characteristics & IMAGE_SCN_MEM_READ)
                is_write = bool(s.Characteristics & IMAGE_SCN_MEM_WRITE)
                perms = ("R" if is_read else "-") + ("W" if is_write else "-") + ("X" if is_exec else "-")

                status = "PACKED" if ent > 7.0 else ("HIGH" if ent > 6.5 else "OK")
                lines.append(f"{name:<10} {s.Misc_VirtualSize:>12} {s.SizeOfRawData:>12} {perms:>7} {ent:>8.2f} {status:>10}")
                total_entropy += ent

                # Check for RWX anomaly
                if is_exec and is_write:
                    anomalies.append(f"[!] Critical: Section '{name}' is RWX (Writable + Executable). Indicates self-modifying code, packer stub, or shellcode buffer.")

                # Check for size discrepancy (VirtualSize >> RawSize)
                if s.Misc_VirtualSize > (s.SizeOfRawData * 5) and s.Misc_VirtualSize > 65536 and s.SizeOfRawData > 0:
                    anomalies.append(f"[!] Suspicious: Section '{name}' VirtualSize ({s.Misc_VirtualSize}) is much larger than RawSize ({s.SizeOfRawData}) - space reserved for unpacked payload.")
                elif s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0 and is_exec:
                    anomalies.append(f"[!] Suspicious: Section '{name}' has RawSize=0 with Executable permission - typical uncompressed payload landing zone.")

                # Check for known packer section names
                if raw_name.lower() in SUSPICIOUS_SECTION_NAMES:
                    anomalies.append(f"[!] Packer indicator: Section '{name}' matches known packer/protector signature.")

        avg_entropy = (total_entropy / section_count) if section_count > 0 else 0
        lines.append("-" * 65)
        lines.append(f"Average Section Entropy: {avg_entropy:.2f}")

        if avg_entropy > 7.0:
            lines.append("VERDICT: High probability of PACKED / ENCRYPTED content (Entropy > 7.0)")
        elif avg_entropy > 6.0:
            lines.append("VERDICT: Possibly packed, compressed resources, or encrypted configuration")
        else:
            lines.append("VERDICT: Normal uncompressed code entropy (< 6.0)")

        import_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                import_count += len(entry.imports)
        lines.append(f"Total Import Count:      {import_count} " + ("(suspiciously low - packer indicator)" if import_count < 10 else "(normal)"))

        if anomalies:
            lines.append("\n--- Section Anomalies & Risk Indicators ---")
            for a in anomalies:
                lines.append(f"  {a}")
        else:
            lines.append("\nNo RWX or anomalous section characteristics detected.")

        return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="ENTROPY ANALYSIS")
    finally:
        if pe:
            try:
                pe.close()
            except Exception:
                pass


async def pe_info(file_path: str) -> str:
    """Inspect PE headers, Imphash, compile timestamp, security mitigations, exports, and categorized suspicious APIs."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    pe = None
    try:
        pe = pefile.PE(resolved_path)
    except Exception as e:
        return f"Failed to parse PE file: {e}"

    try:
        # Calculate Imphash
        imphash = ""
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = "N/A"

        # Security Mitigations (Checksec)
        has_opt = hasattr(pe, "OPTIONAL_HEADER") and pe.OPTIONAL_HEADER is not None
        chars = pe.OPTIONAL_HEADER.DllCharacteristics if has_opt and hasattr(pe.OPTIONAL_HEADER, "DllCharacteristics") else 0
        has_aslr = bool(chars & 0x0040)
        has_high_entropy = bool(chars & 0x0020)
        has_dep = bool(chars & 0x0100)
        has_cfg = bool(chars & 0x4000)
        has_no_seh = bool(chars & 0x0400)
        has_integrity = bool(chars & 0x0080)

        machine = pe.FILE_HEADER.Machine if hasattr(pe, "FILE_HEADER") and hasattr(pe.FILE_HEADER, "Machine") else 0
        subsystem = pe.OPTIONAL_HEADER.Subsystem if has_opt and hasattr(pe.OPTIONAL_HEADER, "Subsystem") else 0
        image_base = pe.OPTIONAL_HEADER.ImageBase if has_opt and hasattr(pe.OPTIONAL_HEADER, "ImageBase") else 0
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint if has_opt and hasattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint") else 0
        timestamp = pe.FILE_HEADER.TimeDateStamp if hasattr(pe, "FILE_HEADER") and hasattr(pe.FILE_HEADER, "TimeDateStamp") else 0
        num_sections = len(pe.sections) if hasattr(pe, "sections") else 0

        lines = [
            "=== PE Structure & Capability Profile ===",
            f"File:               {resolved_path}",
            f"Machine:            0x{machine:04X} ({'64-bit AMD64' if machine == 0x8664 else ('32-bit i386' if machine == 0x014C else 'Other')})",
            f"Subsystem:          0x{subsystem:04X} ({'GUI' if subsystem == 2 else ('Console' if subsystem == 3 else 'Other')})",
            f"ImageBase:          0x{image_base:08X}",
            f"AddressOfEntryPoint:0x{entry_point:08X}",
            f"TimeDateStamp:      0x{timestamp:08X}",
            f"Number of Sections: {num_sections}",
            f"Imphash:            {imphash}",
            "",
            "--- Security Mitigations (Checksec) ---",
            f"  ASLR (Dynamic Base):     {'ENABLED' if has_aslr else 'DISABLED [!] Vulnerable / Legacy / Stub'}",
            f"  High Entropy VA (64-bit):{'ENABLED' if has_high_entropy else 'DISABLED'}",
            f"  DEP / NX Compatibility:  {'ENABLED' if has_dep else 'DISABLED [!] Vulnerable'}",
            f"  Control Flow Guard (CFG):{'ENABLED' if has_cfg else 'DISABLED'}",
            f"  SEH Protection:          {'NO SEH (Modern/Clean)' if has_no_seh else 'SEH Present'}",
            f"  Code Integrity:          {'ENFORCED' if has_integrity else 'DEFAULT'}",
            ""
        ]

        # Categorize Suspicious Imported APIs
        all_imported_apis = set()
        dll_imports = {}

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors="replace").lower() if entry.dll else "(unknown)"
                funcs = []
                for imp in entry.imports:
                    fn = imp.name.decode(errors="replace") if imp.name else f"Ordinal({imp.ordinal})"
                    funcs.append(fn)
                    if imp.name:
                        all_imported_apis.add(imp.name.decode(errors="replace"))
                dll_imports[dll_name] = funcs

        # Group suspicious APIs by technique
        categorized_hits = {}
        for cat_name, api_list in SUSPICIOUS_APIS.items():
            matched = [api for api in api_list if api in all_imported_apis]
            if matched:
                categorized_hits[cat_name] = matched

        if categorized_hits:
            lines.append(f"--- Suspicious API Capabilities ({len(categorized_hits)} Categories Detected) ---")
            for cat, apis in categorized_hits.items():
                lines.append(f"  [!] {cat}:")
                lines.append(f"      {', '.join(apis)}")
            lines.append("")
        else:
            lines.append("--- Suspicious API Capabilities ---")
            lines.append("  No high-risk Windows API patterns identified in import table.\n")

        # Exports
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
            lines.append(f"--- Exported Functions ({len(exports)}) ---")
            for exp in exports[:25]:
                exp_name = exp.name.decode(errors="replace") if exp.name else f"Ordinal({exp.ordinal})"
                lines.append(f"  - Ordinal {exp.ordinal:<4} 0x{exp.address:08X}: {exp_name}")
            if len(exports) > 25:
                lines.append(f"  ... and {len(exports) - 25} more exports")
            lines.append("")

        # DLL Import summary
        lines.append(f"--- Imported DLLs ({len(dll_imports)}) ---")
        if dll_imports:
            for dll_name, funcs in sorted(dll_imports.items()):
                lines.append(f"  {dll_name:<25} ({len(funcs)} functions)")
                for f in funcs[:5]:
                    lines.append(f"    - {f}")
                if len(funcs) > 5:
                    lines.append(f"    - ... and {len(funcs) - 5} more")
        else:
            lines.append("  No imports found (statically linked or packed).")

        return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="PE INFO")
    finally:
        if pe:
            try:
                pe.close()
            except Exception:
                pass


async def sigcheck_analyze(file_path: str) -> str:
    """Verify Authenticode digital signature, certificate status, publisher, and binary metadata using Sysinternals sigcheck."""
    try:
        resolved_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    sigcheck_path = resolve_tool("sigcheck")
    cmd = [sigcheck_path, "-accepteula", "-nobanner", "-a", resolved_path]
    stdout, stderr, code = await run_command_async(cmd, timeout=60)

    lines = [
        "=== Authenticode Signature & Binary Metadata ===",
        f"File: {resolved_path}\n"
    ]
    if stdout:
        for line in stdout.splitlines():
            line_str = line.strip()
            if line_str:
                lines.append(f"  {line_str}")
    else:
        lines.append("  No signature or metadata extracted.")
    if stderr:
        lines.append(f"\nWarnings/Errors:\n{stderr}")
    return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="SIGCHECK ANALYSIS")


async def dnspy_decompile(assembly_path: str, output_dir: str = r"C:\temp\mal_mcp\decompiled") -> str:
    """Decompile a .NET assembly into C# source code files using dnSpy.Console."""
    try:
        resolved_asm = str(require_sample_file(assembly_path))
        resolved_out = str(validate_output_path(output_dir))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    target_dir = os.path.join(resolved_out, Path(resolved_asm).stem)
    os.makedirs(target_dir, exist_ok=True)
    dnspy_path = resolve_tool("dnspy_console")
    cmd = [dnspy_path, "-o", target_dir, resolved_asm]
    stdout, stderr, code = await run_command_async(cmd, timeout=180)

    files = []
    for root, _, fnames in os.walk(target_dir):
        for f in fnames:
            rel = os.path.relpath(os.path.join(root, f), target_dir)
            files.append(rel)

    lines = [
        "=== dnSpy Decompilation ===",
        f"Assembly: {resolved_asm}",
        f"Output Directory: {target_dir}",
        f"Decompiled Files ({len(files)} total):"
    ]
    for f in files[:50]:
        lines.append(f"  {f}")
    if len(files) > 50:
        lines.append(f"  ... and {len(files) - 50} more files")

    if stdout:
        lines.append(f"\nConsole Output:\n{stdout}")
    if stderr:
        lines.append(f"\nWarnings/Errors:\n{stderr}")

    return wrap_untrusted_data(safe_truncate("\n".join(lines)), label="DNSPY DECOMPILE")
