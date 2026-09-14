"""Configuration and dynamic tool resolution for Flare-VM Native MCP Server."""

import os
import shutil
from pathlib import Path

# Base directories
TEMP_DIR = Path(r"C:\temp\mal_mcp")
TEMP_DIR.mkdir(parents=True, exist_ok=True)

# Candidate locations for common Flare-VM tools
CANDIDATE_PATHS = {
    "diec": [
        r"C:\Tools\die\diec.exe",
        r"C:\ProgramData\chocolatey\bin\diec.exe",
    ],
    "floss": [
        r"C:\Tools\FLOSS\floss.exe",
        r"C:\ProgramData\chocolatey\bin\floss.exe",
    ],
    "capa": [
        r"C:\Tools\capa\capa.exe",
        r"C:\ProgramData\chocolatey\bin\capa.exe",
    ],
    "yara64": [
        r"C:\Tools\yara\yara64.exe",
        r"C:\Tools\yara\yara.exe",
        r"C:\ProgramData\chocolatey\bin\yara64.exe",
        r"C:\ProgramData\chocolatey\bin\yara.exe",
    ],
    "procmon": [
        r"C:\Tools\sysinternals\procmon64.exe",
        r"C:\Tools\sysinternals\procmon.exe",
        r"C:\ProgramData\chocolatey\bin\procmon.exe",
    ],
    "autorunsc": [
        r"C:\Tools\sysinternals\autorunsc64.exe",
        r"C:\Tools\sysinternals\autorunsc.exe",
        r"C:\ProgramData\chocolatey\bin\autorunsc.exe",
    ],
    "strings": [
        r"C:\Tools\sysinternals\strings64.exe",
        r"C:\Tools\sysinternals\strings.exe",
        r"C:\ProgramData\chocolatey\bin\strings.exe",
    ],
    "sigcheck": [
        r"C:\Tools\sysinternals\sigcheck64.exe",
        r"C:\Tools\sysinternals\sigcheck.exe",
        r"C:\ProgramData\chocolatey\bin\sigcheck.exe",
    ],
    "pe_sieve": [
        r"C:\Tools\pe-sieve\pe-sieve.exe",
        r"C:\ProgramData\chocolatey\bin\pe-sieve.exe",
    ],
    "hollows_hunter": [
        r"C:\Tools\hollows_hunter\hollows_hunter.exe",
        r"C:\ProgramData\chocolatey\bin\hollows_hunter.exe",
    ],
    "upx": [
        r"C:\Tools\upx\upx.exe",
        r"C:\ProgramData\chocolatey\bin\upx.exe",
    ],
    "procdump": [
        r"C:\Tools\sysinternals\procdump64.exe",
        r"C:\Tools\sysinternals\procdump.exe",
        r"C:\ProgramData\chocolatey\bin\procdump.exe",
    ],
    "de4dot": [
        r"C:\ProgramData\chocolatey\bin\de4dot.exe",
        r"C:\Tools\de4dot\de4dot.exe",
    ],
    "dnspy_console": [
        r"C:\ProgramData\chocolatey\bin\dnSpy.Console.exe",
        r"C:\Tools\dnSpy\dnSpy.Console.exe",
    ],
    "dnspy_gui": [
        r"C:\ProgramData\chocolatey\bin\dnSpy.exe",
        r"C:\Tools\dnSpy\dnSpy.exe",
    ],
    "fakenet": [
        r"C:\ProgramData\chocolatey\bin\fakenet.exe",
        r"C:\Tools\fakenet\fakenet3.5\fakenet.exe",
    ],
    "x64dbg": [
        r"C:\ProgramData\chocolatey\bin\x64dbg.exe",
        r"C:\Tools\x64dbg\release\x64\x64dbg.exe",
    ],
    "x32dbg": [
        r"C:\ProgramData\chocolatey\bin\x32dbg.exe",
        r"C:\Tools\x64dbg\release\x32\x32dbg.exe",
    ],
    "tshark": [
        r"C:\ProgramData\chocolatey\bin\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
    ],
    "pestudio": [
        r"C:\ProgramData\chocolatey\bin\pestudio.exe",
        r"C:\Tools\pestudio\pestudio.exe",
    ],
    "cutter": [
        r"C:\ProgramData\chocolatey\bin\cutter.exe",
        r"C:\Tools\Cutter\Cutter-v2.4.1-Windows-x86_64\cutter.exe",
    ],
    "ghidra": [
        r"C:\ProgramData\chocolatey\bin\ghidra.exe",
    ],
    "scdbg": [
        r"C:\tools\scdbg\scdbg.exe",
        r"C:\ProgramData\chocolatey\bin\scdbg.exe",
    ],
    "blobrunner": [
        r"C:\tools\blobrunner\blobrunner.exe",
    ],
    "blobrunner64": [
        r"C:\tools\blobrunner64\blobrunner64.exe",
    ],
}

# Ports for existing local reverse engineering MCP services
IDA_MCP_PORT = int(os.environ.get("IDA_MCP_PORT", 13337))
DNSPY_MCP_PORT = int(os.environ.get("DNSPY_MCP_PORT", 50301))

# Cache of resolved tool paths
_RESOLVED_CACHE = {}


def resolve_tool(name: str) -> str:
    """Resolve executable path for a tool by checking PATH and known Flare-VM locations."""
    if name in _RESOLVED_CACHE:
        return _RESOLVED_CACHE[name]

    # Check candidates
    if name in CANDIDATE_PATHS:
        for candidate in CANDIDATE_PATHS[name]:
            if os.path.isfile(candidate):
                _RESOLVED_CACHE[name] = candidate
                return candidate

    # Check PATH
    which_path = shutil.which(name)
    if which_path:
        _RESOLVED_CACHE[name] = which_path
        return which_path

    # Check if name is already an absolute existing file
    if os.path.isfile(name):
        _RESOLVED_CACHE[name] = name
        return name

    raise FileNotFoundError(f"Tool '{name}' was not found in PATH or standard Flare-VM directories.")


def find_ida_executable(prefer_text_mode: bool = False) -> str | None:
    """Dynamically discover IDA Pro executable (ida.exe, ida64.exe, or idat.exe) across standard install directories."""
    import glob

    cache_key = f"ida_{'text' if prefer_text_mode else 'gui'}"
    if cache_key in _RESOLVED_CACHE:
        return _RESOLVED_CACHE[cache_key]

    target_exes = ["idat.exe", "idat64.exe"] if prefer_text_mode else ["ida.exe", "ida64.exe"]
    search_roots = [
        r"C:\Program Files",
        r"C:\Program Files (x86)",
        r"C:\Tools",
        r"C:\tools",
    ]

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for exe_name in target_exes:
            # Pattern matches e.g. "IDA Professional 9.1\ida.exe", "IDA Pro 9.0\ida64.exe"
            matches = glob.glob(os.path.join(root, "IDA*", exe_name))
            if not matches:
                matches = glob.glob(os.path.join(root, "ida*", exe_name))
            for m in matches:
                if os.path.isfile(m):
                    _RESOLVED_CACHE[cache_key] = m
                    return m

    # Fallback to PATH
    for exe_name in target_exes:
        w = shutil.which(exe_name)
        if w and os.path.isfile(w):
            _RESOLVED_CACHE[cache_key] = w
            return w

    return None


def get_all_tool_status() -> dict:
    """Return dictionary of all registered tools and whether they are installed and available."""
    status = {}
    for tool_name in CANDIDATE_PATHS:
        try:
            path = resolve_tool(tool_name)
            status[tool_name] = {"available": True, "path": path}
        except FileNotFoundError:
            status[tool_name] = {"available": False, "path": None}
    
    ida_gui = find_ida_executable(prefer_text_mode=False)
    status["ida_pro"] = {"available": bool(ida_gui), "path": ida_gui}
    return status
