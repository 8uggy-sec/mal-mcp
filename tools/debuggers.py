"""Debugger launchers, safe emulators, and RE integration for x64dbg, IDA Pro, dnSpy, Cutter, and scdbg."""

import asyncio
import ctypes
import os
import shutil
import socket
from typing import Optional, List
import psutil

from ..config import resolve_tool, find_ida_executable, IDA_MCP_PORT, DNSPY_MCP_PORT
from ..helpers import launch_gui_app, run_command_async
from ..security import (
    require_sample_file,
    validate_output_path,
    validate_api_identifier,
    wrap_untrusted_data,
)


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def _get_process_bitness(pid: int) -> str:
    """Determine whether a running Windows process is 32-bit (WOW64) or 64-bit native."""
    try:
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return "unknown"
        is_wow = ctypes.c_bool()
        ctypes.windll.kernel32.IsWow64Process(handle, ctypes.byref(is_wow))
        ctypes.windll.kernel32.CloseHandle(handle)
        return "x86" if is_wow.value else "x64"
    except Exception:
        return "unknown"


async def ida_status() -> str:
    """Check if IDA Pro MCP server is currently alive on port 13337 and report installed IDA paths."""
    alive = is_port_open("127.0.0.1", IDA_MCP_PORT)
    ida_exe = find_ida_executable(prefer_text_mode=False)
    ida_text = find_ida_executable(prefer_text_mode=True)
    
    status_str = "[ONLINE]" if alive else "[OFFLINE]"
    details = [
        f"=== IDA Pro MCP Status ===",
        f"Server Status:   {status_str} on http://127.0.0.1:{IDA_MCP_PORT}/mcp",
        f"GUI Executable:  {ida_exe or 'Not detected'}",
        f"Batch/Text Mode: {ida_text or 'Not detected'}",
    ]
    if not alive:
        details.append(
            f"Note: To enable IDA MCP integration, open IDA Pro with the ida-pro-mcp plugin loaded, "
            f"or call ida_launch_and_wait(binary_path)."
        )
    return "\n".join(details)


async def dnspy_status() -> str:
    """Check if dnSpy GUI MCP server is currently alive on port 50301 and report dnSpy binary paths."""
    alive = is_port_open("127.0.0.1", DNSPY_MCP_PORT)
    try:
        gui_path = resolve_tool("dnspy_gui")
    except FileNotFoundError:
        gui_path = "Not found"

    try:
        cli_path = resolve_tool("dnspy_console")
    except FileNotFoundError:
        cli_path = "Not found"

    status_str = "[ONLINE]" if alive else "[OFFLINE]"
    details = [
        f"=== dnSpy MCP Status ===",
        f"Server Status:   {status_str} on http://127.0.0.1:{DNSPY_MCP_PORT}/mcp",
        f"dnSpy GUI:       {gui_path}",
        f"dnSpy CLI:       {cli_path}",
    ]
    if not alive:
        details.append(
            f"Note: To enable dnSpy MCP integration, open dnSpy with the MCP HTTP plugin enabled on port {DNSPY_MCP_PORT}."
        )
    return "\n".join(details)


async def ida_launch_and_wait(binary_path: str, wait_timeout: int = 45) -> str:
    """Launch IDA Pro with target binary and wait until the IDA MCP JSON-RPC server (port 13337) is ready."""
    try:
        binary_path = str(require_sample_file(binary_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    ida_path = find_ida_executable(prefer_text_mode=False)
    if not ida_path:
        return "IDA Pro executable (ida.exe / ida64.exe) was not found in standard directories or PATH."

    await launch_gui_app(ida_path, [binary_path])

    # Poll for port readiness
    for elapsed in range(0, wait_timeout, 2):
        await asyncio.sleep(2)
        if is_port_open("127.0.0.1", IDA_MCP_PORT):
            return (
                f"=== IDA Pro Launched ===\n"
                f"Executable:  {ida_path}\n"
                f"Target:      {binary_path}\n"
                f"MCP Status:  [ONLINE] Ready on port {IDA_MCP_PORT} after {elapsed + 2}s."
            )

    return (
        f"IDA Pro was launched ({ida_path}) with target '{binary_path}', "
        f"but the MCP server on port {IDA_MCP_PORT} did not respond within {wait_timeout}s.\n"
        f"Verify that the ida-pro-mcp plugin is installed in IDA's plugins directory."
    )


async def x64dbg_load(file_path: str, arch: str = "auto") -> str:
    """Load an executable into x64dbg or x32dbg debugger."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    dbg_tool = "x64dbg"
    if arch.lower() in ("x86", "32", "win32"):
        dbg_tool = "x32dbg"
    elif arch.lower() == "auto":
        try:
            import pefile
            pe = pefile.PE(file_path, fast_load=True)
            if pe.FILE_HEADER.Machine == 0x014c:  # IMAGE_FILE_MACHINE_I386
                dbg_tool = "x32dbg"
        except Exception:
            pass

    try:
        dbg_path = resolve_tool(dbg_tool)
    except FileNotFoundError:
        return f"[-] Tool Unavailable: {dbg_tool}.exe was not found on Flare-VM."
    res = await launch_gui_app(dbg_path, [file_path])
    return (
        f"=== Debugger Launched ===\n"
        f"Debugger: {dbg_tool} ({dbg_path})\n"
        f"Target:   {file_path}\n"
        f"Arch:     {arch}\n"
        f"Status:   {res}"
    )


async def x64dbg_attach(target: str) -> str:
    """Attach x64dbg or x32dbg to an already running or suspended process (by PID or process name)."""
    target_pid = None
    target_name = None

    # Check if target is a PID
    if str(target).strip().isdigit():
        pid = int(target)
        try:
            p = psutil.Process(pid)
            target_pid = pid
            target_name = p.name()
        except psutil.NoSuchProcess:
            return f"Error: No running process found with PID {pid}."
    else:
        # Search by process name
        search_name = str(target).strip().lower()
        matches = []
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if p.info['name'] and p.info['name'].lower() == search_name:
                    matches.append((p.info['pid'], p.info['name']))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not matches:
            return f"Error: No active process matching '{target}' found."
        
        target_pid, target_name = matches[0]

    bitness = _get_process_bitness(target_pid)
    dbg_tool = "x32dbg" if bitness == "x86" else "x64dbg"
    try:
        dbg_path = resolve_tool(dbg_tool)
    except FileNotFoundError:
        return f"[-] Tool Unavailable: {dbg_tool}.exe was not found on Flare-VM."

    res = await launch_gui_app(dbg_path, ["-p", str(target_pid)])
    return (
        f"=== x64dbg Attach Initiated ===\n"
        f"Process:    {target_name}\n"
        f"PID:        {target_pid}\n"
        f"Arch:       {bitness}\n"
        f"Debugger:   {dbg_tool} ({dbg_path})\n"
        f"Command:    {dbg_tool}.exe -p {target_pid}\n"
        f"Status:     {res}"
    )


async def x64dbg_generate_script(
    template: str = "anti_anti_debug",
    custom_apis: Optional[List[str]] = None,
    output_path: str = r"C:\temp\mal_mcp\x64dbg_script.txt"
) -> str:
    """Generate an automated x64dbg script (templates: 'anti_anti_debug', 'api_tracer', 'unpack_oep', 'custom')."""
    try:
        output_path = str(validate_output_path(output_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    template_key = template.lower().strip()

    if template_key in ("anti_anti_debug", "anti_debug", "antidebug"):
        script = (
            "// ========================================================\n"
            "// Flare-VM x64dbg Automated Anti-Anti-Debugging Script\n"
            "// Intercepts common evasion checks and forces benign returns\n"
            "// ========================================================\n\n"
            "// 1. IsDebuggerPresent -> return 0 (debugger absent)\n"
            "bp IsDebuggerPresent\n"
            'SetBreakpointCommand IsDebuggerPresent, "set eax, 0; rtr; run"\n\n'
            "// 2. CheckRemoteDebuggerPresent -> write FALSE to out pointer, return 0\n"
            "bp CheckRemoteDebuggerPresent\n"
            'SetBreakpointCommand CheckRemoteDebuggerPresent, "set eax, 0; rtr; run"\n\n'
            "// 3. NtQueryInformationProcess -> spoof debug port/object\n"
            "bp NtQueryInformationProcess\n"
            'SetBreakpointCommand NtQueryInformationProcess, "set eax, 0; rtr; run"\n\n'
            "// 4. NtSetInformationThread -> block ThreadHideFromDebugger (0x11)\n"
            "bp NtSetInformationThread\n"
            'SetBreakpointCommand NtSetInformationThread, "set eax, 0; rtr; run"\n\n'
            "// 5. OutputDebugStringA/W -> prevent SetLastError timing trick\n"
            "bp OutputDebugStringA\n"
            'SetBreakpointCommand OutputDebugStringA, "set eax, 1; rtr; run"\n'
            "bp OutputDebugStringW\n"
            'SetBreakpointCommand OutputDebugStringW, "set eax, 1; rtr; run"\n\n'
            'log "[mal-mcp] Anti-anti-debugging breakpoints initialized."\n'
            "run\n"
        )
    elif template_key in ("api_tracer", "trace", "tracer"):
        script = (
            "// ========================================================\n"
            "// Flare-VM x64dbg API Tracer Script\n"
            "// Logs API parameters to the x64dbg Log tab without pausing\n"
            "// ========================================================\n\n"
            "// Memory Allocation & Permissions\n"
            'bplog VirtualAlloc, "[TRACER] VirtualAlloc(Addr={arg.get(0)}, Size={arg.get(1)}, Type={arg.get(2)}, Protect={arg.get(3)})"\n'
            'bpcnd VirtualAlloc, "0"\n\n'
            'bplog VirtualProtect, "[TRACER] VirtualProtect(Addr={arg.get(0)}, Size={arg.get(1)}, NewProtect={arg.get(2)})"\n'
            'bpcnd VirtualProtect, "0"\n\n'
            "// Process Injection & Remote Execution\n"
            'bplog WriteProcessMemory, "[TRACER] WriteProcessMemory(hProcess={arg.get(0)}, BaseAddr={arg.get(1)}, Size={arg.get(3)})"\n'
            'bpcnd WriteProcessMemory, "0"\n\n'
            'bplog CreateRemoteThread, "[TRACER] CreateRemoteThread(hProcess={arg.get(0)}, StartAddr={arg.get(3)})"\n'
            'bpcnd CreateRemoteThread, "0"\n\n'
            'bplog QueueUserAPC, "[TRACER] QueueUserAPC(pfnAPC={arg.get(0)}, hThread={arg.get(1)})"\n'
            'bpcnd QueueUserAPC, "0"\n\n'
            "// Network Sockets\n"
            'bplog connect, "[TRACER] connect(s={arg.get(0)}, name={arg.get(1)})"\n'
            'bpcnd connect, "0"\n\n'
            'bplog InternetOpenUrlA, "[TRACER] InternetOpenUrlA({utf8@arg.get(1)})"\n'
            'bpcnd InternetOpenUrlA, "0"\n\n'
            "// Persistence & Registry\n"
            'bplog RegSetValueExW, "[TRACER] RegSetValueExW(ValueName={utf16@arg.get(1)})"\n'
            'bpcnd RegSetValueExW, "0"\n\n'
            'log "[mal-mcp] API Tracer active. Monitor output in x64dbg Log tab."\n'
            "run\n"
        )
    elif template_key in ("unpack_oep", "oep", "unpacker"):
        script = (
            "// ========================================================\n"
            "// Flare-VM x64dbg Generic OEP (Original Entry Point) Trap\n"
            "// Breaks when code protection changes on unpacked payloads\n"
            "// ========================================================\n\n"
            "// Break on VirtualProtect changing memory to executable\n"
            "bp VirtualProtect\n"
            'SetBreakpointCommand VirtualProtect, "log \\"[OEP] VirtualProtect called for target {arg.get(0)} size {arg.get(1)} protect {arg.get(2)}\\"; rtr"\n\n'
            "// Break on VirtualAlloc\n"
            "bp VirtualAlloc\n"
            'SetBreakpointCommand VirtualAlloc, "log \\"[OEP] VirtualAlloc requested size {arg.get(1)}\\"; rtr"\n\n'
            'log "[mal-mcp] OEP transition breakpoints configured."\n'
            "run\n"
        )
    elif template_key == "custom":
        apis = custom_apis or ["VirtualAlloc", "CreateProcessW", "WriteProcessMemory"]
        if len(apis) > 100:
            return "[-] Security Refusal: Custom API count exceeds maximum limit (100)."
        for api in apis:
            if not isinstance(api, str) or len(api) > 128 or not validate_api_identifier(api):
                return f"[-] Security Refusal: Invalid API identifier '{api}'. Custom APIs must match ^[A-Za-z_][A-Za-z0-9_@$?.]{{0,127}}$"

        lines = [
            "// ========================================================",
            "// Flare-VM x64dbg Custom Logging Script",
            "// ========================================================\n",
        ]
        for api in apis:
            lines.append(f'bplog {api}, "[CUSTOM-TRACE] Hit: {api}"')
            lines.append(f'bpcnd {api}, "0"\n')
        lines.append('log "[mal-mcp] Custom logging script initialized."')
        lines.append("run\n")
        script = "\n".join(lines)
    else:
        return f"Unknown template '{template}'. Supported: 'anti_anti_debug', 'api_tracer', 'unpack_oep', 'custom'."

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(script)

    return (
        f"=== x64dbg Script Generated ===\n"
        f"Template:   {template_key}\n"
        f"Path:       {output_path}\n"
        f"Command:    In x64dbg command line, execute: scriptload \"{output_path}\"\n\n"
        f"--- Script Preview ---\n{script.strip()}"
    )


async def x64dbg_run_script(script_content: str, script_path: str = r"C:\temp\mal_mcp\x64dbg_script.txt") -> str:
    """Save an arbitrary x64dbg script and return the command to load it."""
    try:
        script_path = str(validate_output_path(script_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    if len(script_content.encode("utf-8", errors="replace")) > 65536:
        return "[-] Security Refusal: Script content exceeds maximum allowed limit (65,536 bytes)."

    os.makedirs(os.path.dirname(script_path), exist_ok=True)
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(script_content)

    return (
        f"=== x64dbg Script Saved ===\n"
        f"Path: {script_path}\n"
        f"In x64dbg command bar, run: scriptload \"{script_path}\""
    )


async def scdbg_emulate_shellcode(
    file_path: str,
    max_steps: int = 2000000,
    find_sc: bool = False,
    dump_unpacked: bool = False,
    offset: str = "0"
) -> str:
    """Emulate 32-bit shellcode safely via Libemu (scdbg.exe) without native CPU execution.
    
    Hooks Win32 APIs (sockets, file I/O, process execution, URL download) in isolated userspace emulation.
    """
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        scdbg_path = resolve_tool("scdbg")
    except FileNotFoundError:
        return "scdbg.exe not found on Flare-VM (expected at C:\\tools\\scdbg\\scdbg.exe)."

    args = [scdbg_path, "-f", file_path, "-s", str(max_steps), "-r", "-nc"]
    if find_sc:
        args.append("-findsc")
    if dump_unpacked:
        args.append("-d")
    if offset and offset != "0":
        args.extend(["-foff", offset])

    stdout, stderr, code = await run_command_async(args, timeout=60)
    
    output = stdout or stderr or "No output from scdbg."
    return (
        f"=== Libemu Shellcode Emulation (scdbg) ===\n"
        f"Target File: {file_path}\n"
        f"Exit Code:   {code}\n"
        f"Max Steps:   {max_steps}\n"
        f"Find Offset: {find_sc}\n"
        f"Dump Stages: {dump_unpacked}\n\n"
        f"--- Emulation Log & Report ---\n"
        f"{wrap_untrusted_data(output.strip(), max_chars=4000, label='SCDBG EMULATION LOG')}"
    )


async def blobrunner_prepare(file_path: str, arch: str = "auto", offset: str = "0") -> str:
    """Prepare raw shellcode for live debugging via Flare-VM's blobrunner (x86) and blobrunner64 (x64)."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    runner_tool = "blobrunner64" if arch.lower() in ("x64", "64") else "blobrunner"
    try:
        runner_path = resolve_tool(runner_tool)
    except FileNotFoundError:
        runner_path = rf"C:\tools\{runner_tool}\{runner_tool}.exe"

    dbg_tool = "x64dbg" if runner_tool == "blobrunner64" else "x32dbg"
    try:
        dbg_path = resolve_tool(dbg_tool)
    except FileNotFoundError:
        dbg_path = f"{dbg_tool}.exe"

    offset_arg = f"--offset {offset}" if offset and offset != "0" else ""
    launch_cmd = f'"{runner_path}" "{file_path}" {offset_arg}'.strip()

    instructions = (
        f"=== Blobrunner Shellcode Debugging Setup ===\n"
        f"Payload:         {file_path}\n"
        f"Architecture:    {runner_tool} ({'64-bit' if runner_tool == 'blobrunner64' else '32-bit'})\n"
        f"Runner Path:     {runner_path}\n"
        f"Debugger:        {dbg_tool} ({dbg_path})\n\n"
        f"--- Step-by-Step Shellcode Debugging Workflow ---\n"
        f"1. Open a Command Prompt or PowerShell and execute:\n"
        f"   {launch_cmd}\n\n"
        f"2. Blobrunner will allocate executable memory, print the Base Address and Entry point, and PAUSE:\n"
        f"   Example: '[x] Base Address: 0x00400000  Entry: 0x00400020  Press any key to execute'\n\n"
        f"3. Open {dbg_tool} and attach to the running 'blobrunner.exe' process:\n"
        f"   (Use MCP tool: x64dbg_attach(target=\"blobrunner.exe\"))\n\n"
        f"4. In {dbg_tool}, press [Ctrl+G] and enter the reported Entry address.\n"
        f"5. Press [F2] to place a software breakpoint at the Entry address.\n"
        f"6. Switch back to the blobrunner console and press [Enter] to resume.\n"
        f"7. {dbg_tool} will immediately trigger the breakpoint at the shellcode entry point!"
    )
    return instructions


async def cutter_load(file_path: str) -> str:
    """Launch Cutter GUI (Rizin/Radare2 graphical frontend) with the target binary."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    try:
        cutter_path = resolve_tool("cutter")
    except FileNotFoundError:
        return "Cutter executable was not found on Flare-VM."

    res = await launch_gui_app(cutter_path, [file_path])
    return (
        f"=== Cutter GUI Launched ===\n"
        f"Binary: {file_path}\n"
        f"Cutter: {cutter_path}\n"
        f"Status: {res}"
    )
