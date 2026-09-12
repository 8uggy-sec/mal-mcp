# mal-mcp - Flare-VM Native Malware Analysis MCP Server

A native [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server engineered specifically to run directly on Windows inside **Flare-VM** without requiring a Kali Linux host, WinRM network configuration, or SMB shares.

Exposes **52 specialized tools** across static analysis, dynamic behavioral monitoring, memory injection scanning, debuggers, and automated composite playbooks.

---

## Tool Categories

### 1. System & Host Diagnostics
- `check_flarevm_status`: Diagnostic check of Flare-VM host info, Windows version, and availability of all installed RE tools.
- `execute_powershell`: Run arbitrary PowerShell command locally with captured stdout/stderr and exit code.
- `execute_cmd`: Run CMD / Command Prompt commands locally.
- `get_file_hash`: MD5, SHA1, and SHA256 hashes of a local file (in-process via `hashlib`).
- `read_file_hex`: Read binary files or inspect specific offsets and bytes.
- `list_processes`: Enumerate running processes using `psutil` with process name/PID filtering.

### 2. Static Analysis
- `die_analyze`: Run DetectItEasy (`diec.exe`) for compiler, packer, and protector detection.
- `floss_extract_strings`: Run Mandiant FLOSS (`floss.exe`) for obfuscated, stack, and tight string recovery.
- `capa_analyze`: Run Mandiant CAPA (`capa.exe`) for capability detection and ATT&CK mapping.
- `yara_scan`: Scan a file or directory with YARA rules using `yara64.exe` or `yara-python`.
- `strings_extract`: Extract printable strings using Sysinternals `strings.exe` (ASCII and Unicode).
- `sigcheck_analyze`: Verify Authenticode digital signatures, certificate validity, publisher, and binary metadata with `sigcheck64.exe`.
- `entropy_analysis`: Calculate per-section Shannon entropy, detect RWX (Writable + Executable) memory anomalies, and identify packer stubs.
- `pe_info`: Deep PE header inspection, Imphash calculation, security mitigations (ASLR, DEP, CFG, High Entropy VA), export table parsing, and categorized suspicious API capability profiling (Injection, Anti-Debug, Persistence, Token Manipulation).
- `dnspy_decompile`: Headless decompilation of .NET assemblies into C# source trees using `dnSpy.Console.exe`.

### 3. Dynamic Analysis & Behavioral Monitoring
- `procmon_start`: Launch Process Monitor (`procmon64.exe`) with backing `.pml` file.
- `procmon_stop`: Stop ProcMon, export events to CSV, filter system noise, and compute event category breakdown (file, registry, network, process).
- `procmon_export_csv`: Export an existing PML file to CSV.
- `process_info`: In-depth inspection of a specific PID (modules, threads, handles, command line, parent PID, sockets).
- `detect_dropped_files`: Scan `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `Public`, and `ProgramData` for newly created or modified files, highlighting executables, scripts, and SHA256 hashes.
- `regshot_snapshot`: Registry and autostart snapshot (`before`, `after`, `compare`) showing registry keys, services, and tasks created or modified.

### 4. Network Monitoring & Simulation
- `network_connections_list`: Instant (0.1s) point-in-time snapshot of all active listening ports and established sockets with process names, PIDs, and remote IPs.
- `monitor_network`: Real-time monitoring of newly established TCP connections and DNS cache entries during malware execution.
- `fakenet_start`: Start FakeNet-NG (`fakenet.exe`) safely to divert network activity without dropping local MCP services.
- `fakenet_stop`: Stop FakeNet-NG and harvest captured HTTP/DNS requests, defanged IOCs, and raw HTTP POST payloads.
- `wireshark_capture`: Start and stop packet capture using `tshark.exe`.
- `pcap_analyze`: Offline deep packet inspection of `.pcap`/`.pcapng` captures using `tshark.exe` (DNS queries, HTTP requests/URIs, TLS SNI domains, defanged IOCs).

### 5. Memory Injection & Unpacking
- `pe_sieve_scan`: Scan a running process PID for hooks, shellcode, and replaced headers with `pe-sieve.exe`, triaging and hashing dumped artifacts.
- `hollows_hunter_scan`: System-wide scan for process hollowing and code injection with `hollows_hunter.exe`, triaging dumped artifacts.
- `injection_scan_all`: Full memory scan combining hollows hunter and PE-sieve.
- `procdump_process`: Dump complete process memory (`.dmp`) using Sysinternals `procdump64.exe` for in-memory string extraction, heap analysis, and C2 config recovery.
- `de4dot_deobfuscate`: Deobfuscate and unpack .NET assemblies (ConfuserEx, .NET Reactor, SmartAssembly, Dotfuscator, etc.) using `de4dot.exe`.
- `extract_pe_overlay`: Detect, analyze Shannon entropy, and carve hidden or appended payload overlays from PE files.
- `upx_unpack`: Attempt automated UPX decompression with `upx.exe -d`.
- `unpack_detect_and_try`: Multi-engine automated unpacker: detects UPX, .NET obfuscators (`de4dot`), and carved overlays in one unified workflow.

### 6. Debuggers & MCP Bridges
- `x64dbg_load`: Launch target executable in `x64dbg.exe` or `x32dbg.exe` with automatic PE bitness resolution.
- `x64dbg_attach`: Attach `x64dbg` or `x32dbg` directly to an active or suspended process with automated bitness inspection (WOW64 32-bit vs native 64-bit).
- `x64dbg_generate_script`: Generate production-grade x64dbg automation scripts (`anti_anti_debug`, `api_tracer`, `unpack_oep`, `custom`).
- `x64dbg_run_script`: Prepare and save an arbitrary x64dbg script file for execution.
- `scdbg_emulate_shellcode`: Emulate 32-bit shellcode safely in userspace via Libemu (`scdbg.exe`) without native CPU execution. Intercepts Win32 API calls and dumps unpacked stages.
- `blobrunner_prepare`: Prepare raw shellcode for live debugging via Flare-VM's `blobrunner.exe` (x86) and `blobrunner64.exe` (x64) with step-by-step debugger attachment workflow.
- `cutter_load`: Launch Cutter GUI (Rizin/Radare2 graphical frontend) with the target binary.
- `ida_status`: Probe whether the IDA Pro MCP JSON-RPC server is currently responding on port 13337 and report installed IDA paths.
- `dnspy_status`: Probe whether the dnSpy GUI MCP server is currently responding on port 50301 and report installed dnSpy paths.
- `ida_launch_and_wait`: Dynamically discover modern IDA Pro (9.1+, 9.0, 8.x) and launch with a binary, waiting for the IDA MCP server (`127.0.0.1:13337`) to become ready.

### 7. Composite Playbooks & Persistence Auditing
- `triage_full`: Complete automated static triage: Hashes + Authenticode + PE structure + DIE + Section Entropy & RWX + CAPA + FLOSS + YARA.
- `unpack_and_triage`: End-to-end automated pipeline: detects packing/obfuscation, unpacks payload (UPX, .NET de4dot, or carved overlay) with physical artifact tracking, and runs deep static triage with comparative diff.
- `generate_ioc_report`: Compile an automated, defanged Threat Intelligence & IOC Markdown report (hashes, Authenticode, suspicious APIs, defanged candidate C2 URLs/IPs/domains with `is_global` validation, MITRE ATT&CK TTPs).
- `autoruns_analyze`: Run Sysinternals Autoruns with non-Microsoft noise filtering (`-m`) and structured Markdown table output grouped by category.
- `persistence_audit`: Comprehensive forensic persistence audit across Registry Run/RunOnce, Startup Folders, Winlogon overrides, IFEO debugger hijacks, AppInit_DLLs, WMI subscriptions, Scheduled Tasks, and Services.
- `execute_with_monitoring`: Run binary under Procmon capture with isolated per-run artifact workspaces (`C:\temp\mal_mcp\runs\<id>`), fail-closed prechecks, process tree tracking, and guaranteed `try ... finally` tree cleanup.
- `behavioral_full`: Full dynamic execution pipeline: System baseline -> ProcMon capture -> FakeNet-NG simulation with readiness polling -> Process tree tracking -> Mid-flight Hollows Hunter memory injection scan -> Guaranteed `finally` process tree kill -> FakeNet log harvest & DNS restoration -> Filtered ProcMon summary -> Dropped files detection -> Registry diff -> Snapshot advisory.

---

## Installation & Quickstart

Clone the repository into your Flare-VM environment:

```bash
git clone https://github.com/8uggy-sec/mal-mcp.git
cd mal-mcp
pip install -e .
```

You can run the server directly or configure your MCP client to invoke `server.py`:

```bash
# Direct execution (stdio)
python server.py
# Or via entry point
mal-mcp
```

---

## Client Configuration

`mal-mcp` connects to any standard Model Context Protocol (MCP) client over `stdio`.

### Standard MCP Configuration Snippet

```json
{
  "mcpServers": {
    "mal-mcp": {
      "command": "python",
      "args": [
        "C:\\path\\to\\mal-mcp\\server.py"
      ]
    },
    "ida-pro-mcp": {
      "type": "http",
      "serverUrl": "http://127.0.0.1:13337/mcp"
    },
    "dnspy-gui-mcp": {
      "type": "http",
      "serverUrl": "http://127.0.0.1:50301/mcp"
    }
  }
}
```

### Supported AI Clients & Config Locations

- **Claude Desktop**:
  Edit `%APPDATA%\Claude\claude_desktop_config.json` and paste the snippet above into `"mcpServers"`.

- **Claude Code CLI**:
  Add it directly from your terminal:
  ```bash
  claude mcp add mal-mcp python "C:\path\to\mal-mcp\server.py"
  ```
  Or add to your project `.mcp.json` or `~/.claude.json`.

- **Cursor**:
  Go to **Settings > Features > MCP > Add New MCP Server**:
  - Name: `mal-mcp`
  - Type: `command`
  - Command: `python C:\path\to\mal-mcp\server.py`

- **OpenCode / Cline / Roo Code (VS Code)**:
  Open the MCP tab in the sidebar and click **Configure**, or edit `cline_mcp_settings.json` / `roo_mcp_settings.json` and add the `mal-mcp` block.

- **Any Other MCP Client (GPT, Windsurf, etc.)**:
  Use the standard `command: python` with argument pointing to `server.py`.

---

## Practical AI Prompts & Usage Examples

Once `mal-mcp` is connected to your AI assistant (Claude Desktop, Antigravity, Cursor, or OpenCode), you can interact in natural language without remembering complex command-line syntax. Here are production prompt examples:

### 1. Zero-Execution Static Triage
> *"Run full static triage on `C:\Samples\malware.exe`. Give me the hashes, compiler, section entropy, and MITRE ATT&CK capabilities."*
- **Invokes**: `triage_full`
- **Output**: Aggregates DIE, PE headers, checksec mitigations, CAPA capabilities, FLOSS deobfuscated strings, and YARA signatures into a unified markdown report.

### 2. Defanged Threat Intel & IOC Extraction
> *"Generate an automated, defanged Threat Intelligence Markdown report for `C:\Samples\dropper.exe`."*
- **Invokes**: `generate_ioc_report`
- **Output**: Generates a clean markdown report containing defanged candidate C2 URLs (`hxxp`), public IPv4 addresses (`1.1.1[.]1`), shell invocations (`cmd.exe /c ...`, `ping ...`), dropped filesystem paths, and PDB debug symbols.

### 3. Automated Unpacking & Payload Carving
> *"Is `C:\Samples\packed_sample.exe` packed or obfuscated? Detect the packer, unpack it, and triage the clean payload."*
- **Invokes**: `unpack_and_triage`
- **Output**: Detects and unpacks UPX stubs, deobfuscates .NET assemblies (ConfuserEx, .NET Reactor, SmartAssembly via `de4dot`), or carves appended PE overlays, running deep static triage on the extracted binary with before/after size diffs.

### 4. Dynamic Behavioral Detonation (FakeNet + ProcMon)
> *"Run full behavioral analysis on `C:\Samples\sample.exe` for 30 seconds with network simulation and process tracking."*
- **Invokes**: `behavioral_full`
- **Output**: Establishes registry baseline, starts ProcMon kernel tracing and FakeNet-NG network redirection, executes sample under Win32 Job Object containment, monitors process tree creation, runs mid-flight Hollows Hunter memory injection scan, guarantees safe process tree termination and exact DNS restoration, detects dropped files, and outputs a registry diff.

### 5. Memory Injection & Process Hollowing Scan
> *"Scan all running processes across the system with Hollows Hunter and PE-sieve to see if any process is hollowed or injected."*
- **Invokes**: `injection_scan_all`
- **Output**: Scans every active process, detects inline hooks / shellcode buffers, and carves detected memory artifacts directly to disk for analysis.

### 6. Forensic Persistence & Backdoor Audit
> *"Audit system persistence mechanisms to see if malware installed any autostart keys, services, or scheduled tasks."*
- **Invokes**: `persistence_audit`
- **Output**: Audits Registry Run/RunOnce keys, Startup folders, Winlogon overrides, IFEO debugger hijacks, AppInit_DLLs, WMI event subscriptions, Scheduled Tasks, and non-standard Windows services.

### 7. Interactive GUI Testing (Without an LLM)
If you want to test and execute any of the 52 tools through an interactive web browser dashboard:
```powershell
npx @modelcontextprotocol/inspector python -m mal_mcp.server
```

### 8. Automated End-to-End Verification Suite
To verify all 7 tool categories live on your Flare-VM machine against a safe target (`notepad.exe` and synthetic test artifacts):
```powershell
python scripts/verify_all_tools.py
```
*Runs 48 automated live checks across static analysis, ProcMon kernel tracking, FakeNet network simulation, memory injection scanning (PE-sieve & Hollows Hunter), debuggers, and composite playbooks with a clean pass/fail summary matrix.*

---

## Security & Research Disclaimer

> [!WARNING]
> **FOR AUTHORIZED RESEARCH & EDUCATIONAL PURPOSES ONLY**
>
> `mal-mcp` is designed strictly for authorized cybersecurity research, malware analysis, reverse engineering, and digital forensics within isolated sandbox environments (such as dedicated Windows Flare-VM virtual machines).
>
> - **Sandbox Isolation**: Never execute dynamic analysis tools (`behavioral_full`, `execute_with_monitoring`, etc.) on production systems or unisolated host machines. Always execute suspicious binaries inside disposable virtual machines with snapshots enabled.
> - **Tool Orchestration**: This repository contains Python orchestration code only and does not bundle or redistribute third-party or proprietary binaries. All referenced analysis tools (Sysinternals, Mandiant CAPA/FLOSS, x64dbg, IDA Pro) are the property of their respective copyright holders.
> - **Limitation of Liability**: The author (`8uggy-sec`) assumes no liability and is not responsible for any misuse, data loss, system compromise, or damages resulting from the use or misuse of this software.

