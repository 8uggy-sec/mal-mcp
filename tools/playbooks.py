"""Automated composite playbooks for malware analysis and triage on Flare-VM."""

import asyncio
import csv
import io
import os
import re
import shlex
import subprocess
import time
from typing import Optional, Union, List
import psutil

from ..config import resolve_tool, TEMP_DIR
from ..helpers import (
    run_command_async,
    run_powershell_async,
    safe_truncate,
    get_process_tree_info,
    kill_process_tree,
    create_job_object,
    assign_process_to_job,
    close_job_object,
    launch_process_in_job,
    get_run_temp_dir,
)
from ..security import (
    feature_enabled,
    require_sample_file,
    validate_dynamic_target,
    validate_output_path,
    wrap_untrusted_data,
    get_output_root,
)

_DYNAMIC_LOCK = asyncio.Lock()
from .system import get_file_hash
from .static import (
    die_analyze,
    entropy_analysis,
    capa_analyze,
    floss_extract_strings,
    yara_scan,
    pe_info,
    sigcheck_analyze,
    strings_extract
)
from .dynamic import procmon_start, procmon_stop, regshot_snapshot, detect_dropped_files
from .network import fakenet_start, fakenet_stop, fakenet_start_structured, fakenet_stop_structured, monitor_network, is_public_ioc_ip
from .injection import hollows_hunter_scan, unpack_detect_and_try, unpack_detect_and_try_structured


async def triage_full(file_path: str) -> str:
    """Run full automated 8-stage static triage pipeline: Hashes, Signatures, PE structure, DIE, Entropy & RWX, CAPA, FLOSS, YARA."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    report = [
        "=" * 65,
        "FLARE-VM FULL STATIC TRIAGE REPORT",
        "=" * 65,
        f"Target File: {file_path}\n",
    ]

    # 1. Hashes
    report.append("--- 1. File Hashes ---")
    try:
        report.append(await get_file_hash(file_path))
    except Exception as e:
        report.append(f"Hash calculation error: {e}")
    report.append("")

    # 2. Digital Signature (Authenticode)
    report.append("--- 2. Authenticode Digital Signature (sigcheck) ---")
    try:
        report.append(await sigcheck_analyze(file_path))
    except Exception as e:
        report.append(f"Signature check error: {e}")
    report.append("")

    # 3. PE Headers, Imphash, Checksec & Capabilities
    report.append("--- 3. PE Structure, Imphash & Capability Profile ---")
    try:
        report.append(await pe_info(file_path))
    except Exception as e:
        report.append(f"PE structure error: {e}")
    report.append("")

    # 4. DetectItEasy
    report.append("--- 4. Compiler & Packer Detection (DIE) ---")
    try:
        report.append(await die_analyze(file_path))
    except Exception as e:
        report.append(f"DIE error: {e}")
    report.append("")

    # 5. Section Entropy & RWX Anomalies
    report.append("--- 5. PE Section Entropy & Anomaly Analysis ---")
    try:
        report.append(await entropy_analysis(file_path))
    except Exception as e:
        report.append(f"Entropy analysis error: {e}")
    report.append("")

    # 6. CAPA
    report.append("--- 6. Capability Detection (CAPA) ---")
    try:
        report.append(await capa_analyze(file_path))
    except Exception as e:
        report.append(f"CAPA error: {e}")
    report.append("")

    # 7. FLOSS Strings
    report.append("--- 7. Deobfuscated Strings (FLOSS) ---")
    try:
        report.append(await floss_extract_strings(file_path, min_length=6))
    except Exception as e:
        report.append(f"FLOSS error: {e}")
    report.append("")

    # 8. YARA
    report.append("--- 8. YARA Rule Matches ---")
    try:
        report.append(await yara_scan(file_path))
    except Exception as e:
        report.append(f"YARA error: {e}")
    report.append("")

    report.append("=" * 65)
    report.append("END OF STATIC TRIAGE REPORT")
    report.append("=" * 65)

    return safe_truncate("\n".join(report), max_chars=40000)


async def execute_with_monitoring(
    executable: str,
    arguments: Optional[Union[list[str], str]] = None,
    duration: int = 30
) -> str:
    """Execute a binary under Procmon capture with process tree tracking and dropped files detection."""
    if _DYNAMIC_LOCK.locked():
        return "[-] Refusal: Another dynamic analysis is already running. Concurrent sessions are forbidden for host stability."

    async with _DYNAMIC_LOCK:
        try:
            exe_path = validate_dynamic_target(executable)
            executable = str(exe_path)
        except Exception as e:
            return f"[-] Security Refusal: {e}"

        duration = max(1, min(300, int(duration)))
        start_time = time.time()
        deadline = start_time + duration
        run_dir = get_run_temp_dir("exec_mon")
        pml = str(run_dir / "exec_mon.pml")
        csv = str(run_dir / "exec_mon.csv")

        arg_list: list[str] = []
        if arguments:
            if isinstance(arguments, list):
                arg_list = [str(a) for a in arguments if str(a).strip()]
            elif isinstance(arguments, str) and arguments.strip():
                arg_list = shlex.split(arguments, posix=False)
        args_display = " ".join(arg_list)

        target_pid = None
        target_proc = None
        job_handle = None
        all_tree_procs = []
        killed = []
        remaining_procs = []
        proc_summary = ""
        dropped = ""
        cleanup_status = {
            "target_terminated": False,
            "procmon_stopped": False,
        }

        try:
            # 1. Start ProcMon
            procmon_start_msg = await procmon_start(output_path=pml)
            if not os.path.isfile(pml) or os.path.getsize(pml) == 0:
                return (
                    f"[-] Containment Precheck Failed: ProcMon did not initialize backing PML ({pml}).\n"
                    f"ProcMon Status: {procmon_start_msg}\n"
                    f"Execution ABORTED to prevent running target without forensic monitoring."
                )

            # 2. Launch target fail-closed suspended inside Win32 Job Object
            target_proc, job_handle = launch_process_in_job(
                [executable] + arg_list,
                job_handle=None,
                cwd=str(run_dir)
            )
            target_pid = target_proc.pid

            # 3. Monitor process tree over duration using single absolute deadline clock
            poll_interval = 2
            while time.time() < deadline:
                sleep_sec = min(poll_interval, max(0.1, deadline - time.time()))
                await asyncio.sleep(sleep_sec)
                if target_pid:
                    tree = get_process_tree_info(target_pid)
                    for item in tree:
                        if item not in all_tree_procs:
                            all_tree_procs.append(item)
        finally:
            async def _do_cleanup():
                nonlocal killed, remaining_procs, proc_summary, dropped, cleanup_status, job_handle
                if target_pid:
                    try:
                        killed, remaining_procs = kill_process_tree(target_pid, job_handle=job_handle, close_job=False)
                        cleanup_status["target_terminated"] = (len(remaining_procs) == 0 and not psutil.pid_exists(target_pid))
                    except Exception:
                        cleanup_status["target_terminated"] = False
                else:
                    cleanup_status["target_terminated"] = True

                if target_proc:
                    try:
                        target_proc.kill()
                    except Exception:
                        pass

                if job_handle:
                    try:
                        close_job_object(job_handle)
                        job_handle = None
                    except Exception:
                        pass

                # Stop ProcMon and convert PML to CSV
                try:
                    proc_summary = await procmon_stop(pml_path=pml, csv_path=csv, filter_process=os.path.basename(executable))
                    pm_running = any("procmon" in (p.info['name'] or "").lower() for p in psutil.process_iter(['name']))
                    cleanup_status["procmon_stopped"] = not pm_running
                except Exception as e:
                    proc_summary = f"Error stopping ProcMon: {e}"
                    cleanup_status["procmon_stopped"] = False

                # Detect dropped files
                try:
                    elapsed = int(time.time() - start_time) + 5
                    dropped = await detect_dropped_files(since_seconds=elapsed)
                except Exception as e:
                    dropped = f"Error detecting dropped files: {e}"

            cleanup_coro = _do_cleanup()
            try:
                await asyncio.shield(cleanup_coro)
            except asyncio.CancelledError:
                try:
                    await cleanup_coro
                except Exception:
                    pass
                raise

        tree_str = f"Spanned Processes: {len(all_tree_procs)}\n"
        for p in all_tree_procs:
            tree_str += f"  - PID {p['pid']}: {p['name']} ({p.get('cmdline', '')[:60]})\n"

        return (
            f"=== Execution with Monitoring ({duration}s) ===\n"
            f"Executable:   {executable} {args_display}\n"
            f"Artifact Dir: {run_dir}\n"
            f"Target PID:   {target_pid} (Terminated PIDs: {killed})\n"
            f"Cleanup:      Target Terminated: {cleanup_status['target_terminated']} | ProcMon Stopped: {cleanup_status['procmon_stopped']}\n\n"
            f"--- Process Tree ---\n{tree_str}\n"
            f"{wrap_untrusted_data(proc_summary, max_chars=4000, label='PROCMON SUMMARY')}\n\n"
            f"{wrap_untrusted_data(dropped, max_chars=4000, label='DROPPED FILES')}"
        )


async def behavioral_full(
    executable: str,
    arguments: Optional[Union[list[str], str]] = None,
    duration: int = 30
) -> str:
    """Run full automated dynamic behavioral analysis with guaranteed fail-closed containment, process tree tracking, injection scan, FakeNet, and Registry diff."""
    if _DYNAMIC_LOCK.locked():
        return "[-] Refusal: Another dynamic analysis is already running. Concurrent sessions are forbidden for host stability."

    async with _DYNAMIC_LOCK:
        try:
            exe_path = validate_dynamic_target(executable)
            executable = str(exe_path)
        except Exception as e:
            return f"[-] Security Refusal: {e}"

        duration = max(1, min(300, int(duration)))
        start_time = time.time()
        deadline = start_time + duration
        run_dir = get_run_temp_dir("behav")
        pml = str(run_dir / "behav_procmon.pml")
        csv = str(run_dir / "behav_procmon.csv")

        arg_list: list[str] = []
        if arguments:
            if isinstance(arguments, list):
                arg_list = [str(a) for a in arguments if str(a).strip()]
            elif isinstance(arguments, str) and arguments.strip():
                arg_list = shlex.split(arguments, posix=False)
        args_display = " ".join(arg_list)

        report = [
            "=" * 65,
            "FLARE-VM FULL BEHAVIORAL ANALYSIS REPORT",
            "=" * 65,
            f"Executable:   {executable}",
            f"Arguments:    {args_display}",
            f"Artifact Dir: {run_dir}",
            f"Duration:     {duration}s\n"
        ]

        target_pid = None
        target_proc = None
        job_handle = None
        all_tree_procs = []
        killed = []
        remaining_procs = []
        mem_scan = ""
        fakenet_log = ""
        proc_summary = ""
        dropped_files = ""
        reg_diff = ""
        procmon_started = False
        fakenet_started = False

        cleanup_status = {
            "target_terminated": False,
            "procmon_stopped": False,
            "fakenet_stopped": False,
            "dns_restored": False,
            "route_restored": False,
        }

        try:
            # 1. Baseline
            report.append("--- Step 1: System & Registry Baseline ---")
            report.append(await regshot_snapshot("before", workspace_dir=str(run_dir)))
            report.append("")

            # 2. Start ProcMon
            report.append("--- Step 2: Start ProcMon ---")
            procmon_start_msg = await procmon_start(output_path=pml)
            report.append(procmon_start_msg)
            report.append("")
            # Fail-closed check for ProcMon
            if not os.path.isfile(pml) or os.path.getsize(pml) == 0:
                report.append(f"[-] Containment Precheck Failed: ProcMon failed to allocate PML ({pml}). Dynamic execution ABORTED.")
                return "\n".join(report)
            procmon_started = True

            # 3. Start FakeNet
            report.append("--- Step 3: Start FakeNet-NG ---")
            fn_start_res = await fakenet_start_structured()
            report.append(fn_start_res.get("message", ""))
            report.append("")
            # Fail-closed check for FakeNet: abort immediately without substring guessing
            if not fn_start_res.get("ok") or not fn_start_res.get("pid"):
                report.append(f"[-] Containment Precheck Failed: FakeNet failed to start ({fn_start_res.get('error', 'unknown')}). Dynamic execution ABORTED to protect external network.")
                return "\n".join(report)
            fakenet_started = True

            # 4. Launch Target fail-closed suspended inside Win32 Job Object
            report.append("--- Step 4: Executing Target & Tracking Process Tree ---")
            target_proc, job_handle = launch_process_in_job(
                [executable] + arg_list,
                job_handle=None,
                cwd=str(run_dir)
            )
            target_pid = target_proc.pid
            report.append(f"Target launched with PID: {target_pid} (Win32 Job Object containment active)")

            # 5. Continuous Process Tree Monitoring during execution using single absolute deadline clock
            report.append(f"\n--- Step 5: Monitoring Execution ({duration}s) ---")
            scan_reserve = 8 if duration >= 20 else 2
            monitor_deadline = deadline - scan_reserve

            poll_interval = 2
            while time.time() < monitor_deadline:
                sleep_sec = min(poll_interval, max(0.1, monitor_deadline - time.time()))
                await asyncio.sleep(sleep_sec)
                if target_pid:
                    current_tree = get_process_tree_info(target_pid)
                    for p in current_tree:
                        if p not in all_tree_procs:
                            all_tree_procs.append(p)

            if all_tree_procs:
                report.append(f"Discovered {len(all_tree_procs)} process tree member(s):")
                for p in all_tree_procs:
                    report.append(f"  [+] PID {p['pid']:<6} {p['name']:<25} {p.get('cmdline', '')[:80]}")
            else:
                report.append("No active child processes detected.")
            report.append("")

            # 6. Mid-Flight In-Memory Injection Scan (BEFORE killing process, within remaining deadline budget)
            report.append("--- Step 6: Mid-Flight Memory Injection Scan (Hollows Hunter) ---")
            rem_budget = max(5, int(deadline - time.time()))
            try:
                mem_scan = await asyncio.wait_for(
                    hollows_hunter_scan(output_dir=str(run_dir / "hollows")),
                    timeout=rem_budget
                )
                report.append(wrap_untrusted_data(mem_scan, max_chars=4000, label="HOLLOWS HUNTER SCAN"))
            except asyncio.TimeoutError:
                report.append(f"Hollows Hunter mid-flight scan exceeded remaining deadline ({rem_budget}s). Skipped to prioritize teardown.")
            except Exception as e:
                report.append(f"Memory scan error: {e}")
            report.append("")

        finally:
            async def _do_teardown():
                nonlocal killed, remaining_procs, fakenet_log, proc_summary, dropped_files, reg_diff, cleanup_status, job_handle
                # 7. Terminate Malware Process Tree
                report.append("--- Step 7: Terminating Malware Process Tree ---")
                if target_pid:
                    try:
                        killed, remaining_procs = kill_process_tree(target_pid, job_handle=job_handle, close_job=False)
                        report.append(f"Terminated PIDs: {killed}")
                        cleanup_status["target_terminated"] = (len(remaining_procs) == 0 and not psutil.pid_exists(target_pid))
                    except Exception as e:
                        report.append(f"Error terminating process tree: {e}")
                        cleanup_status["target_terminated"] = False
                else:
                    cleanup_status["target_terminated"] = True

                if target_proc:
                    try:
                        target_proc.kill()
                    except Exception:
                        pass

                if job_handle:
                    try:
                        close_job_object(job_handle)
                        job_handle = None
                    except Exception:
                        pass
                report.append("")

                # 8. Stop FakeNet & restore network configuration
                if fakenet_started:
                    report.append("--- Step 8: FakeNet-NG Network Logs & Restoration ---")
                    try:
                        fn_res = await fakenet_stop_structured(start_time=start_time)
                        fakenet_log = fn_res.get("report", "")
                        report.append(fakenet_log)
                        cleanup_status["fakenet_stopped"] = True
                        cleanup_status["dns_restored"] = bool(fn_res.get("dns_verified"))
                        cleanup_status["route_restored"] = bool(fn_res.get("route_verified"))
                    except Exception as e:
                        report.append(f"Error stopping FakeNet: {e}")
                        cleanup_status["fakenet_stopped"] = False
                        cleanup_status["dns_restored"] = False
                        cleanup_status["route_restored"] = False
                    report.append("")
                else:
                    cleanup_status["fakenet_stopped"] = True
                    cleanup_status["dns_restored"] = True
                    cleanup_status["route_restored"] = True

                # 9. Stop ProcMon with Noise Filtering
                if procmon_started:
                    report.append("--- Step 9: ProcMon Activity Results ---")
                    try:
                        proc_summary = await procmon_stop(pml_path=pml, csv_path=csv, ignore_noise=True)
                        report.append(wrap_untrusted_data(proc_summary, max_chars=4000, label="PROCMON SUMMARY"))
                        pm_running = any("procmon" in (p.info['name'] or "").lower() for p in psutil.process_iter(['name']))
                        cleanup_status["procmon_stopped"] = not pm_running
                    except Exception as e:
                        report.append(f"Error stopping ProcMon: {e}")
                        cleanup_status["procmon_stopped"] = False
                    report.append("")
                else:
                    cleanup_status["procmon_stopped"] = True

                # 10. Dropped Files Detection
                report.append("--- Step 10: Dropped & Modified Files ---")
                try:
                    elapsed_time = int(time.time() - start_time) + 10
                    dropped_files = await detect_dropped_files(since_seconds=elapsed_time)
                    report.append(wrap_untrusted_data(dropped_files, max_chars=4000, label="DROPPED FILES"))
                except Exception as e:
                    report.append(f"Error detecting dropped files: {e}")
                report.append("")

                # 11. Registry Diff
                report.append("--- Step 11: Post-Execution Registry & System Diff ---")
                try:
                    await regshot_snapshot("after", workspace_dir=str(run_dir))
                    reg_diff = await regshot_snapshot("compare", workspace_dir=str(run_dir))
                    report.append(reg_diff)
                except Exception as e:
                    report.append(f"Error diffing registry: {e}")
                report.append("")

            teardown_coro = _do_teardown()
            try:
                await asyncio.shield(teardown_coro)
            except asyncio.CancelledError:
                try:
                    await teardown_coro
                except Exception:
                    pass
                raise

        # 12. Hygiene advisory with verified cleanup status
        report.append("=" * 65)
        report.append("CLEANUP STATUS & VM HYGIENE REPORT:")
        report.append(f"  - Target Process Terminated: {cleanup_status['target_terminated']}")
        report.append(f"  - ProcMon Stopped:           {cleanup_status['procmon_stopped']}")
        report.append(f"  - FakeNet Stopped:           {cleanup_status['fakenet_stopped']}")
        report.append(f"  - DNS Configuration Restored:{cleanup_status['dns_restored']}")
        report.append(f"  - Default Route Restored:    {cleanup_status['route_restored']}")
        if all(cleanup_status.values()):
            report.append("\nAll containment and forensic components successfully terminated and restored.")
        else:
            report.append("\n[!] WARNING: One or more cleanup steps could not be verified. Review report before next run.")
        report.append("Remember to revert your Flare-VM snapshot before analyzing the next sample.")
        report.append("=" * 65)

        return safe_truncate("\n".join(report), max_chars=40000)


async def autoruns_analyze(filter_microsoft: bool = True, categories: str = "lste") -> str:
    """Run Sysinternals autorunsc.exe to enumerate autostart entries with non-Microsoft filtering and structured table output."""
    autoruns_path = resolve_tool("autorunsc")
    cmd = [autoruns_path, "-accepteula", "-a", categories, "-c", "-nobanner"]
    if filter_microsoft:
        cmd.append("-m")

    stdout, stderr, code = await run_command_async(cmd, timeout=90)
    if not stdout and stderr:
        return f"Autoruns execution error:\n{stderr}"

    reader = csv.DictReader(io.StringIO(stdout))
    rows = list(reader)

    by_cat = {}
    for r in rows:
        entry = (r.get("Entry") or "").strip()
        img = (r.get("Image Path") or "").strip()
        if not entry and not img:
            continue
        cat = (r.get("Category") or "Other").strip()
        by_cat.setdefault(cat, []).append(r)

    filter_desc = "Non-Microsoft / Third-Party Only (-m)" if filter_microsoft else "All Entries (including Windows defaults)"
    res = [
        "=" * 65,
        "SYSINTERNALS AUTORUNS PERSISTENCE AUDIT",
        "=" * 65,
        f"Filter Mode: {filter_desc}",
        f"Categories:  {categories} (Logon, Services, Tasks, Explorer)",
        f"Total Flagged Items: {len(rows)}\n",
    ]

    if not rows:
        res.append("No third-party autostart entries found matching the specified filter.")
        return "\n".join(res)

    for cat, items in by_cat.items():
        res.append(f"### {cat} ({len(items)} items)")
        res.append("| Entry | Company / Signer | Image Path | Launch Command |")
        res.append("| :--- | :--- | :--- | :--- |")
        for item in items[:25]:
            entry_name = (item.get("Entry") or "Unknown").replace("|", "/")
            company = (item.get("Company") or "Unknown").replace("|", "/")
            img_path = (item.get("Image Path") or "").replace("|", "/")
            launch = (item.get("Launch String") or "").replace("|", "/")
            if len(launch) > 80:
                launch = launch[:77] + "..."
            res.append(f"| {entry_name} | {company} | `{img_path}` | `{launch}` |")
        if len(items) > 25:
            res.append(f"| ... | ... and {len(items) - 25} more omitted | ... | ... |")
        res.append("")

    return wrap_untrusted_data(safe_truncate("\n".join(res), max_chars=40000), label="AUTORUNS ANALYSIS")


async def persistence_audit() -> str:
    """Forensic audit of autostart persistence: Registry Run, Startup Folders, Winlogon, IFEO hijacks, AppInit_DLLs, WMI subscriptions, Tasks, and Services."""
    ps = r"""
Write-Output "=== COMPREHENSIVE PERSISTENCE AUDIT ==="

# 1. Registry Run & RunOnce (HKLM, HKCU, and Wow6432Node)
Write-Output "`n--- 1. Registry Run & RunOnce Keys ---"
$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($k in $keys) {
    if (Test-Path $k) {
        $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Output "  [$k] $($_.Name) = $($_.Value)"
            }
        }
    }
}

# 2. Startup Folders
Write-Output "`n--- 2. Startup Folders ---"
$startup_paths = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
    (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)
$startup_found = 0
foreach ($p in $startup_paths) {
    if (Test-Path $p) {
        $files = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue
        if ($files) {
            foreach ($f in $files) {
                $startup_found++
                Write-Output "  [Startup File] $($f.FullName) ($($f.Length) bytes)"
            }
        }
    }
}
if ($startup_found -eq 0) { Write-Output "  No files found in User or System Startup folders." }

# 3. Winlogon Overrides
Write-Output "`n--- 3. Winlogon Overrides ---"
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Test-Path $winlogon) {
    $props = Get-ItemProperty -Path $winlogon -ErrorAction SilentlyContinue
    Write-Output "  Shell:     $($props.Shell)"
    Write-Output "  Userinit:  $($props.Userinit)"
    if ($props.Taskman) { Write-Output "  [ALERT] Taskman override: $($props.Taskman)" }
}

# 4. Image File Execution Options (IFEO) Debugger Hijacks
Write-Output "`n--- 4. IFEO Debugger Hijacks ---"
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$hijacks = 0
if (Test-Path $ifeo) {
    Get-ChildItem -Path $ifeo -ErrorAction SilentlyContinue | ForEach-Object {
        $sub = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
        if ($sub.Debugger) {
            $hijacks++
            Write-Output "  [HIJACK DETECTED] $($_.PSChildName) -> Debugger: $($sub.Debugger)"
        }
    }
}
if ($hijacks -eq 0) { Write-Output "  No IFEO debugger hijacks detected." }

# 5. AppInit_DLLs
Write-Output "`n--- 5. AppInit_DLLs (DLL Injection) ---"
$appinit_key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
if (Test-Path $appinit_key) {
    $sub = Get-ItemProperty -Path $appinit_key -ErrorAction SilentlyContinue
    $app_dlls = $sub.AppInit_DLLs
    $load_app = $sub.LoadAppInit_DLLs
    if ($app_dlls) {
        Write-Output "  [ALERT] AppInit_DLLs Present: $app_dlls (LoadAppInit_DLLs: $load_app)"
    } else {
        Write-Output "  AppInit_DLLs is clean (empty)."
    }
}

# 6. WMI Event Consumers (Fileless Persistence)
Write-Output "`n--- 6. WMI Event Subscriptions ---"
$wmi_consumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
if ($wmi_consumers) {
    foreach ($w in $wmi_consumers) {
        Write-Output "  [WMI Consumer] $($w.Name): $($w.CommandLineTemplate)"
    }
} else {
    Write-Output "  No custom WMI event consumers detected."
}

# 7. Active Non-Microsoft Scheduled Tasks
Write-Output "`n--- 7. Non-Microsoft Scheduled Tasks ---"
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' } | Select-Object -First 25
if ($tasks) {
    foreach ($t in $tasks) {
        $action = $t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        Write-Output "  Task: $($t.TaskName) | State: $($t.State) | Action: $action"
    }
} else {
    Write-Output "  No non-Microsoft scheduled tasks found."
}

# 8. Non-Standard Services
Write-Output "`n--- 8. Non-Standard Services ---"
$services = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and $_.PathName -notmatch 'C:\\Windows\\system32' -and $_.PathName -notmatch 'C:\\Windows\\servicing'
} | Select-Object -First 25
if ($services) {
    foreach ($s in $services) {
        Write-Output "  Service: $($s.Name) [$($s.State)] -> $($s.PathName)"
    }
} else {
    Write-Output "  No non-standard services found."
}
"""
    stdout, _, _ = await run_powershell_async(ps, timeout=60)
    return wrap_untrusted_data(safe_truncate(stdout, max_chars=40000), label="PERSISTENCE AUDIT")


def _defang_text(text: str) -> str:
    """Safely defang URLs, domain names, and IPv4 addresses for threat intelligence reporting."""
    # Defang URLs: http -> hxxp
    text = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), text)
    # Defang IP addresses: 1.2.3.4 -> 1.2.3[.]4
    text = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1.\2.\3[.]\4", text)
    # Defang common TLD domains: example.com -> example[.]com
    tlds = r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|me|online|site|cc|tk|to|pw|su|onion)"
    text = re.sub(rf"\b([a-zA-Z0-9-]+)\.({tlds})\b", r"\1[.]\2", text, flags=re.IGNORECASE)
    return text


async def generate_ioc_report(file_path: str, output_path: str = "") -> str:
    """Compile an automated, defanged Threat Intelligence & IOC Markdown report for a binary sample."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    base_name = os.path.basename(file_path)
    if not output_path:
        stem = os.path.splitext(base_name)[0]
        output_path = str(get_output_root() / f"{stem}_ioc_report.md")
    else:
        try:
            output_path = str(validate_output_path(output_path))
        except Exception as e:
            return f"[-] Security Refusal on output_path: {e}"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # 1. Hashes & Metadata
    hashes_str = await get_file_hash(file_path)
    sig_str = await sigcheck_analyze(file_path)
    pe_str = await pe_info(file_path)
    capa_str = await capa_analyze(file_path)
    strings_raw = await strings_extract(file_path, min_length=5)

    # 2. Extract Network Indicators from Strings
    raw_urls = set(re.findall(r"https?://[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+", strings_raw, re.IGNORECASE))
    SCHEMA_DOMAINS = (
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "www.w3.org",
        "tempuri.org",
        "purl.org",
        "xml.org",
        "xmlsoap.org",
        "oasis-open.org",
    )
    filtered_urls = {
        u for u in raw_urls
        if not any(domain in u.lower() for domain in SCHEMA_DOMAINS)
    }
    raw_ips = set(re.findall(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", strings_raw))
    # Filter non-routable, private, loopback, or multicast IPs
    filtered_ips = {ip for ip in raw_ips if is_public_ioc_ip(ip)}
    raw_pdbs = set(re.findall(r"[a-zA-Z]:\\[^\x00-\x1f<>\":|?*]+\.pdb", strings_raw, re.IGNORECASE))

    # Defang indicators
    defanged_urls = [_defang_text(u) for u in sorted(filtered_urls)[:15]]
    defanged_ips = [_defang_text(ip) for ip in sorted(filtered_ips)[:15]]

    # 3. Extract Candidate Command Lines & Scripting Invocations
    raw_cmd_lines = []
    for line in strings_raw.splitlines():
        line_clean = line.strip()
        if len(line_clean) < 8 or len(line_clean) > 300:
            continue
        lower = line_clean.lower()
        if any(trigger in lower for trigger in ("cmd.exe", "powershell", "ping ", "del /", "reg add", "net user", "net localgroup", "wscript", "cscript", "bitsadmin", "certutil", "vssadmin", "schtasks", "sc.exe", "rundll32", "regsvr32", "mshta", "curl ", "wget ")):
            if line_clean not in raw_cmd_lines:
                raw_cmd_lines.append(line_clean)

    # 4. Extract Staged / Dropped File Paths
    raw_file_paths = []
    for line in strings_raw.splitlines():
        line_clean = line.strip()
        if len(line_clean) < 6 or len(line_clean) > 260 or line_clean.startswith("File:"):
            continue
        m = re.search(r"(?:[a-zA-Z]:\\|%[a-zA-Z_]+%\\)(?:Users|ProgramData|Windows|temp|Documents|Downloads|AppData|Local|Roaming)\\[^\x00-\x1f<>\":|?* ]+\.(?:exe|dll|dat|bin|bat|cmd|vbs|ps1|tmp|txt|ico|png|jpg|sys)", line_clean, re.IGNORECASE)
        if m:
            fp = m.group(0)
            if not fp.lower().endswith(".pdb") and fp not in raw_file_paths:
                raw_file_paths.append(fp)

    # 5. Extract MITRE ATT&CK TTPs and Capabilities from CAPA
    ttps = []
    for line in capa_str.splitlines():
        line_s = line.strip()
        if any(marker in line_s for marker in ("ATT&CK", "T1", "T0", "MBC", "objective", "behavior")):
            if not line_s.startswith("=") and not line_s.startswith("-") and len(line_s) > 4:
                ttps.append(line_s)

    # 6. Build Report
    report = [
        f"# Threat Intelligence & IOC Report: {base_name}",
        f"\n**Target File**: `{file_path}`",
        f"**Analysis Mode**: Static & Capability Extraction",
        f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
        "---",
        "## 1. File Identification & Hashes\n",
        hashes_str,
        "\n---",
        "## 2. Authenticode Signature & Verification\n",
        sig_str,
        "\n---",
        "## 3. PE Structure & Suspicious API Capability Profile\n",
        pe_str,
        "\n---",
        "## 4. Candidate Network Indicators (Unverified Strings - Defanged)\n",
    ]

    if defanged_urls:
        report.append("### Extracted Candidate URLs (Defanged)")
        for u in defanged_urls:
            report.append(f"- `{u}`")
        report.append("")
    else:
        report.append("- No public HTTP/HTTPS URLs extracted from strings.\n")

    if defanged_ips:
        report.append("### Extracted Candidate Public IPv4 Addresses (Defanged)")
        for ip in defanged_ips:
            report.append(f"- `{ip}`")
        report.append("")
    else:
        report.append("- No public IPv4 addresses extracted from strings.\n")

    if raw_pdbs:
        report.append("### PDB Debug Paths")
        for pdb in raw_pdbs:
            report.append(f"- `{pdb}`")
        report.append("")

    report.append("---")
    report.append("## 5. Candidate Command Lines & Shell Invocations\n")
    if raw_cmd_lines:
        for cmd in raw_cmd_lines[:15]:
            report.append(f"- `{cmd}`")
        report.append("")
    else:
        report.append("- No shell or scripting command lines identified in strings.\n")

    report.append("---")
    report.append("## 6. Candidate Staged & Dropped File Paths\n")
    if raw_file_paths:
        for fp in raw_file_paths[:15]:
            report.append(f"- `{fp}`")
        report.append("")
    else:
        report.append("- No filesystem paths identified in strings.\n")

    report.append("---")
    report.append("## 7. MITRE ATT&CK Tactics & Capabilities (CAPA)\n")
    if ttps:
        for t in ttps[:25]:
            report.append(f"- {t}")
    else:
        report.append("Refer to full CAPA report for complete MITRE ATT&CK mapping.")

    report_content = "\n".join(report)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    res = (
        f"=== IOC Report Generated ===\n"
        f"Saved to: {output_path}\n\n"
        f"{report_content[:2500]}\n\n"
        f"[... Full report ({len(report_content)} characters) written to {output_path} ...]"
    )
    return wrap_untrusted_data(res, label="IOC REPORT")


async def unpack_and_triage(file_path: str) -> str:
    """End-to-end automated pipeline: detect packing/obfuscation, unpack payload, and run deep static triage on unpacked binary."""
    try:
        file_path = str(require_sample_file(file_path))
    except Exception as e:
        return f"[-] Security Refusal: {e}"

    base_name = os.path.basename(file_path)
    res_lines = [
        "=" * 65,
        f"AUTOMATED UNPACK & TRIAGE PIPELINE: {base_name}",
        "=" * 65,
        f"Input File: {file_path}\n",
        "--- STAGE 1: Automated Packer Detection & Unpacking ---"
    ]

    unpack_meta = await unpack_detect_and_try_structured(file_path)
    res_lines.append(unpack_meta["report"])

    # Directly consume structured output with physical file verification
    unpacked_file = None
    if unpack_meta.get("success") and unpack_meta.get("unpacked_file"):
        cand = unpack_meta["unpacked_file"]
        if os.path.isfile(cand) and os.path.getsize(cand) > 0:
            unpacked_file = cand

    target_for_triage = unpacked_file or file_path
    is_unpacked = bool(unpacked_file)

    res_lines.append("\n" + "=" * 65)
    if is_unpacked:
        res_lines.append(f"--- STAGE 2: Deep Static Triage of Unpacked Binary ---")
        res_lines.append(f"Unpacked Target: {unpacked_file} (Engine: {unpack_meta.get('engine', 'auto')})")
    else:
        res_lines.append(f"--- STAGE 2: Deep Static Triage of Original Binary ---")
        res_lines.append(f"(Binary was not packed or already clean: {file_path})")
    res_lines.append("=" * 65 + "\n")

    triage_res = await triage_full(target_for_triage)
    res_lines.append(triage_res)

    if is_unpacked:
        orig_size = os.path.getsize(file_path)
        new_size = os.path.getsize(unpacked_file)
        res_lines.append("\n" + "=" * 65)
        res_lines.append("--- STAGE 3: Comparative Analysis Summary ---")
        res_lines.append(f"Original Binary:  {file_path} ({orig_size} bytes)")
        res_lines.append(f"Unpacked Payload: {unpacked_file} ({new_size} bytes)")
        diff_pct = round(((new_size - orig_size) / max(orig_size, 1)) * 100, 1)
        res_lines.append(f"Size Change:      {diff_pct}%")
        res_lines.append(f"Unpack Engine:    {unpack_meta.get('engine', 'auto')}")
        res_lines.append("Inner code and structures are now fully exposed for decompilation or debugging.")
        res_lines.append("=" * 65)

    return safe_truncate("\n".join(res_lines), max_chars=45000)
