"""Comprehensive End-to-End Verification Suite for mal-mcp.

Executes and verifies all tool categories against notepad.exe and synthetic test artifacts:
- Category 1: System & Host Diagnostics
- Category 2: Static Analysis & PE Headers
- Category 3: Dynamic Analysis & Process Monitoring (ProcMon)
- Category 4: Network Simulation & Capture (FakeNet, TShark, Sockets)
- Category 5: Memory Injection & Unpacking (PE-sieve, Hollows Hunter, ProcDump, UPX, Overlays)
- Category 6: Debuggers & Emulators (scdbg, blobrunner, x64dbg scripts, IDA/dnSpy probing)
- Category 7: Composite Playbooks (triage_full, execute_with_monitoring, behavioral_full, autoruns, persistence, IOC report, unpack_and_triage)
"""

import asyncio
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Ensure mal_mcp package can be imported directly
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root.parent) not in sys.path:
    sys.path.insert(0, str(repo_root.parent))
if str(repo_root) not in sys.path:
    sys.path.insert(1, str(repo_root))

from mal_mcp.tools import system, static, dynamic, network, injection, debuggers, playbooks
from mal_mcp.config import resolve_tool, TEMP_DIR

TEST_DIR = TEMP_DIR / "notepad_verification"
TARGET_EXE = TEST_DIR / "notepad.exe"
TARGET_UPX = TEST_DIR / "notepad_upx.exe"
TARGET_OVERLAY = TEST_DIR / "notepad_overlay.exe"
TARGET_SC = TEST_DIR / "dummy_shellcode.bin"


def setup_test_artifacts():
    """Set up target notepad.exe and synthetic variants for testing."""
    TEST_DIR.mkdir(parents=True, exist_ok=True)
    src_notepad = r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(src_notepad):
        raise FileNotFoundError(f"Source notepad.exe not found at {src_notepad}")

    # 1. Copy clean notepad.exe
    shutil.copyfile(src_notepad, str(TARGET_EXE))

    # 2. Create UPX-packed notepad.exe
    try:
        upx_path = resolve_tool("upx")
        subprocess.run(
            [upx_path, "--force", str(TARGET_EXE), "-o", str(TARGET_UPX)],
            capture_output=True,
            check=True
        )
    except Exception as e:
        print(f"Warning: Could not create UPX packed notepad: {e}")

    # 3. Create notepad with overlay payload
    shutil.copyfile(str(TARGET_EXE), str(TARGET_OVERLAY))
    with open(str(TARGET_OVERLAY), "ab") as fh:
        fh.write(b"MAL_MCP_VERIFICATION_TEST_OVERLAY_DATA_" * 16)

    # 4. Create safe dummy shellcode (NOP sled + XOR EAX, EAX + RET)
    with open(str(TARGET_SC), "wb") as fh:
        fh.write(b"\x90\x90\x90\x90\x31\xc0\xc3")


results = []


async def run_test(category: str, name: str, coro):
    """Run an async tool test and record duration and result."""
    t0 = time.time()
    status = "PASS"
    error_msg = ""
    try:
        res = await coro
        if res is None or (isinstance(res, str) and ("Error:" in res and "expected" not in res.lower())):
            status = "WARN"
            error_msg = str(res)[:120]
    except Exception as e:
        status = "FAIL"
        error_msg = str(e)

    elapsed = time.time() - t0
    results.append({
        "category": category,
        "name": name,
        "status": status,
        "duration": round(elapsed, 2),
        "detail": error_msg
    })
    mark = "[PASS]" if status == "PASS" else (f"[{status}]" if status == "WARN" else "[FAIL]")
    print(f"  {mark:<7} {name:<35} ({elapsed:.2f}s) {error_msg}")


async def main():
    print("=" * 75)
    print("mal-mcp AUTOMATED END-TO-END VERIFICATION SUITE")
    print(f"Target Binary: {TARGET_EXE}")
    print("=" * 75)

    setup_test_artifacts()
    print("Test artifacts prepared in", TEST_DIR)
    print()

    # ── Category 1: System & Host Diagnostics ──────────────────────────────
    print(">>> 1. SYSTEM & HOST DIAGNOSTICS")
    await run_test("System", "check_flarevm_status", system.check_flarevm_status())
    await run_test("System", "get_file_hash", system.get_file_hash(str(TARGET_EXE)))
    await run_test("System", "read_file_hex", system.read_file_hex(str(TARGET_EXE), offset=0, length=128))
    await run_test("System", "list_processes", system.list_processes(filter_name=""))
    await run_test("System", "execute_powershell (safe-gate)", system.execute_powershell("Get-Date"))
    await run_test("System", "execute_cmd (safe-gate)", system.execute_cmd("ver"))

    # ── Category 2: Static Analysis ─────────────────────────────────────────
    print("\n>>> 2. STATIC ANALYSIS")
    await run_test("Static", "die_analyze", static.die_analyze(str(TARGET_EXE)))
    await run_test("Static", "pe_info", static.pe_info(str(TARGET_EXE)))
    await run_test("Static", "entropy_analysis", static.entropy_analysis(str(TARGET_EXE)))
    await run_test("Static", "strings_extract", static.strings_extract(str(TARGET_EXE), min_length=6))
    await run_test("Static", "sigcheck_analyze", static.sigcheck_analyze(str(TARGET_EXE)))
    await run_test("Static", "yara_scan (inline rule)", static.yara_scan(str(TARGET_EXE), rule_string='rule IsPE { strings: $mz = "MZ" condition: $mz at 0 }'))
    await run_test("Static", "floss_extract_strings", static.floss_extract_strings(str(TARGET_EXE), min_length=6))
    await run_test("Static", "capa_analyze", static.capa_analyze(str(TARGET_EXE)))

    # ── Category 3: Dynamic Analysis ────────────────────────────────────────
    print("\n>>> 3. DYNAMIC ANALYSIS & PROCMON")
    pml_test = str(TEST_DIR / "test_pm.pml")
    csv_test = str(TEST_DIR / "test_pm.csv")
    await run_test("Dynamic", "procmon_start", dynamic.procmon_start(output_path=pml_test))

    # Spawn test notepad process for PID testing
    target_proc = subprocess.Popen([str(TARGET_EXE)])
    target_pid = target_proc.pid
    await asyncio.sleep(2)

    await run_test("Dynamic", "process_info", dynamic.process_info(target_pid))
    await run_test("Dynamic", "procmon_stop", dynamic.procmon_stop(pml_path=pml_test, csv_path=csv_test, filter_process="notepad"))
    await run_test("Dynamic", "procmon_export_csv", dynamic.procmon_export_csv(pml_path=pml_test, csv_path=csv_test))
    await run_test("Dynamic", "detect_dropped_files", dynamic.detect_dropped_files(since_seconds=60))
    await run_test("Dynamic", "regshot_snapshot (before)", dynamic.regshot_snapshot("before", workspace_dir=str(TEST_DIR)))
    await run_test("Dynamic", "regshot_snapshot (after)", dynamic.regshot_snapshot("after", workspace_dir=str(TEST_DIR)))
    await run_test("Dynamic", "regshot_snapshot (compare)", dynamic.regshot_snapshot("compare", workspace_dir=str(TEST_DIR)))

    # ── Category 4: Network & Simulation ───────────────────────────────────
    print("\n>>> 4. NETWORK & SIMULATION")
    await run_test("Network", "network_connections_list", network.network_connections_list())
    await run_test("Network", "monitor_network (short)", network.monitor_network(duration=3))
    await run_test("Network", "fakenet_start", network.fakenet_start())
    await run_test("Network", "fakenet_stop", network.fakenet_stop())
    pcap_test = str(TEST_DIR / "net_test.pcap")
    await run_test("Network", "wireshark_capture", network.wireshark_capture(duration=4, output_pcap=pcap_test))
    await run_test("Network", "pcap_analyze", network.pcap_analyze(pcap_path=pcap_test))

    # ── Category 5: Injection & Memory Analysis ────────────────────────────
    print("\n>>> 5. INJECTION & UNPACKING")
    await run_test("Injection", "pe_sieve_scan", injection.pe_sieve_scan(target_pid, output_dir=str(TEST_DIR / "pe_sieve")))
    await run_test("Injection", "procdump_process", injection.procdump_process(target_pid, output_dir=str(TEST_DIR / "dumps"), full_memory=False))
    await run_test("Injection", "hollows_hunter_scan", injection.hollows_hunter_scan(output_dir=str(TEST_DIR / "hollows")))
    await run_test("Injection", "extract_pe_overlay (clean)", injection.extract_pe_overlay(str(TARGET_EXE)))
    await run_test("Injection", "extract_pe_overlay (overlay)", injection.extract_pe_overlay(str(TARGET_OVERLAY)))
    if os.path.isfile(str(TARGET_UPX)):
        await run_test("Injection", "upx_unpack", injection.upx_unpack(str(TARGET_UPX), str(TEST_DIR / "notepad_unpacked.exe")))
        await run_test("Injection", "unpack_detect_and_try", injection.unpack_detect_and_try(str(TARGET_UPX), str(TEST_DIR / "notepad_auto_unupx.exe")))

    # Clean up spawned test target
    try:
        target_proc.terminate()
        target_proc.wait(timeout=3)
    except Exception:
        target_proc.kill()

    # ── Category 6: Debuggers & Emulation ──────────────────────────────────
    print("\n>>> 6. DEBUGGERS & EMULATION")
    await run_test("Debuggers", "scdbg_emulate_shellcode", debuggers.scdbg_emulate_shellcode(str(TARGET_SC)))
    await run_test("Debuggers", "blobrunner_prepare", debuggers.blobrunner_prepare(str(TARGET_SC), arch="x64"))
    await run_test("Debuggers", "x64dbg_generate_script", debuggers.x64dbg_generate_script(template="anti_anti_debug", output_path=str(TEST_DIR / "x64dbg_test.txt")))
    await run_test("Debuggers", "x64dbg_run_script", debuggers.x64dbg_run_script("log test", script_path=str(TEST_DIR / "x64dbg_test.txt")))
    await run_test("Debuggers", "ida_status", debuggers.ida_status())
    await run_test("Debuggers", "dnspy_status", debuggers.dnspy_status())

    # ── Category 7: Composite Playbooks ────────────────────────────────────
    print("\n>>> 7. COMPOSITE PLAYBOOKS")
    await run_test("Playbooks", "autoruns_analyze", playbooks.autoruns_analyze(filter_microsoft=True))
    await run_test("Playbooks", "persistence_audit", playbooks.persistence_audit())
    await run_test("Playbooks", "generate_ioc_report", playbooks.generate_ioc_report(str(TARGET_EXE), output_path=str(TEST_DIR / "notepad_ioc.md")))
    await run_test("Playbooks", "execute_with_monitoring", playbooks.execute_with_monitoring(executable=str(TARGET_EXE), duration=5))
    await run_test("Playbooks", "behavioral_full", playbooks.behavioral_full(executable=str(TARGET_EXE), duration=8))
    if os.path.isfile(str(TARGET_UPX)):
        await run_test("Playbooks", "unpack_and_triage", playbooks.unpack_and_triage(str(TARGET_UPX)))
    await run_test("Playbooks", "triage_full", playbooks.triage_full(str(TARGET_EXE)))

    # ── Summary Report ─────────────────────────────────────────────────────
    print("\n" + "=" * 75)
    print("VERIFICATION SUITE SUMMARY MATRIX")
    print("=" * 75)
    passed = sum(1 for r in results if r["status"] == "PASS")
    warn = sum(1 for r in results if r["status"] == "WARN")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)

    print(f"Total Tests Executed: {total}")
    print(f"Passed:               {passed} / {total} ({(passed/total)*100:.1f}%)")
    if warn:
        print(f"Warnings:             {warn}")
    if failed:
        print(f"Failed:               {failed}")

    print("\nDetailed Matrix:")
    print(f"{'Category':<14} {'Tool Test Name':<32} {'Status':<8} {'Time (s)':<10}")
    print("-" * 68)
    for r in results:
        print(f"{r['category']:<14} {r['name']:<32} {r['status']:<8} {r['duration']:<10.2f}")

    print("=" * 75)
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
