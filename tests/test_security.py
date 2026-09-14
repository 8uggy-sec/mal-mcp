"""Security hardening regression test suite for mal-mcp.

Verifies:
1. Server import and MCP tool registration
2. Shell command gating (MAL_MCP_ENABLE_SHELL)
3. Dynamic analysis gating (MAL_MCP_ENABLE_DYNAMIC)
4. Target path confinement to MAL_MCP_SAMPLE_ROOT
5. Rejection of dangerous path patterns (UNC, device paths, ADS, NUL bytes)
6. Command interpreter blocklist for dynamic analysis
7. Win32 Job Object fail-closed suspended launch and termination
8. FakeNet recovery state schema & IP validation
9. Output path confinement to MAL_MCP_OUTPUT_ROOT
10. Credential redaction and untrusted data wrapping
11. API identifier strict validation
12. Concurrency locking on dynamic analysis playbooks
"""

import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure package root is in sys.path
pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
parent_dir = os.path.dirname(pkg_root)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if pkg_root not in sys.path:
    sys.path.insert(1, pkg_root)

import mal_mcp
import mal_mcp.server
from mal_mcp.security import (
    feature_enabled,
    require_feature,
    require_sample_file,
    validate_dynamic_target,
    validate_output_path,
    redact_credentials,
    wrap_untrusted_data,
    validate_api_identifier,
    BLOCKED_COMMAND_INTERPRETERS,
)
from mal_mcp.helpers import (
    create_job_object,
    close_job_object,
    launch_process_in_job,
    kill_process_tree,
)
from mal_mcp.tools.network import validate_fakenet_recovery_state, pcap_analyze, fakenet_start_structured
from mal_mcp.tools.dynamic import procmon_export_csv
from mal_mcp.tools.static import (
    die_analyze, capa_analyze, pe_info, sigcheck_analyze,
    entropy_analysis, strings_extract, floss_extract_strings,
    yara_scan, dnspy_decompile
)
from mal_mcp.tools.injection import (
    pe_sieve_scan, hollows_hunter_scan, procdump_process,
    injection_scan_all, de4dot_deobfuscate, extract_pe_overlay, upx_unpack
)
from unittest.mock import patch, AsyncMock
from mal_mcp.tools.playbooks import _DYNAMIC_LOCK, execute_with_monitoring, behavioral_full


class TestSecurityHardening(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Preserve environment
        self.orig_env = os.environ.copy()

    def tearDown(self):
        # Restore environment
        os.environ.clear()
        os.environ.update(self.orig_env)

    def test_server_import_and_tool_registration(self):
        """Verify mal_mcp.server imports cleanly and registers MCP tools."""
        self.assertIsNotNone(mal_mcp.server.mcp)
        tool_names = mal_mcp.server.mcp._tool_manager._tools.keys()
        self.assertIn("check_flarevm_status", tool_names)
        self.assertIn("execute_with_monitoring", tool_names)
        self.assertIn("behavioral_full", tool_names)
        self.assertIn("fakenet_start", tool_names)

    async def test_shell_gating_disabled_by_default(self):
        """Verify execute_powershell and execute_cmd are refused when MAL_MCP_ENABLE_SHELL=0."""
        os.environ["MAL_MCP_ENABLE_SHELL"] = "0"
        res_ps = await mal_mcp.server.execute_powershell("Get-Process")
        self.assertIn("disabled by default for security", res_ps)

        res_cmd = await mal_mcp.server.execute_cmd("dir")
        self.assertIn("disabled by default for security", res_cmd)

    async def test_dynamic_gating_disabled_by_default(self):
        """Verify dynamic MCP entry points are refused when MAL_MCP_ENABLE_DYNAMIC=0."""
        os.environ["MAL_MCP_ENABLE_DYNAMIC"] = "0"

        res_mon = await mal_mcp.server.execute_with_monitoring("test.exe")
        self.assertIn("disabled by default for security", res_mon)

        res_beh = await mal_mcp.server.behavioral_full("test.exe")
        self.assertIn("disabled by default for security", res_beh)

        res_pm_start = await mal_mcp.server.procmon_start()
        self.assertIn("disabled by default for security", res_pm_start)

        res_fn_start = await mal_mcp.server.fakenet_start()
        self.assertIn("disabled by default for security", res_fn_start)

        res_dbg = await mal_mcp.server.x64dbg_load("test.exe")
        self.assertIn("disabled by default for security", res_dbg)

        res_pm_exp = await mal_mcp.server.procmon_export_csv("test.pml", "test.csv")
        self.assertIn("disabled by default for security", res_pm_exp)

    def test_target_outside_sample_root_rejected(self):
        """Verify target sample files outside MAL_MCP_SAMPLE_ROOT are rejected."""
        with tempfile.TemporaryDirectory() as sample_dir, tempfile.TemporaryDirectory() as evil_dir:
            os.environ["MAL_MCP_SAMPLE_ROOT"] = sample_dir

            evil_file = Path(evil_dir) / "evil.exe"
            evil_file.write_bytes(b"MZ\x90\x00")

            with self.assertRaises(PermissionError) as ctx:
                require_sample_file(evil_file)
            self.assertIn("Security Violation: Target path", str(ctx.exception))

            good_file = Path(sample_dir) / "good.exe"
            good_file.write_bytes(b"MZ\x90\x00")
            resolved = require_sample_file(good_file)
            self.assertEqual(resolved, good_file.resolve())

    def test_dangerous_path_patterns_rejected(self):
        """Verify UNC paths, device namespaces, NTFS ADS, and NUL bytes are rejected."""
        # Empty
        with self.assertRaises(ValueError):
            require_sample_file("")
        # NUL byte
        with self.assertRaises(ValueError):
            require_sample_file("C:\\Samples\\test\x00.exe")
        # UNC path
        with self.assertRaises(ValueError):
            require_sample_file(r"\\192.168.1.50\share\payload.exe")
        with self.assertRaises(ValueError):
            require_sample_file("//192.168.1.50/share/payload.exe")
        # Device path
        with self.assertRaises(ValueError):
            require_sample_file(r"\\.\pipe\docker_engine")
        with self.assertRaises(ValueError):
            require_sample_file(r"\\?\C:\Samples\test.exe")
        # NTFS Alternate Data Stream
        with self.assertRaises(ValueError):
            require_sample_file(r"C:\Samples\notepad.exe:hidden.exe")
        # Quotation mark and newline injection tokens
        with self.assertRaises(ValueError):
            require_sample_file(r'C:\Samples\test.exe"; calc.exe')
        with self.assertRaises(ValueError):
            require_sample_file("C:\\Samples\\test.exe\nwhoami")

    def test_command_interpreters_blocked_for_dynamic_analysis(self):
        """Verify command interpreters are blocked from dynamic execution unless shell mode is active."""
        with tempfile.TemporaryDirectory() as sample_dir:
            os.environ["MAL_MCP_SAMPLE_ROOT"] = sample_dir
            os.environ["MAL_MCP_ENABLE_SHELL"] = "0"

            for interpreter in ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "mshta.exe"]:
                fake_target = Path(sample_dir) / interpreter
                fake_target.write_bytes(b"MZ\x90\x00")

                with self.assertRaises(PermissionError) as ctx:
                    validate_dynamic_target(fake_target)
                self.assertIn("Security Refusal: Execution of command interpreter", str(ctx.exception))

            # When shell mode is enabled, it should pass validation
            os.environ["MAL_MCP_ENABLE_SHELL"] = "1"
            cmd_target = Path(sample_dir) / "cmd.exe"
            res = validate_dynamic_target(cmd_target)
            self.assertEqual(res, cmd_target.resolve())

    def test_job_object_containment_and_termination(self):
        """Verify launch_process_in_job creates suspended process, assigns to Job Object, and closes cleanly."""
        if sys.platform != "win32":
            return

        cmd = [sys.executable, "-c", "import time; time.sleep(30)"]
        proc, h_job = launch_process_in_job(cmd)
        try:
            self.assertIsNotNone(proc.pid)
            self.assertIsNotNone(h_job)
            self.assertIsNone(proc.poll(), "Process should be running after resume")

            # Terminate via Job Object handle
            close_job_object(h_job)
            h_job = None

            # Verify process terminates
            proc.wait(timeout=5)
            self.assertIsNotNone(proc.poll())
        finally:
            if h_job:
                close_job_object(h_job)
            if proc.poll() is None:
                proc.kill()

    def test_fakenet_recovery_state_validation(self):
        """Verify FakeNet recovery state validation rejects tampered/malformed data."""
        # Valid state
        valid_state = {
            "dns_baseline": [
                {
                    "interface_index": 5,
                    "mode": "dhcp",
                    "server_addresses": ["10.0.0.1"]
                },
                {
                    "interface_index": 7,
                    "mode": "static",
                    "server_addresses": ["8.8.8.8", "1.1.1.1"]
                }
            ],
            "route": {
                "created": True,
                "destination": "0.0.0.0/0",
                "interface_index": 5,
                "next_hop": "192.168.1.1",
                "metric": 250
            }
        }
        self.assertTrue(validate_fakenet_recovery_state(valid_state))

        # Invalid: not a dict
        self.assertFalse(validate_fakenet_recovery_state("malicious_string"))

        # Invalid: malicious IP string (command injection attempt)
        bad_ip_state = {
            "dns_baseline": [
                {
                    "interface_index": 5,
                    "mode": "static",
                    "server_addresses": ["10.0.0.1; Invoke-Expression evil"]
                }
            ],
            "route": {"created": False}
        }
        self.assertFalse(validate_fakenet_recovery_state(bad_ip_state))

        # Invalid: negative interface index
        bad_if_state = {
            "dns_baseline": [
                {
                    "interface_index": -1,
                    "mode": "dhcp",
                    "server_addresses": []
                }
            ],
            "route": {"created": False}
        }
        self.assertFalse(validate_fakenet_recovery_state(bad_if_state))

        # Invalid: route created is not boolean
        bad_route_state = {
            "dns_baseline": [],
            "route": {
                "created": "true",  # string instead of bool
                "destination": "0.0.0.0/0",
                "interface_index": 5,
                "next_hop": "192.168.1.1",
                "metric": 250
            }
        }
        self.assertFalse(validate_fakenet_recovery_state(bad_route_state))

    def test_output_path_confinement(self):
        """Verify validate_output_path restricts output files to authorized output root."""
        with tempfile.TemporaryDirectory() as out_dir:
            os.environ["MAL_MCP_OUTPUT_ROOT"] = out_dir

            valid_out = Path(out_dir) / "run1" / "analysis.json"
            resolved = validate_output_path(valid_out)
            self.assertEqual(resolved, valid_out.resolve())

            # Traversal escape
            evil_out = Path(out_dir) / ".." / "system_file.exe"
            with self.assertRaises(PermissionError):
                validate_output_path(evil_out)

    def test_credential_redaction_and_wrapping(self):
        """Verify HTTP headers, tokens, and cookies are redacted and wrapped as untrusted data."""
        raw_text = (
            "POST /api/v1/exfil HTTP/1.1\r\n"
            "Host: evil-c2.com\r\n"
            "Authorization: Bearer secret_jwt_token_123456789\r\n"
            "Cookie: session_id=abcdef1234567890; admin=1\r\n"
            "api_key: secret_api_key_value_987654321\r\n"
            "\r\n"
            "sensitive data payload"
        )
        redacted = redact_credentials(raw_text)
        self.assertNotIn("secret_jwt_token_123456789", redacted)
        self.assertNotIn("abcdef1234567890", redacted)
        self.assertNotIn("secret_api_key_value_987654321", redacted)
        self.assertIn("[REDACTED]", redacted)

        wrapped = wrap_untrusted_data(raw_text, label="TEST HARNESS")
        self.assertIn("=== BEGIN UNTRUSTED DATA (TEST HARNESS) ===", wrapped)
        self.assertIn("=== END UNTRUSTED DATA (TEST HARNESS) ===", wrapped)
        self.assertIn("SHA256=", wrapped)
        self.assertNotIn("secret_jwt_token_123456789", wrapped)

    def test_api_identifier_strict_validation(self):
        """Verify custom x64dbg API identifiers match strict regex and reject dangerous chars."""
        # Valid Win32 API names
        self.assertTrue(validate_api_identifier("CreateFileA"))
        self.assertTrue(validate_api_identifier("VirtualAllocEx"))
        self.assertTrue(validate_api_identifier("NtQueryInformationProcess"))
        self.assertTrue(validate_api_identifier("_InitOnceExecuteOnce"))
        self.assertTrue(validate_api_identifier("func_MyClass_YAXXZ"))

        # Invalid / injection attempts
        self.assertFalse(validate_api_identifier(""))
        self.assertFalse(validate_api_identifier("CreateFileA; rm -rf /"))
        self.assertFalse(validate_api_identifier("cmd.exe & whoami"))
        self.assertFalse(validate_api_identifier("API Name With Spaces"))
        self.assertFalse(validate_api_identifier("A" * 200))

    async def test_concurrent_dynamic_locking(self):
        """Verify dynamic playbooks refuse execution if another dynamic analysis is active."""
        os.environ["MAL_MCP_ENABLE_DYNAMIC"] = "1"
        self.assertFalse(_DYNAMIC_LOCK.locked())

        # Simulate an ongoing dynamic analysis by acquiring the lock
        await _DYNAMIC_LOCK.acquire()
        try:
            res_mon = await execute_with_monitoring("C:\\Samples\\test.exe")
            self.assertIn("Another dynamic analysis is already running.", res_mon)

            res_beh = await behavioral_full("C:\\Samples\\test.exe")
            self.assertIn("Another dynamic analysis is already running.", res_beh)
        finally:
            _DYNAMIC_LOCK.release()



    async def test_procmon_export_csv_injection_and_containment(self):
        """Verify procmon_export_csv safely handles malicious arguments without shell injection."""
        os.environ["MAL_MCP_ENABLE_DYNAMIC"] = "1"
        with tempfile.TemporaryDirectory() as out_dir:
            os.environ["MAL_MCP_OUTPUT_ROOT"] = out_dir

            # Path traversal / escaping output root is refused
            evil_pml = r"..\..\Windows\System32\cmd.exe"
            res = await procmon_export_csv(evil_pml, os.path.join(out_dir, "out.csv"))
            self.assertIn("[-] Security Refusal", res)

            # Malicious characters / injection tokens are rejected by path validation
            evil_cmd_pml = os.path.join(out_dir, 'test.pml"; calc.exe; #')
            res2 = await procmon_export_csv(evil_cmd_pml, os.path.join(out_dir, "out.csv"))
            self.assertIn("[-] Security Refusal", res2)

            # Non-existent PML file
            good_pml = os.path.join(out_dir, "valid.pml")
            res3 = await procmon_export_csv(good_pml, os.path.join(out_dir, "out.csv"))
            self.assertIn("PML file does not exist", res3)

    async def test_static_tools_sample_confinement(self):
        """Verify all static analysis tools refuse target files outside MAL_MCP_SAMPLE_ROOT."""
        with tempfile.TemporaryDirectory() as sample_dir, tempfile.TemporaryDirectory() as evil_dir:
            os.environ["MAL_MCP_SAMPLE_ROOT"] = sample_dir
            evil_file = str(Path(evil_dir) / "evil.exe")
            Path(evil_file).write_bytes(b"MZ\x90\x00")

            for fn, name in [
                (die_analyze(evil_file), "die_analyze"),
                (capa_analyze(evil_file), "capa_analyze"),
                (entropy_analysis(evil_file), "entropy_analysis"),
                (pe_info(evil_file), "pe_info"),
                (sigcheck_analyze(evil_file), "sigcheck_analyze"),
                (strings_extract(evil_file), "strings_extract"),
                (floss_extract_strings(evil_file), "floss_extract_strings"),
                (yara_scan(evil_file), "yara_scan"),
                (dnspy_decompile(evil_file), "dnspy_decompile"),
            ]:
                res = await fn
                self.assertIn("[-] Security Refusal", res, f"Failed confinement check on {name}")

    async def test_injection_tools_output_confinement(self):
        """Verify injection and memory analysis tools refuse output directories outside MAL_MCP_OUTPUT_ROOT."""
        with tempfile.TemporaryDirectory() as out_dir, tempfile.TemporaryDirectory() as evil_dir:
            os.environ["MAL_MCP_OUTPUT_ROOT"] = out_dir
            evil_out = str(Path(evil_dir) / "escaped")

            res_ps = await pe_sieve_scan(pid=99999, output_dir=evil_out)
            self.assertIn("[-] Security Refusal", res_ps)

            res_hh = await hollows_hunter_scan(output_dir=evil_out)
            self.assertIn("[-] Security Refusal", res_hh)

            res_pd = await procdump_process(pid=99999, output_dir=evil_out)
            self.assertIn("[-] Security Refusal", res_pd)

            res_inj = await injection_scan_all(output_dir=evil_out)
            self.assertIn("[-] Security Refusal", res_inj)

    async def test_pcap_analyze_output_confinement(self):
        """Verify pcap_analyze refuses PCAP files outside MAL_MCP_OUTPUT_ROOT."""
        with tempfile.TemporaryDirectory() as out_dir, tempfile.TemporaryDirectory() as evil_dir:
            os.environ["MAL_MCP_OUTPUT_ROOT"] = out_dir
            evil_pcap = str(Path(evil_dir) / "capture.pcap")
            Path(evil_pcap).write_bytes(b"\xd4\xc3\xb2\xa1")

            res = await pcap_analyze(pcap_path=evil_pcap)
            self.assertIn("[-] Security Refusal", res)

    async def test_fakenet_failure_aborts_behavioral_full(self):
        """Verify behavioral_full aborts immediately when FakeNet fails to initialize."""
        os.environ["MAL_MCP_ENABLE_DYNAMIC"] = "1"
        with tempfile.TemporaryDirectory() as sample_dir, tempfile.TemporaryDirectory() as out_dir:
            os.environ["MAL_MCP_SAMPLE_ROOT"] = sample_dir
            os.environ["MAL_MCP_OUTPUT_ROOT"] = out_dir

            target_exe = Path(sample_dir) / "sample.exe"
            target_exe.write_bytes(b"MZ\x90\x00")

            # Mock procmon_start to succeed and create PML
            async def fake_procmon_start(output_path):
                Path(output_path).write_bytes(b"PML_HEADER")
                return "ProcMon started"

            # Mock fakenet_start_structured to report driver failure
            async def fake_fakenet_failed():
                return {
                    "ok": False,
                    "pid": None,
                    "message": "[-] Driver initialization failed",
                    "error": "WinDivert failed to load"
                }

            with patch("mal_mcp.tools.playbooks.procmon_start", side_effect=fake_procmon_start), \
                 patch("mal_mcp.tools.playbooks.fakenet_start_structured", side_effect=fake_fakenet_failed), \
                 patch("mal_mcp.tools.playbooks.launch_process_in_job") as mock_launch:

                res = await behavioral_full(str(target_exe), duration=5)
                self.assertIn("Containment Precheck Failed: FakeNet failed to start", res)
                self.assertIn("Dynamic execution ABORTED", res)
                # Verify malware binary was NEVER launched
                mock_launch.assert_not_called()

    def test_non_windows_job_object_fail_closed(self):
        """Verify launch_process_in_job raises RuntimeError on non-Windows platforms."""
        with patch("sys.platform", "linux"):
            with self.assertRaises(RuntimeError) as ctx:
                launch_process_in_job(["/bin/ls"])
            self.assertIn("Win32 Job Object process containment is only supported on Windows", str(ctx.exception))

if __name__ == "__main__":
    unittest.main()
