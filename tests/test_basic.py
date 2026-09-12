"""Basic regression and unit tests for mal-mcp (Standard library unittest + pytest compatible)."""

import csv
import io
import os
import sys
import tempfile
import unittest

# Ensure parent directory is in sys.path
pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
parent_dir = os.path.dirname(pkg_root)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if pkg_root not in sys.path:
    sys.path.insert(1, pkg_root)

import mal_mcp
from mal_mcp.tools.network import is_public_ioc_ip
from mal_mcp.tools.playbooks import _defang_text
from mal_mcp.tools.system import execute_powershell, execute_cmd, read_file_hex
from mal_mcp.tools.injection import unpack_detect_and_try_structured
from mal_mcp.helpers import create_job_object, close_job_object


class TestMalMcp(unittest.IsolatedAsyncioTestCase):

    def test_version_consistency(self):
        """Ensure __version__ matches pyproject.toml and is 1.0.1."""
        self.assertEqual(mal_mcp.__version__, "1.0.1")

        pyproject_path = os.path.join(pkg_root, "pyproject.toml")
        with open(pyproject_path, "r", encoding="utf-8") as f:
            pyproject_text = f.read()
        self.assertIn('version = "1.0.1"', pyproject_text)

    def test_is_public_ioc_ip(self):
        """Verify private, loopback, link-local, and broadcast IPs are filtered out."""
        self.assertFalse(is_public_ioc_ip("127.0.0.1"))
        self.assertFalse(is_public_ioc_ip("10.0.0.5"))
        self.assertFalse(is_public_ioc_ip("192.168.1.1"))
        self.assertFalse(is_public_ioc_ip("172.16.5.10"))
        self.assertFalse(is_public_ioc_ip("169.254.10.20"))
        self.assertFalse(is_public_ioc_ip("224.0.0.1"))
        self.assertFalse(is_public_ioc_ip("255.255.255.255"))
        self.assertFalse(is_public_ioc_ip("0.0.0.0"))

        # Public IPs should pass
        self.assertTrue(is_public_ioc_ip("8.8.8.8"))
        self.assertTrue(is_public_ioc_ip("1.1.1.1"))
        self.assertTrue(is_public_ioc_ip("93.184.216.34"))

    def test_defang_text(self):
        """Verify URL, domain, and IP defanging."""
        text = "Connect to http://malware-c2.com and download from https://198.51.100.25/payload.exe"
        defanged = _defang_text(text)
        self.assertIn("hxxp://", defanged)
        self.assertIn("hxxps://", defanged)
        self.assertIn("malware-c2[.]com", defanged)
        self.assertIn("198.51.100[.]25", defanged)

    async def test_shell_execution_gating(self):
        """Verify execute_powershell and execute_cmd are gated behind MAL_MCP_ENABLE_SHELL."""
        old_val = os.environ.get("MAL_MCP_ENABLE_SHELL")
        try:
            os.environ["MAL_MCP_ENABLE_SHELL"] = "0"
            ps_res = await execute_powershell("Get-Process")
            self.assertIn("disabled by default", ps_res)

            cmd_res = await execute_cmd("dir")
            self.assertIn("disabled by default", cmd_res)
        finally:
            if old_val is not None:
                os.environ["MAL_MCP_ENABLE_SHELL"] = old_val
            else:
                os.environ.pop("MAL_MCP_ENABLE_SHELL", None)

    async def test_read_file_hex_bounds(self):
        """Verify read_file_hex safely handles negative offset and non-positive length."""
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"Hello Flare-VM Malware Analysis")
            tmp_path = tf.name

        try:
            res_neg = await read_file_hex(tmp_path, offset=-5, length=10)
            self.assertIn("Invalid offset", res_neg)

            res_zero = await read_file_hex(tmp_path, offset=0, length=0)
            self.assertIn("Invalid length", res_zero)

            res_ok = await read_file_hex(tmp_path, offset=0, length=10)
            self.assertIn("Hex Dump", res_ok)
            self.assertIn("48 65 6C 6C 6F", res_ok)
        finally:
            os.remove(tmp_path)

    def test_job_object_lifecycle(self):
        """Verify Win32 Job Object creation and closure."""
        handle = create_job_object()
        if sys.platform == "win32":
            self.assertIsNotNone(handle)
            close_job_object(handle)
        else:
            self.assertIsNone(handle)

    def test_procmon_csv_null_byte_tolerance(self):
        """Verify CSV parser tolerates NUL bytes and UTF-16 LE BOM from ProcMon exports."""
        raw_bytes = b"\xff\xfeT\x00i\x00m\x00e\x00,\x00P\x00r\x00o\x00c\x00e\x00s\x00s\x00 \x00N\x00a\x00m\x00e\x00\r\x00\n\x001\x002\x00:\x000\x000\x00,\x00m\x00a\x00l\x00.\x00e\x00x\x00e\x00\r\x00\n\x00"

        if raw_bytes.startswith(b"\xff\xfe"):
            text = raw_bytes.decode("utf-16-le", errors="replace")
        else:
            text = raw_bytes.decode("utf-8", errors="replace")
        cleaned_text = text.replace("\x00", "")

        reader = csv.DictReader(io.StringIO(cleaned_text))
        rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Process Name"], "mal.exe")

    async def test_unpack_structured_return_missing_file(self):
        """Verify unpack_detect_and_try_structured returns clean metadata dictionary."""
        res = await unpack_detect_and_try_structured(r"C:\non_existent_binary_xyz123.exe")
        self.assertIsInstance(res, dict)
        self.assertFalse(res["success"])
        self.assertEqual(res["engine"], "none")
        self.assertIn("File not found", res["report"])


if __name__ == "__main__":
    unittest.main()
