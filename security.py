"""Central Security Controls & Containment Boundaries for mal-mcp.

Implements defense-in-depth boundaries:
1. Feature gating (MAL_MCP_ENABLE_SHELL, MAL_MCP_ENABLE_DYNAMIC, MAL_MCP_ENABLE_SSE)
2. Strict path validation (canonical resolution, UNC/ADS/device-path rejection, root confinement)
3. Dynamic target interpreter restriction
4. Untrusted data wrapping & credential redaction
5. API identifier syntax verification
"""

import functools
import hashlib
import ipaddress
import os
import re
import sys
from pathlib import Path
from typing import Callable, Optional, Union, Any

# ── FEATURE GATING ─────────────────────────────────────────────────────────────

def feature_enabled(name: str, default: bool = False) -> bool:
    """Check whether a security feature flag is enabled in the environment or Windows user registry."""
    val = os.environ.get(name)
    if val is not None:
        return val.strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                reg_val, _ = winreg.QueryValueEx(key, name)
                return str(reg_val).strip().lower() in ("1", "true", "yes", "on", "enable", "enabled")
        except Exception:
            pass
    return default


def require_feature(name: str) -> Callable:
    """Decorator to gate an MCP tool endpoint behind an environment feature flag."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not feature_enabled(name):
                return (
                    f"Error: Refused. Feature '{name}' is disabled by default for security.\n"
                    f"To enable this capability in your Flare-VM sandbox, set environment variable {name}=1."
                )
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            if not feature_enabled(name):
                return (
                    f"Error: Refused. Feature '{name}' is disabled by default for security.\n"
                    f"To enable this capability in your Flare-VM sandbox, set environment variable {name}=1."
                )
            return func(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    return decorator


# ── CANONICAL ROOTS & PATH RESTRICTIONS ────────────────────────────────────────

def get_sample_root() -> Path:
    """Return canonical directory permitted for analysis targets."""
    p = Path(os.environ.get("MAL_MCP_SAMPLE_ROOT", r"C:\Samples"))
    return p.resolve()


def get_output_root() -> Path:
    """Return canonical root directory permitted for analysis artifacts & outputs."""
    p = Path(os.environ.get("MAL_MCP_OUTPUT_ROOT", r"C:\temp\mal_mcp"))
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


BLOCKED_COMMAND_INTERPRETERS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "python.exe",
    "pythonw.exe",
    "node.exe",
}


def _check_dangerous_path_patterns(path_str: str) -> None:
    """Reject UNC paths, Windows device namespaces, and NTFS Alternate Data Streams."""
    if not path_str or not path_str.strip():
        raise ValueError("Path cannot be empty or whitespace.")

    if "\x00" in path_str:
        raise ValueError("Path contains illegal NUL bytes.")

    if any(c in path_str for c in ('"', '\r', '\n', '<', '>')):
        raise ValueError(f"Path contains illegal or dangerous characters: '{path_str}'")

    normalized = path_str.replace("/", "\\").strip()

    # Reject UNC network shares and device namespaces: \\, \\?\, \\.\
    if normalized.startswith("\\\\") or normalized.startswith("//"):
        raise ValueError(f"UNC network paths and device namespaces are forbidden: '{path_str}'")

    # Reject Alternate Data Streams (colon anywhere after drive specifier e.g. C:...)
    check_str = normalized
    if len(check_str) >= 2 and check_str[1] == ":" and check_str[0].isalpha():
        check_str = check_str[2:]
    if ":" in check_str:
        raise ValueError(f"NTFS Alternate Data Streams are forbidden: '{path_str}'")


def require_sample_file(path: Union[str, Path], allowed_root: Optional[Path] = None) -> Path:
    """Validate that a target sample exists, is a regular file, and resides within allowed root."""
    path_str = str(path)
    _check_dangerous_path_patterns(path_str)

    target = Path(path_str).resolve()
    if not target.exists():
        raise FileNotFoundError(f"File not found: Target sample file does not exist: '{target}'")
    if not target.is_file():
        raise ValueError(f"Target path is not a regular file: '{target}'")

    root = (allowed_root or get_sample_root()).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError(
            f"Security Violation: Target path '{target}' is outside permitted sample root '{root}'.\n"
            f"Set MAL_MCP_SAMPLE_ROOT to permit alternative directory."
        )

    return target


def validate_dynamic_target(path: Union[str, Path], allowed_root: Optional[Path] = None) -> Path:
    """Validate sample path for dynamic execution and verify interpreter blocklist."""
    target = require_sample_file(path, allowed_root=allowed_root)

    # Prevent dynamic execution bypass using command interpreters unless shell mode is explicitly active
    if target.name.lower() in BLOCKED_COMMAND_INTERPRETERS:
        if not feature_enabled("MAL_MCP_ENABLE_SHELL"):
            raise PermissionError(
                f"Security Refusal: Execution of command interpreter '{target.name}' is blocked "
                f"in dynamic analysis mode unless MAL_MCP_ENABLE_SHELL=1 is explicitly set."
            )

    return target


def validate_output_path(path: Union[str, Path], allowed_root: Optional[Path] = None) -> Path:
    """Validate that an output file path remains strictly within the authorized output workspace."""
    path_str = str(path)
    _check_dangerous_path_patterns(path_str)

    target = Path(path_str).resolve()
    root = (allowed_root or get_output_root()).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError(
            f"Security Violation: Output path '{target}' escapes authorized output root '{root}'."
        )

    return target


# ── UNTRUSTED DATA WRAPPING & CREDENTIAL REDACTION ────────────────────────────

CREDENTIAL_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key[\s:=]+)[^\s;&\r\n]{6,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token[\s:=]+)[^\s;&\r\n]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password[\s:=]+)[^\s;&\r\n]+"), r"\1[REDACTED]"),
]


def redact_credentials(text: str) -> str:
    """Redact authentication headers, cookies, tokens, and credentials from text."""
    redacted = text
    for pattern, repl in CREDENTIAL_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


def wrap_untrusted_data(text: str, max_chars: int = 8000, label: str = "SAMPLE DATA") -> str:
    """Wrap untrusted output with boundary markers, metadata hash, and credential redaction."""
    if text is None:
        return ""

    raw_bytes = text.encode("utf-8", errors="replace")
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    total_len = len(text)

    redacted = redact_credentials(text)
    truncated = False
    if len(redacted) > max_chars:
        redacted = redacted[:max_chars] + f"\n... [Truncated {len(redacted) - max_chars} characters. Full content preserved on disk] ..."
        truncated = True

    return (
        f"=== BEGIN UNTRUSTED DATA ({label}) ===\n"
        f"[Metadata: SHA256={sha256} | TotalBytes={len(raw_bytes)} | Truncated={truncated}]\n"
        f"{redacted}\n"
        f"=== END UNTRUSTED DATA ({label}) ==="
    )


# ── API IDENTIFIER STRICT VALIDATION ──────────────────────────────────────────

API_IDENTIFIER_REGEX = re.compile(r"^[A-Za-z_][A-Za-z0-9_@$?.]{0,127}$")


def validate_api_identifier(identifier: str) -> bool:
    """Strictly validate custom API identifier syntax to prevent injection attacks."""
    if not identifier or not isinstance(identifier, str):
        return False
    return bool(API_IDENTIFIER_REGEX.fullmatch(identifier.strip()))
