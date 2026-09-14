"""Helper routines for executing commands, PowerShell, and GUI apps on Flare-VM."""

import asyncio
import ctypes
from ctypes import wintypes
import datetime
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
from typing import Tuple, Optional, Union, List, Any
import uuid
import psutil

# ── WIN32 JOB OBJECT DEFINITIONS ───────────────────────────────────────────────
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JobObjectExtendedLimitInformation = 9
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
CREATE_SUSPENDED = 0x00000004

if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE

    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
else:
    kernel32 = None


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]


def create_job_object() -> Optional[int]:
    """Create a Windows Job Object configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE."""
    try:
        h_job = kernel32.CreateJobObjectW(None, None)
        if not h_job:
            return None

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ret = kernel32.SetInformationJobObject(
            h_job,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info)
        )
        if not ret:
            kernel32.CloseHandle(h_job)
            return None
        return h_job
    except Exception:
        return None


def assign_process_to_job(job_handle: int, pid: int) -> bool:
    """Assign a process PID to a Windows Job Object for kernel-level containment."""
    if not job_handle or not pid:
        return False
    h_proc = None
    try:
        h_proc = kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not h_proc:
            return False
        ret = kernel32.AssignProcessToJobObject(job_handle, h_proc)
        return bool(ret)
    except Exception:
        return False
    finally:
        if h_proc:
            kernel32.CloseHandle(h_proc)


def close_job_object(job_handle: int) -> None:
    """Close Job Object handle, atomically terminating all member processes."""
    if job_handle:
        try:
            kernel32.TerminateJobObject(job_handle, 1)
        except Exception:
            pass
        try:
            kernel32.CloseHandle(job_handle)
        except Exception:
            pass


def launch_process_in_job(
    cmd: Union[list[str], str],
    job_handle: Optional[int] = None,
    cwd: Optional[str] = None,
    stdout: Any = subprocess.DEVNULL,
    stderr: Any = subprocess.DEVNULL,
    stdin: Any = subprocess.DEVNULL,
) -> Tuple[subprocess.Popen, int]:
    """Launch a process suspended, assign to Win32 Job Object, and resume execution.

    Fail-closed: If Job Object creation or process assignment fails, the target is
    terminated immediately before executing any code.
    Returns (proc, job_handle).
    """
    if sys.platform != "win32" or not kernel32:
        raise RuntimeError("Fail-closed: Win32 Job Object process containment is only supported on Windows Flare-VM.")

    owned_job = False
    if not job_handle:
        job_handle = create_job_object()
        owned_job = True
        if not job_handle:
            raise RuntimeError("Fail-closed: Unable to create Win32 Job Object for containment.")

    cmd_list = cmd if isinstance(cmd, list) else shlex.split(cmd, posix=False)
    creationflags = (
        getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    )

    try:
        proc = subprocess.Popen(
            cmd_list,
            creationflags=creationflags,
            cwd=cwd,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
        )
    except Exception as e:
        if owned_job and job_handle:
            close_job_object(job_handle)
        raise RuntimeError(f"Fail-closed: Failed to spawn suspended target: {e}") from e

    assigned = assign_process_to_job(job_handle, proc.pid)
    if not assigned:
        try:
            proc.terminate()
            proc.kill()
        except Exception:
            pass
        if owned_job and job_handle:
            close_job_object(job_handle)
        raise RuntimeError(
            f"Fail-closed: Failed to assign suspended process PID {proc.pid} to Job Object. "
            f"Process was terminated immediately before execution."
        )

    try:
        psutil.Process(proc.pid).resume()
    except Exception as e:
        try:
            proc.kill()
        except Exception:
            pass
        if owned_job and job_handle:
            close_job_object(job_handle)
        raise RuntimeError(f"Failed to resume process PID {proc.pid} after Job assignment: {e}") from e

    return proc, job_handle


async def run_command_async(
    cmd: list[str],
    timeout: int = 120,
    cwd: Optional[str] = None,
    input_text: Optional[str] = None
) -> Tuple[str, str, int]:
    """Run an executable asynchronously, returning (stdout, stderr, exit_code) with process tree cleanup on timeout."""
    stdin_pipe = subprocess.PIPE if input_text is not None else subprocess.DEVNULL
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=stdin_pipe,
        cwd=cwd
    )

    input_bytes = input_text.encode("utf-8") if input_text else None
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(input=input_bytes),
            timeout=timeout
        )
        def _smart_decode(b: bytes) -> str:
            if not b:
                return ""
            if b"\x00" in b:
                try:
                    return b.decode("utf-16").strip("\x00")
                except Exception:
                    pass
            return b.decode("utf-8", errors="replace")

        stdout = _smart_decode(stdout_bytes)
        stderr = _smart_decode(stderr_bytes)
        return stdout, stderr, proc.returncode or 0
    except asyncio.TimeoutError:
        if proc.pid:
            kill_process_tree(proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except Exception:
            pass
        return "", f"Command timed out after {timeout} seconds", -1


async def run_powershell_async(
    script: str,
    timeout: int = 120
) -> Tuple[str, str, int]:
    """Execute PowerShell code locally with ExecutionPolicy Bypass."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", script
    ]
    return await run_command_async(cmd, timeout=timeout)



def get_run_temp_dir(prefix: str = "run") -> Path:
    """Create an isolated, unique temporary directory for an analysis run under MAL_MCP_OUTPUT_ROOT."""
    from .security import get_output_root
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"{ts}_{prefix}_{uuid.uuid4().hex[:6]}"
    run_dir = get_output_root() / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


async def launch_gui_app_proc(exe_path: str, arguments: Optional[list[str] | str] = None) -> Tuple[str, Optional[int]]:
    """Launch a GUI application decoupled from the server session and return (status_message, pid)."""
    if not os.path.isfile(exe_path) and not shutil.which(exe_path):
        return f"Executable not found: {exe_path}", None

    cmd = [exe_path]
    if arguments:
        if isinstance(arguments, list):
            cmd.extend([str(a) for a in arguments if str(a).strip()])
        elif isinstance(arguments, str):
            cmd.extend(shlex.split(arguments, posix=False))

    try:
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )
        proc = subprocess.Popen(
            cmd,
            creationflags=creationflags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        return f"Successfully launched {os.path.basename(exe_path)} (PID: {proc.pid})", proc.pid
    except Exception as e:
        return f"Failed to launch {exe_path}: {e}", None


async def launch_gui_app(exe_path: str, arguments: Optional[list[str] | str] = None) -> str:
    """Launch a GUI application decoupled from the server session using direct process creation."""
    msg, _ = await launch_gui_app_proc(exe_path, arguments)
    return msg


def safe_truncate(text: str, max_chars: int = 25000) -> str:
    """Truncate long text with a warning note if exceeded."""
    if len(text) <= max_chars:
        return text
    truncated = text[:max_chars]
    return f"{truncated}\n\n[... Truncated: {len(text) - max_chars} characters omitted ...]"


def get_process_tree_info(pid: int) -> list[dict]:
    """Retrieve details of parent process and all child/descendant processes recursively."""
    import psutil
    descendants = []
    try:
        parent = psutil.Process(pid)
        procs = [parent] + parent.children(recursive=True)
        for p in procs:
            try:
                descendants.append({
                    "pid": p.pid,
                    "name": p.name(),
                    "cmdline": " ".join(p.cmdline()),
                    "status": p.status()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return descendants


def kill_process_tree(pid: int, job_handle: Optional[int] = None, close_job: bool = True) -> tuple[list[int], list[int]]:
    """Forcefully terminate a process tree using Windows Job Object containment, psutil, and taskkill fallback.
    
    Verifies that all captured PIDs have exited before returning.
    Returns (terminated_pids, remaining_pids).
    """
    all_pids = []
    tracked_procs = []

    # 1. Enumerate known tree members
    try:
        parent = psutil.Process(pid)
        tracked_procs = [parent] + parent.children(recursive=True)
        for p in tracked_procs:
            all_pids.append(p.pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        all_pids.append(pid)

    # 2. Kernel-level Job Object termination if attached
    if job_handle and close_job:
        close_job_object(job_handle)

    # 3. Individual psutil kill traversal
    for p in tracked_procs:
        try:
            p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # 4. Windows taskkill fallback (/F /T)
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)

    # 5. Verification: wait up to 3 seconds for all processes to exit
    for _ in range(6):
        alive = [p for p in tracked_procs if p.is_running()]
        if not alive:
            break
        time.sleep(0.5)

    remaining_pids = [p.pid for p in tracked_procs if p.is_running()]
    terminated_pids = [p for p in list(dict.fromkeys(all_pids)) if p not in remaining_pids]
    return terminated_pids, remaining_pids

