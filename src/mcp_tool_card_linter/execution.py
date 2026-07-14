from __future__ import annotations

import ctypes
import math
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


class ExecutionError(RuntimeError):
    """Raised when a requested execution boundary cannot be established."""


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    memory_mb: int = 512
    cpu_count: float = 1.0
    process_count: int = 64
    temporary_mb: int = 64
    cpu_seconds: int = 60

    def __post_init__(self) -> None:
        _bounded_int("memory_mb", self.memory_mb, 16, 65_536)
        if (
            isinstance(self.cpu_count, bool)
            or not isinstance(self.cpu_count, (int, float))
            or not math.isfinite(float(self.cpu_count))
            or not 0.1 <= float(self.cpu_count) <= 64.0
        ):
            raise ValueError("cpu_count must be finite and in 0.1..64")
        _bounded_int("process_count", self.process_count, 1, 4096)
        _bounded_int("temporary_mb", self.temporary_mb, 1, 4096)
        _bounded_int("cpu_seconds", self.cpu_seconds, 1, 86_400)


@dataclass(slots=True)
class ManagedProcess:
    process: subprocess.Popen[bytes]
    _release: Callable[[], None] | None = None

    def release(self) -> None:
        callback = self._release
        self._release = None
        if callback is not None:
            callback()


class ProcessExecutor(Protocol):
    @property
    def name(self) -> str: ...

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess: ...


@dataclass(frozen=True, slots=True)
class DenyExecutor:
    name: str = "none"

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess:
        del command, cwd, env
        raise ExecutionError(
            "Local command execution is disabled; select an executor after reviewing the command"
        )


@dataclass(frozen=True, slots=True)
class HostExecutor:
    """Explicit compatibility backend without filesystem or network isolation."""

    name: str = "host"

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess:
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=-1,
            start_new_session=os.name == "posix",
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt"
                else 0
            ),
        )
        return ManagedProcess(process)


_IMAGE_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,511}\Z")
_CONTAINER_ENV_EXCLUSIONS = {
    "COMSPEC",
    "HOME",
    "LOGNAME",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USER",
    "WINDIR",
}


@dataclass(frozen=True, slots=True)
class DockerExecutor:
    image: str
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    binary: str = "docker"
    name: str = "docker"

    def __post_init__(self) -> None:
        if not isinstance(self.image, str) or not _IMAGE_REFERENCE.fullmatch(self.image):
            raise ValueError("Docker image must be a bounded image reference without whitespace")

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess:
        if cwd is not None:
            raise ExecutionError(
                "Docker execution does not map host cwd; omit config cwd and use paths inside the image"
            )
        binary = shutil.which(self.binary)
        if binary is None:
            raise ExecutionError(f"Docker executable not found: {self.binary}")
        docker_command = [
            binary,
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--pids-limit",
            str(self.limits.process_count),
            "--memory",
            f"{self.limits.memory_mb}m",
            "--memory-swap",
            f"{self.limits.memory_mb}m",
            "--cpus",
            f"{float(self.limits.cpu_count):g}",
            "--tmpfs",
            (
                "/tmp:rw,noexec,nosuid,nodev,mode=1777,"
                f"size={self.limits.temporary_mb}m"
            ),
            "--workdir",
            "/tmp",
        ]
        for key in sorted(env):
            if key not in _CONTAINER_ENV_EXCLUSIONS:
                # Passing only the name avoids exposing its value through argv.
                docker_command.extend(("--env", key))
        docker_command.extend((self.image, *command))
        process = subprocess.Popen(
            docker_command,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=-1,
            start_new_session=os.name == "posix",
        )
        return ManagedProcess(process)


@dataclass(frozen=True, slots=True)
class BubblewrapExecutor:
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    binary: str = "bwrap"
    name: str = "bubblewrap"

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess:
        if not _running_on_linux():
            raise ExecutionError("Bubblewrap execution is supported only on Linux")
        binary = shutil.which(self.binary)
        if binary is None:
            raise ExecutionError(f"Bubblewrap executable not found: {self.binary}")
        workdir = Path(cwd or os.getcwd()).resolve()
        if not workdir.is_dir():
            raise ExecutionError("Bubblewrap working directory must be an existing directory")

        sandbox_command = [
            binary,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/etc",
        ]
        for path in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
            if Path(path).exists():
                sandbox_command.extend(("--ro-bind", path, path))
        for path in ("/etc/ld.so.cache", "/etc/ssl", "/etc/ca-certificates"):
            if Path(path).exists():
                sandbox_command.extend(("--ro-bind", path, path))
        for parent in reversed(workdir.parents):
            if str(parent) != "/":
                sandbox_command.extend(("--dir", str(parent)))
        sandbox_command.extend(("--ro-bind", str(workdir), str(workdir)))
        sandbox_command.extend(("--chdir", str(workdir)))

        prlimit = shutil.which("prlimit")
        if prlimit is not None:
            sandbox_command.extend(
                (
                    prlimit,
                    f"--as={self.limits.memory_mb * 1024 * 1024}",
                    f"--nproc={self.limits.process_count}",
                    f"--cpu={self.limits.cpu_seconds}",
                    "--",
                )
            )
        sandbox_command.extend(command)
        process = subprocess.Popen(
            sandbox_command,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=-1,
            start_new_session=True,
        )
        return ManagedProcess(process)


@dataclass(frozen=True, slots=True)
class WindowsJobExecutor:
    limits: ExecutionLimits = field(default_factory=ExecutionLimits)
    name: str = "windows-job"

    def spawn(
        self,
        command: Sequence[str],
        *,
        cwd: str | None,
        env: Mapping[str, str],
    ) -> ManagedProcess:
        if os.name != "nt":
            raise ExecutionError("Windows Job Object execution is supported only on Windows")
        process = subprocess.Popen(
            list(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=-1,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        try:
            job = _create_windows_job(process, self.limits)
        except BaseException:
            process.kill()
            process.wait(timeout=5)
            raise

        def release() -> None:
            kernel32 = _windows_kernel32()
            if not kernel32.CloseHandle(job):
                raise ExecutionError(
                    f"CloseHandle(job) failed with Windows error {_windows_error()}"
                )

        return ManagedProcess(process, release)


def executor_from_options(
    backend: str,
    *,
    image: str | None = None,
    limits: ExecutionLimits | None = None,
) -> ProcessExecutor:
    effective_limits = limits or ExecutionLimits()
    if backend == "none":
        return DenyExecutor()
    if backend == "host":
        return HostExecutor()
    if backend == "docker":
        if image is None:
            raise ExecutionError("--executor-image is required for the Docker executor")
        return DockerExecutor(image=image, limits=effective_limits)
    if backend == "bubblewrap":
        return BubblewrapExecutor(limits=effective_limits)
    if backend == "windows-job":
        return WindowsJobExecutor(limits=effective_limits)
    raise ExecutionError(f"Unsupported executor backend: {backend}")


def _create_windows_job(
    process: subprocess.Popen[bytes], limits: ExecutionLimits
) -> int:
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
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
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = _windows_kernel32()
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ExecutionError(
            f"CreateJobObject failed with Windows error {_windows_error()}"
        )
    information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    information.BasicLimitInformation.LimitFlags = (
        0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | 0x00000008  # JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | 0x00000200  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | 0x00000100  # JOB_OBJECT_LIMIT_PROCESS_TIME
    )
    information.BasicLimitInformation.ActiveProcessLimit = limits.process_count
    information.BasicLimitInformation.PerProcessUserTimeLimit = limits.cpu_seconds * 10_000_000
    information.ProcessMemoryLimit = limits.memory_mb * 1024 * 1024
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(information), ctypes.sizeof(information)
    ):
        error = _windows_error()
        kernel32.CloseHandle(job)
        raise ExecutionError(f"SetInformationJobObject failed with Windows error {error}")
    process_handle = getattr(process, "_handle", None)
    if process_handle is None or not kernel32.AssignProcessToJobObject(job, process_handle):
        error = _windows_error()
        kernel32.CloseHandle(job)
        raise ExecutionError(f"AssignProcessToJobObject failed with Windows error {error}")
    return int(job)


def _running_on_linux() -> bool:
    return sys.platform.startswith("linux")


def _windows_kernel32() -> Any:
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise ExecutionError("Windows kernel APIs are unavailable on this platform")
    return loader("kernel32", use_last_error=True)


def _windows_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    return int(getter()) if getter is not None else 0


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
