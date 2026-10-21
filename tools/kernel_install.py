#!/usr/bin/env python3
"""AnyKernel3 kernel installer for WSL hosts driving Windows platform-tools.

The normal installation path is ADB-only.  Windows ``adb.exe`` and
``fastboot.exe`` are invoked through WSL->Windows interop (``cmd.exe``) so
that the same binaries the user runs natively are used here.

Fastboot is reachable only from the boot-failure recovery branch.  A
successful Android boot terminates the workflow with the recovery branch
never entered.

Design constraints honoured by this module:

* No long sleeps, no long polling intervals, no unbounded blocking waits.
  Every wait is deadline-bounded and polls at a configurable interval that
  defaults to one second or less.
* Backups of ``boot``, ``vendor_boot`` and ``dtbo`` must be pulled to the
  host and verified before the installer is allowed to run.
* Recovery is bound to a specific device serial and a specific set of
  backup checksums via a recovery manifest.
* Destructive operations refuse to run when device identity, partition
  mapping, backup integrity or device mode is uncertain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import queue
import time
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

# --------------------------------------------------------------------------
# Tunables.  Every one of these is a short bound; nothing here may become an
# unbounded wait.
# --------------------------------------------------------------------------

DEFAULT_POLL_INTERVAL = 1.0
MAX_POLL_INTERVAL = 5.0
DEFAULT_BOOT_TIMEOUT = 240.0
DEFAULT_OP_TIMEOUT = 120.0
DEFAULT_PUSH_TIMEOUT = 900.0
DEFAULT_INSTALL_TIMEOUT = 1800.0
DEFAULT_BACKUP_TIMEOUT = 600.0

DEVICE_SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
WINDOWS_EXE_SUFFIX = ".exe"

# Partitions that must be preserved and restored verbatim.
REQUIRED_PARTITIONS = ("boot", "vendor_boot", "dtbo")

# Env vars consulted before falling back to filesystem discovery.
ADB_ENV_VARS = ("WINDOWS_ADB", "ADB_EXE", "ADB")
FASTBOOT_ENV_VARS = ("WINDOWS_FASTBOOT", "FASTBOOT_EXE", "FASTBOOT")

# Common WSL mount points where platform-tools usually live.
PLATFORM_TOOLS_CANDIDATES = (
    "/mnt/c/platform-tools",
    "/mnt/d/platform-tools",
    "/mnt/e/platform-tools",
    "/mnt/c/Users",
    "/mnt/d/Users",
)


class InstallError(RuntimeError):
    """Fatal, non-recoverable condition.  Stops the state machine."""


class State(Enum):
    """The explicit states of the installation workflow."""

    INITIALIZING = "INITIALIZING"
    RESOLVING_WINDOWS_TOOLS = "RESOLVING_WINDOWS_TOOLS"
    DOWNLOADING_AK3 = "DOWNLOADING_AK3"
    VALIDATING_AK3 = "VALIDATING_AK3"
    CHECKING_DEVICE = "CHECKING_DEVICE"
    CHECKING_ROOT = "CHECKING_ROOT"
    PUSHING_AK3 = "PUSHING_AK3"
    EXTRACTING_AK3 = "EXTRACTING_AK3"
    DISCOVERING_PARTITIONS = "DISCOVERING_PARTITIONS"
    BACKING_UP_PARTITIONS = "BACKING_UP_PARTITIONS"
    VERIFYING_BACKUPS = "VERIFYING_BACKUPS"
    INSTALLING_KERNEL = "INSTALLING_KERNEL"
    REBOOTING = "REBOOTING"
    MONITORING_BOOT = "MONITORING_BOOT"
    COLLECTING_BOOT_LOGS = "COLLECTING_BOOT_LOGS"
    SAVING_INSTALLED_IMAGES = "SAVING_INSTALLED_IMAGES"
    BOOT_SUCCESS = "BOOT_SUCCESS"
    BOOT_FAILURE_CONFIRMED = "BOOT_FAILURE_CONFIRMED"
    VERIFYING_RECOVERY_BACKUPS = "VERIFYING_RECOVERY_BACKUPS"
    FASTBOOT_RECOVERY = "FASTBOOT_RECOVERY"
    RESTORING_BOOT = "RESTORING_BOOT"
    RESTORING_VENDOR_BOOT = "RESTORING_VENDOR_BOOT"
    RESTORING_DTBO = "RESTORING_DTBO"
    REBOOTING_RESTORED_SYSTEM = "REBOOTING_RESTORED_SYSTEM"
    MONITORING_RESTORED_BOOT = "MONITORING_RESTORED_BOOT"
    COLLECTING_FAILURE_LOGS = "COLLECTING_FAILURE_LOGS"
    RECOVERY_SUCCESS = "RECOVERY_SUCCESS"
    RECOVERY_FAILED = "RECOVERY_FAILED"
    STATE_UNKNOWN = "STATE_UNKNOWN"
    MANUAL_INTERVENTION_REQUIRED = "MANUAL_INTERVENTION_REQUIRED"


#: States from which the fastboot recovery branch may be entered.  Fastboot
#: is unreachable from every other state.
RECOVERY_ENTRY_STATES = frozenset(
    {State.BOOT_FAILURE_CONFIRMED, State.VERIFYING_RECOVERY_BACKUPS}
)

#: States in which a fastboot command is allowed to be issued at all.
FASTBOOT_ALLOWED_STATES = frozenset(
    {
        State.FASTBOOT_RECOVERY,
        State.RESTORING_BOOT,
        State.RESTORING_VENDOR_BOOT,
        State.RESTORING_DTBO,
        State.REBOOTING_RESTORED_SYSTEM,
        State.MONITORING_RESTORED_BOOT,
    }
)


class BootOutcome(Enum):
    """Classification of the device while monitoring a boot."""

    ANDROID_READY = "ANDROID_READY"
    ANDROID_BOOTING = "ANDROID_BOOTING"
    DISCONNECTED = "DISCONNECTED"
    UNAUTHORIZED = "UNAUTHORIZED"
    OFFLINE = "OFFLINE"
    FASTBOOT = "FASTBOOT"
    UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------
# Command execution
# --------------------------------------------------------------------------


@dataclass
class CommandResult:
    """Outcome of a single host-side command."""

    argv: Sequence[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def summary(self) -> str:
        state = "ok" if self.ok else f"rc={self.returncode}"
        if self.timed_out:
            state = "timeout"
        return f"{state} ({self.duration:.2f}s): {' '.join(self.argv)}"


#: Characters that cmd.exe interprets inside a /c command string.  Each is
#: escaped with a caret so cmd passes it through to the child verbatim.
CMD_METACHARS = "|<>&^()"


def escape_cmd_arg(value: str) -> str:
    """Escape a value for inclusion in a ``cmd.exe`` command string.

    ``cmd.exe`` interprets ``| < > & ^ ( )`` and ``%`` inside the string
    given to ``/c``.  Each is escaped with a caret so that cmd hands it to
    the child process unchanged.

    Double quotes are rejected outright: with ``/s`` cmd passes them
    through verbatim, which corrupts the argument instead of delimiting
    it.  Arguments must therefore never contain a double quote, and any
    argument containing a space cannot be delimited by cmd at all.
    """
    if "\x00" in value or "\n" in value or "\r" in value:
        raise InstallError(f"refusing to pass control characters to cmd.exe: {value!r}")
    if '"' in value:
        raise InstallError(f"refusing to pass a double quote to cmd.exe: {value!r}")
    if "%" in value:
        # cmd expands %VAR% at parse time and a caret does not prevent it.
        raise InstallError(f"refusing to pass a value containing '%' to cmd.exe: {value!r}")
    out: list[str] = []
    for char in value:
        if char in CMD_METACHARS:
            out.append("^")
        out.append(char)
    return "".join(out)


def build_cmd_line(exe: str, args: Sequence[str]) -> str:
    """Build a ``cmd.exe`` command string for ``exe`` plus ``args``.

    cmd.exe receives a single string and has no way to know where one
    argument ends and the next begins, so an argument may not contain a
    space.  Multi-word device commands are therefore carried by a script
    file rather than by the command line.
    """
    parts = [escape_cmd_arg(exe)]
    for arg in args:
        if " " in arg:
            raise InstallError(
                f"argument contains a space and cannot be delimited by cmd.exe: {arg!r}"
            )
        parts.append(escape_cmd_arg(arg))
    return " ".join(parts)


def run_host_command(
    argv: Sequence[str],
    *,
    timeout: float = DEFAULT_OP_TIMEOUT,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
) -> CommandResult:
    """Run a host command, capturing stdout/stderr and the true exit status.

    The command is executed directly (not through a pipeline) so the exit
    status is never masked.
    """
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            encoding="utf-8",
            # Device output (logcat, kernel rings) can contain arbitrary
            # bytes; a strict decode would abort the whole workflow.
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=argv,
            returncode=124,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr),
            duration=time.monotonic() - started,
            timed_out=True,
        )
    return CommandResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        duration=time.monotonic() - started,
    )


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


# --------------------------------------------------------------------------
# Windows tool discovery and interop
# --------------------------------------------------------------------------


@dataclass
class WindowsTools:
    """Resolved Windows platform-tools executables."""

    adb: Path
    fastboot: Path
    cmd: str = "cmd.exe"

    def as_manifest(self) -> dict[str, str]:
        return {
            "adb": str(self.adb),
            "fastboot": str(self.fastboot),
            "cmd": self.cmd,
        }


class WindowsInterop:
    """Runs Windows executables from WSL through ``cmd.exe``."""

    def __init__(self, tools: WindowsTools, *, log: Optional["Journal"] = None):
        self.tools = tools
        self.log = log
        # cmd.exe cannot execute a WSL path, so the executables are resolved
        # to their Windows equivalents once and reused.
        self._adb_win = self.short_path(self.wsl_to_windows(tools.adb))
        self._fastboot_win = self.short_path(self.wsl_to_windows(tools.fastboot))

    # -- path conversion ---------------------------------------------------

    def wsl_to_windows(self, path: "os.PathLike[str] | str") -> str:
        """Convert a WSL path to a Windows path using ``wslpath -w``."""
        wslpath = shutil.which("wslpath")
        if wslpath:
            result = run_host_command([wslpath, "-w", str(path)], timeout=30)
            if result.ok:
                return result.stdout.strip()
        text = str(path)
        if text.startswith("/"):
            return "C:" + text.replace("/", "\\")
        return text

    # -- execution ---------------------------------------------------------

    def run(
        self,
        exe: "str | Path",
        args: Sequence[str],
        *,
        timeout: float = DEFAULT_OP_TIMEOUT,
    ) -> CommandResult:
        """Invoke a Windows executable through ``cmd.exe``.

        ``exe`` must already be a Windows path; a WSL path is meaningless to
        cmd.exe.
        """
        command = build_cmd_line(str(exe), args)
        argv = [self.tools.cmd, "/d", "/s", "/c", command]
        # cmd.exe warns about UNC working directories, which is what a WSL
        # path looks like to Windows.  Running it from a mounted Windows
        # directory keeps the invocation clean.
        result = run_host_command(argv, timeout=timeout, cwd=self._windows_cwd())
        if self.log is not None:
            self.log.command(result)
        return result

    def short_path(self, windows_path: str) -> str:
        """Return the 8.3 short form of a Windows path when it has spaces.

        cmd.exe cannot delimit an argument that contains a space, so an
        executable installed below e.g. ``C:\\Program Files`` is addressed
        through its short name instead.
        """
        if " " not in windows_path:
            return windows_path
        result = run_host_command(
            [
                self.tools.cmd,
                "/d",
                "/s",
                "/c",
                f'for %I in ("{windows_path}") do @echo %~sI',
            ],
            timeout=30,
            cwd=self._windows_cwd(),
        )
        candidate = result.stdout.strip()
        if result.ok and candidate and " " not in candidate:
            return candidate
        raise InstallError(
            f"cannot express Windows path without spaces: {windows_path!r}"
        )

    def stage_text(self, text: str, name: str, *, subdir: str = "ki") -> str:
        """Write a text file onto the Windows filesystem and return its path."""
        base = self._windows_cwd() or "/mnt/c"
        stage_dir = Path(base) / "kernel-install-staging" / subdir
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged = stage_dir / name
        staged.write_text(text, encoding="utf-8")
        return self.wsl_to_windows(staged)

    def stage_for_windows(self, source: Path, *, subdir: str = "ki") -> str:
        """Copy a file onto the Windows filesystem and return its Windows path.

        Windows tools cannot reliably read files through the WSL UNC
        share, so anything handed to adb or fastboot is staged on the
        Windows side first.  The canonical copy stays in the persistent
        work directory.
        """
        base = self._windows_cwd() or "/mnt/c"
        stage_dir = Path(base) / "kernel-install-staging" / subdir
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged = stage_dir / source.name
        if not staged.exists() or staged.stat().st_size != source.stat().st_size:
            shutil.copy2(source, staged)
        return self.wsl_to_windows(staged)

    @staticmethod
    def _windows_cwd() -> Optional[str]:
        for candidate in ("/mnt/c", "/mnt/d"):
            if os.path.isdir(candidate):
                return candidate
        return None

    def adb(self, args: Sequence[str], *, timeout: float = DEFAULT_OP_TIMEOUT) -> CommandResult:
        return self.run(self._adb_win, args, timeout=timeout)

    def fastboot(
        self, args: Sequence[str], *, timeout: float = DEFAULT_OP_TIMEOUT
    ) -> CommandResult:
        return self.run(self._fastboot_win, args, timeout=timeout)


CMD_ENV_VARS = ("WINDOWS_CMD", "CMD_EXE")
CMD_CANDIDATES = (
    "/mnt/c/Windows/System32/cmd.exe",
    "/mnt/c/Windows/SysWOW64/cmd.exe",
)


def _resolve_cmd() -> str:
    """Locate cmd.exe, which is not necessarily on the WSL PATH."""
    for var in CMD_ENV_VARS:
        value = os.environ.get(var)
        if value and Path(value).is_file():
            return value
    for candidate in CMD_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    found = shutil.which("cmd.exe")
    if found:
        return found
    raise InstallError(
        "cmd.exe not found; WSL-to-Windows interop is unavailable. "
        "Set WINDOWS_CMD to the cmd.exe path."
    )


def _candidate_exe(name: str) -> Iterable[Path]:
    for var in (ADB_ENV_VARS if name == "adb" else FASTBOOT_ENV_VARS):
        value = os.environ.get(var)
        if value:
            candidate = Path(value)
            if candidate.is_file():
                yield candidate
    for base in PLATFORM_TOOLS_CANDIDATES:
        candidate = Path(base) / f"{name}{WINDOWS_EXE_SUFFIX}"
        if candidate.is_file():
            yield candidate
    # Windows-side PATH lookup through cmd.exe.
    try:
        result = run_host_command(
            ["cmd.exe", "/d", "/s", "/c", f"where {name}"], timeout=30
        )
        if result.ok:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.lower().endswith(WINDOWS_EXE_SUFFIX):
                    yield Path("/mnt/c/" + line.replace("\\", "/").lstrip("/"))
    except OSError:
        pass


def resolve_windows_tools(log: "Journal") -> WindowsTools:
    """Locate and verify the Windows adb.exe and fastboot.exe executables.

    Never falls back to the Linux adb/fastboot: a Linux fastboot in this
    workflow would be a different implementation with different device
    handling, and silently using it would be a correctness hazard.
    """
    resolved: dict[str, Path] = {}
    for name in ("adb", "fastboot"):
        for candidate in _candidate_exe(name):
            if not candidate.is_file():
                continue
            # `--help` is the only subcommand guaranteed to return
            # immediately for both tools.  `fastboot version` is not a
            # subcommand in fastboot 1.0.41: it is parsed as a partition
            # name and blocks waiting for a device, so it must not be used
            # as a liveness probe.
            result = run_host_command([str(candidate), "--help"], timeout=30)
            if result.returncode == 0 and not result.timed_out:
                resolved[name] = candidate
                banner = ""
                for line in result.stdout.splitlines():
                    if line.strip():
                        banner = line.strip()
                        break
                log.info(f"resolved {name}.exe -> {candidate} ({banner})")
                break
        else:
            raise InstallError(
                f"could not resolve a working Windows {name}.exe. "
                "Set WINDOWS_ADB/WINDOWS_FASTBOOT to the executable path."
            )
    return WindowsTools(
        adb=resolved["adb"], fastboot=resolved["fastboot"], cmd=_resolve_cmd()
    )


# --------------------------------------------------------------------------
# Journal / artifact handling
# --------------------------------------------------------------------------


class Journal:
    """Records every step, command and state transition for the attempt."""

    def __init__(self, attempt_dir: Path):
        self.attempt_dir = attempt_dir
        self.attempt_dir.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []
        self._log_path = self.attempt_dir / "workflow.log"
        self._log_file = self._log_path.open("a", encoding="utf-8")

    def _write(self, kind: str, message: str, **extra) -> None:
        entry = {
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "kind": kind,
            "message": message,
        }
        entry.update(extra)
        self.entries.append(entry)
        line = f"[{entry['iso']}] {kind}: {message}"
        self._log_file.write(line + "\n")
        self._log_file.flush()
        if kind in ("error", "state", "warn"):
            print(line, file=sys.stderr, flush=True)
        else:
            print(line, flush=True)

    def info(self, message: str, **extra) -> None:
        self._write("info", message, **extra)

    def warn(self, message: str, **extra) -> None:
        self._write("warn", message, **extra)

    def error(self, message: str, **extra) -> None:
        self._write("error", message, **extra)

    def state(self, message: str, **extra) -> None:
        self._write("state", message, **extra)

    def command(self, result: CommandResult) -> None:
        self._write(
            "cmd",
            result.summary(),
            argv=list(result.argv),
            returncode=result.returncode,
            stdout=result.stdout[-4000:],
            stderr=result.stderr[-4000:],
            timed_out=result.timed_out,
        )

    def close(self) -> None:
        if not self._log_file.closed:
            self._log_file.close()

    def __del__(self) -> None:  # pragma: no cover - best effort cleanup
        try:
            self.close()
        except Exception:
            pass

    def dump_json(self) -> None:
        path = self.attempt_dir / "workflow.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            for entry in self.entries:
                handle.write(json.dumps(entry, default=str) + "\n")


# --------------------------------------------------------------------------
# AK3 acquisition
# --------------------------------------------------------------------------


@dataclass
class Ak3Source:
    """Where the AK3 ZIP lives on the build server.

    The project publishes the archive as
    ``~/KernelReleases/MeowKernel_<version>.zip`` where ``<version>`` comes
    from ``~/AnyKernel3/version.txt``.  The filename is therefore resolved
    from the server's own version file rather than guessed.
    """

    host: str = "meowing@141.148.219.139"
    remote_release_dir: str = "~/KernelReleases"
    remote_version_file: str = "~/AnyKernel3/version.txt"
    remote_zip_prefix: str = "MeowKernel"

    def remote_version(self) -> str:
        result = run_host_command(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", self.host,
             f"cat {self.remote_version_file}"],
            timeout=60,
        )
        if not result.ok:
            raise InstallError(
                f"could not read {self.remote_version_file} from {self.host}: "
                f"{result.stderr.strip()}"
            )
        version = result.stdout.strip()
        if not version:
            raise InstallError("remote version file is empty")
        return version

    def remote_zip_path(self, version: str) -> str:
        return f"{self.remote_release_dir}/{self.remote_zip_prefix}_{version}.zip"

    def pull(self, version: str, destination: Path, *, timeout: float) -> Path:
        """Pull the complete archive with rsync over ssh."""
        remote = f"{self.host}:{self.remote_zip_path(version)}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = run_host_command(
            [
                "rsync",
                "-aH",
                "--partial",
                "--info=progress2",
                "-e",
                "ssh -o BatchMode=yes -o ConnectTimeout=15",
                remote,
                str(destination),
            ],
            timeout=timeout,
        )
        if not result.ok:
            raise InstallError(
                f"rsync pull of {remote} failed (rc={result.returncode}): "
                f"{result.stderr.strip()[-500:]}"
            )
        return destination


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Ak3Archive:
    """A validated AnyKernel3 archive, kept intact on the host."""

    path: Path
    sha256: str
    size: int
    installer: str
    touched_partitions: list[str]
    contents: list[str]

    def as_manifest(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "filename": self.path.name,
            "sha256": self.sha256,
            "size": self.size,
            "installer": self.installer,
            "touched_partitions": self.touched_partitions,
        }


#: Partition tokens an AnyKernel3 script may write to.  Used to confirm the
#: archive only touches the partitions we back up.
_PARTITION_PATTERNS = (
    "boot",
    "vendor_boot",
    "init_boot",
    "vendor_kernel_boot",
    "dtbo",
    "dt",
    "recovery",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
)


def inspect_ak3_archive(path: Path, log: Journal) -> Ak3Archive:
    """Validate the archive and read the installer's partition intent.

    The archive is never unpacked on the host: the installer script is read
    in memory so that the individual kernel payloads are not extracted.
    """
    if not path.is_file():
        raise InstallError(f"AK3 archive not found: {path}")
    size = path.stat().st_size
    if size < 1024:
        raise InstallError(f"AK3 archive is implausibly small: {size} bytes")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise InstallError(f"AK3 archive is not a valid zip: {exc}") from exc
    with archive:
        bad = archive.testzip()
        if bad is not None:
            raise InstallError(f"AK3 archive failed CRC check at member {bad!r}")
        names = archive.namelist()
        installer = _find_installer(names)
        script_text = _read_text(archive, installer)
        touched = _partitions_touched(script_text)
    checksum = sha256_file(path)
    log.info(
        f"AK3 archive validated: {path.name} size={size} sha256={checksum[:16]}... "
        f"installer={installer} partitions={touched}"
    )
    return Ak3Archive(
        path=path,
        sha256=checksum,
        size=size,
        installer=installer,
        touched_partitions=touched,
        contents=names,
    )


def _find_installer(names: Sequence[str]) -> str:
    """Locate the AnyKernel3 installer script without assuming its name."""
    candidates = [n for n in names if n.endswith(".sh")]
    for preferred in ("anykernel.sh", "ak3-core.sh"):
        for name in candidates:
            if name.rsplit("/", 1)[-1] == preferred:
                return name
    for name in candidates:
        if "anykernel" in name.lower():
            return name
    if candidates:
        return candidates[0]
    raise InstallError("AK3 archive contains no installer script")


def _read_text(archive: zipfile.ZipFile, name: str) -> str:
    try:
        with archive.open(name) as handle:
            return handle.read().decode("utf-8", "replace")
    except KeyError as exc:
        raise InstallError(f"installer {name} missing from archive") from exc


def _partitions_touched(script_text: str) -> list[str]:
    """Best-effort list of partitions the installer may write to."""
    found: list[str] = []
    lowered = script_text.lower()
    for token in _PARTITION_PATTERNS:
        if re.search(rf"\b{re.escape(token)}\b", lowered):
            found.append(token)
    return sorted(set(found))


# --------------------------------------------------------------------------
# Device access
# --------------------------------------------------------------------------


@dataclass
class DeviceInfo:
    """Identity of the target device."""

    serial: str
    state: str
    model: str = ""
    device: str = ""
    fingerprint: str = ""
    android_release: str = ""
    sdk: str = ""
    slot: str = ""
    kernel: str = ""

    def as_manifest(self) -> dict[str, str]:
        return {
            "serial": self.serial,
            "state": self.state,
            "model": self.model,
            "device": self.device,
            "fingerprint": self.fingerprint,
            "android_release": self.android_release,
            "sdk": self.sdk,
            "slot": self.slot,
            "kernel": self.kernel,
        }


def parse_adb_devices(text: str) -> list[tuple[str, str, str]]:
    """Parse ``adb devices -l`` output into (serial, state, details)."""
    entries: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("*"):
            continue
        if line.lower().startswith("list of devices"):
            continue
        if line.lower().startswith("adb server"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        details = " ".join(parts[2:])
        entries.append((serial, state, details))
    return entries


#: A shell word that cmd.exe can carry through to the device untouched.
SAFE_SHELL_WORD = re.compile(r"^[A-Za-z0-9_./:=@,+%~^()-]+$")


class DeviceSession:
    """ADB operations against one specific device serial.

    Host-side, cmd.exe and Android-shell quoting rules all differ, and
    cmd.exe sits between the host and the device.  Two mechanisms are used:

    * :meth:`words` and :meth:`su` pass a list of simple shell words.  Each
      word becomes its own argument and contains no character that cmd.exe
      would reinterpret; adb rejoins them with spaces on the device.
    * :meth:`script` writes a shell script to the device and executes it.
      This carries arbitrary shell syntax (pipes, redirection, quoting)
      without any of it travelling through the cmd.exe command string.

    cmd.exe receives a single string and cannot know where one argument
    ends and the next begins, so an argument may never contain a space.
    """

    def __init__(self, interop: WindowsInterop, serial: str, log: Journal):
        self.interop = interop
        self.serial = serial
        self.log = log
        self._script_counter = 0

    def next_script_name(self, prefix: str) -> str:
        self._script_counter += 1
        return f"{prefix}_{os.getpid()}_{self._script_counter}.sh"

    def adb(self, args: Sequence[str], *, timeout: float = DEFAULT_OP_TIMEOUT) -> CommandResult:
        return self.interop.adb(["-s", self.serial, *args], timeout=timeout)

    def words(
        self, words: Sequence[str], *, timeout: float = DEFAULT_OP_TIMEOUT
    ) -> CommandResult:
        """Run simple shell words in the Android shell (no root)."""
        return self.adb(["shell", *self._check_words(words)], timeout=timeout)

    def su(
        self, words: Sequence[str], *, timeout: float = DEFAULT_OP_TIMEOUT
    ) -> CommandResult:
        """Run simple shell words with root privileges.

        ``su 0 <command> <args...>`` is used rather than ``su -c`` so the
        command and its arguments stay separate words and no quoting is
        required.
        """
        checked = self._check_words(words)
        return self.adb(["shell", "su", "0", *checked], timeout=timeout)

    def script(
        self,
        script: str,
        *,
        root: bool = True,
        timeout: float = DEFAULT_OP_TIMEOUT,
    ) -> CommandResult:
        """Execute a shell script on the device.

        The script text never passes through cmd.exe, so it may contain
        any shell syntax.  The script's exit status is propagated by adb.
        """
        name = self.next_script_name("ki_cmd")
        remote = f"/data/local/tmp/{name}"
        host_file = self.interop.stage_text(script, name)
        push = self.adb(["push", host_file, remote], timeout=120)
        if not push.ok:
            raise InstallError(
                f"could not stage device script: {push.stderr.strip()[-300:]}"
            )
        args = ["shell"]
        if root:
            args += ["su", "0"]
        args += ["sh", remote]
        try:
            return self.adb(args, timeout=timeout)
        finally:
            self.adb(["shell", "rm", "-f", remote], timeout=60)

    @staticmethod
    def _check_words(words: Sequence[str]) -> list[str]:
        checked: list[str] = []
        for word in words:
            if not SAFE_SHELL_WORD.match(word):
                raise InstallError(
                    f"shell word is not safe to pass through cmd.exe: {word!r}; "
                    "use script() instead"
                )
            checked.append(word)
        return checked

    def prop(self, name: str, *, timeout: float = 30) -> str:
        result = self.words(["getprop", name], timeout=timeout)
        return result.stdout.strip() if result.ok else ""

    def has_root(self) -> bool:
        result = self.su(["id"], timeout=60)
        return result.ok and "uid=0" in result.stdout


def select_device(
    interop: WindowsInterop, log: Journal, requested_serial: Optional[str]
) -> tuple[str, str]:
    """Return (serial, state) for the unambiguous target device."""
    result = interop.adb(["devices", "-l"], timeout=60)
    if not result.ok:
        raise InstallError(f"adb devices failed: {result.stderr.strip()[-300:]}")
    entries = parse_adb_devices(result.stdout)
    if not entries:
        raise InstallError("no ADB devices found")
    if requested_serial:
        for serial, state, _ in entries:
            if serial == requested_serial:
                return serial, state
        raise InstallError(
            f"requested serial {requested_serial} not present; "
            f"available: {[e[0] for e in entries]}"
        )
    if len(entries) > 1:
        raise InstallError(
            "multiple ADB devices connected; select one explicitly with --serial: "
            + ", ".join(f"{s} ({st})" for s, st, _ in entries)
        )
    serial, state, _ = entries[0]
    return serial, state


def read_device_info(session: DeviceSession) -> DeviceInfo:
    return DeviceInfo(
        serial=session.serial,
        state=session.adb(["get-state"], timeout=30).stdout.strip(),
        model=session.prop("ro.product.model"),
        device=session.prop("ro.product.device"),
        fingerprint=session.prop("ro.build.fingerprint"),
        android_release=session.prop("ro.build.version.release"),
        sdk=session.prop("ro.build.version.sdk"),
        slot=session.prop("ro.boot.slot_suffix"),
        kernel=session.prop("ro.boot.kernel.version") or session.prop("ro.kernel.version"),
    )


# --------------------------------------------------------------------------
# Partition discovery and backup
# --------------------------------------------------------------------------


@dataclass
class Partition:
    """One partition of the target device."""

    name: str
    path: str
    resolved: str
    size: int

    def as_manifest(self) -> dict[str, object]:
        return {
            "name": self.name,
            "path": self.path,
            "resolved": self.resolved,
            "size": self.size,
        }


def discover_partitions(
    session: DeviceSession, log: Journal, slot_suffix: str
) -> dict[str, Partition]:
    """Resolve boot/vendor_boot/dtbo for the active slot."""
    by_name = session.script("ls -l /dev/block/by-name/ 2>/dev/null", timeout=60)
    if not by_name.ok:
        raise InstallError("cannot list /dev/block/by-name; root shell unavailable")
    entries: dict[str, str] = {}
    for line in by_name.stdout.splitlines():
        if " -> " not in line:
            continue
        left, _, right = line.rpartition(" -> ")
        name = left.split()[-1] if left.split() else ""
        target = right.strip()
        if name and target:
            entries[name] = target

    partitions: dict[str, Partition] = {}
    for base in REQUIRED_PARTITIONS:
        candidates = [f"{base}{slot_suffix}", base]
        chosen = None
        for candidate in candidates:
            if candidate in entries:
                chosen = candidate
                break
        if chosen is None:
            raise InstallError(
                f"partition {base} (slot {slot_suffix or '?'}) not found in "
                f"/dev/block/by-name"
            )
        resolved = entries[chosen]
        size_result = session.script(
            f"blockdev --getsize64 {resolved} 2>/dev/null || "
            f"cat /sys/class/block/{Path(resolved).name}/size",
            timeout=60,
        )
        size = 0
        for line in size_result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                candidate_size = int(line)
                # blockdev reports bytes, sysfs reports 512-byte sectors.
                size = candidate_size if candidate_size > 4096 else candidate_size * 512
                break
        if size <= 0:
            raise InstallError(f"could not determine size of {chosen} ({resolved})")
        partitions[base] = Partition(
            name=base, path=f"/dev/block/by-name/{chosen}", resolved=resolved, size=size
        )
        log.info(
            f"partition {base}: {partitions[base].path} -> {resolved} size={size}"
        )
    return partitions


# --------------------------------------------------------------------------
# The workflow
# --------------------------------------------------------------------------


@dataclass
class Config:
    """Everything the workflow needs to know up front."""

    ak3_source: Ak3Source
    work_dir: Path
    state_dir: Path
    serial: Optional[str] = None
    poll_interval: float = DEFAULT_POLL_INTERVAL
    boot_timeout: float = DEFAULT_BOOT_TIMEOUT
    op_timeout: float = DEFAULT_OP_TIMEOUT
    push_timeout: float = DEFAULT_PUSH_TIMEOUT
    install_timeout: float = DEFAULT_INSTALL_TIMEOUT
    backup_timeout: float = DEFAULT_BACKUP_TIMEOUT
    download_timeout: float = 1800.0
    dry_run: bool = False
    force_recovery_on_timeout: bool = False
    recover_only: bool = False
    restore_installed: bool = False
    keep_going: bool = True

    def __post_init__(self) -> None:
        if self.poll_interval <= 0 or self.poll_interval > MAX_POLL_INTERVAL:
            raise InstallError(
                f"poll interval must be in (0, {MAX_POLL_INTERVAL}] seconds"
            )
        self.work_dir = Path(self.work_dir)
        self.state_dir = Path(self.state_dir)


class KernelInstaller:
    """The installation state machine."""

    def __init__(self, config: Config, log: Journal):
        self.config = config
        self.log = log
        self.state = State.INITIALIZING
        self.tools: Optional[WindowsTools] = None
        self.interop: Optional[WindowsInterop] = None
        self.session: Optional[DeviceSession] = None
        self.device: Optional[DeviceInfo] = None
        self.partitions: dict[str, Partition] = {}
        self.archive: Optional[Ak3Archive] = None
        self.attempt_id = time.strftime("%Y%m%d-%H%M%S")
        # Artifacts and the journal must share one directory so that the
        # manifest, the installer log and the diagnostics stay together.
        self.attempt_dir = log.attempt_dir
        self.manifest: dict[str, object] = {}
        self.backup_paths: dict[str, Path] = {}
        self.remote_zip_name = ""
        self.remote_zip_version = ""
        self.boot_outcome: Optional[BootOutcome] = None
        self.archive_path: Optional[Path] = None
        self.busybox: Optional[str] = None
        self.device_installer: Optional[str] = None
        self.backup_verification: dict[str, dict[str, object]] = {}
        self.installed_backups: dict[str, dict[str, object]] = {}

    # -- state machine -----------------------------------------------------

    def transition(self, state: State, reason: str = "") -> None:
        previous = self.state
        self.state = state
        self.log.state(f"{previous.value} -> {state.value}" + (f" ({reason})" if reason else ""))

    def _require_recovery_entry(self) -> None:
        if self.state not in RECOVERY_ENTRY_STATES:
            raise InstallError(
                f"refusing to enter fastboot recovery from state {self.state.value}"
            )

    # -- top level ---------------------------------------------------------

    def run(self) -> State:
        try:
            self._resolve_tools()
            if self.config.recover_only:
                return self._recover_only()
            self._download()
            self._validate_archive()
            self._check_device()
            self._check_root()
            self._push()
            self._extract()
            self._discover()
            self._backup()
            self._verify_backups()
            self._install()
            self._reboot()
            self._monitor_boot()
            if self.boot_outcome is BootOutcome.ANDROID_READY:
                self._collect_logs("boot")
                self._save_installed_images()
                self.transition(State.BOOT_SUCCESS, "android booted with new kernel")
                return self.state
            if self.state is State.BOOT_FAILURE_CONFIRMED:
                return self._recover()
            self.transition(State.STATE_UNKNOWN, "boot state could not be classified")
            return self.state
        except InstallError as exc:
            self.log.error(f"fatal: {exc}")
            self.transition(State.MANUAL_INTERVENTION_REQUIRED, str(exc))
            self._write_manifest()
            return self.state
        finally:
            self.log.dump_json()
            self._write_manifest()
            self.log.close()

    def _recover_only(self) -> State:
        """Operator-initiated recovery.

        The device is placed in fastboot and the verified original images
        are restored.  Every gate that guards the automatic recovery branch
        applies unchanged: the manifest must match the connected device,
        all three backups must exist and pass their checksums, and the
        device must be reachable in fastboot.
        """
        self._check_device()
        self._check_root()
        self._discover()
        self._load_manifest()
        self._load_backups()
        if self.config.restore_installed:
            if not self.installed_backups:
                raise InstallError(
                    "the manifest has no installed image set to restore"
                )
            self.backup_paths = {
                base: Path(str(info["file"]))
                for base, info in self.installed_backups.items()
            }
            self.log.info("restoring the installed (known-good) image set")
        assert self.session is not None
        self.log.info("placing device in fastboot for recovery")
        self.session.adb(["reboot", "bootloader"], timeout=60)
        deadline = time.monotonic() + self.config.boot_timeout
        while time.monotonic() < deadline:
            if self._probe_device_state() is BootOutcome.FASTBOOT:
                break
            time.sleep(self.config.poll_interval)
        else:
            self.transition(
                State.MANUAL_INTERVENTION_REQUIRED, "device did not reach fastboot"
            )
            return self.state
        self.transition(State.BOOT_FAILURE_CONFIRMED, "operator-initiated recovery")
        return self._recover()

    def _load_manifest(self) -> None:
        """Load the newest recovery manifest from a previous attempt."""
        candidates = sorted(self.config.state_dir.glob("*/recovery-manifest.json"))
        if not candidates:
            raise InstallError("no recovery manifest found in the state directory")
        manifest_path = candidates[-1]
        self.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.log.info(f"loaded recovery manifest {manifest_path}")

    def _load_backups(self) -> None:
        """Locate the backup images referenced by the manifest."""
        backups = self.manifest.get("backups") or {}
        if not backups:
            raise InstallError("recovery manifest does not reference any backups")
        for base, info in backups.items():
            path = Path(str(info.get("file", "")))
            if not path.is_file():
                raise InstallError(f"backup image for {base} is missing: {path}")
            self.backup_paths[base] = path
        self.backup_verification = backups

        installed = self.manifest.get("installed_backups") or {}
        for base, info in installed.items():
            path = Path(str(info.get("file", "")))
            if path.is_file():
                self.installed_backups[base] = info
        self.log.info(
            "loaded backups: " + ", ".join(sorted(self.backup_paths))
        )
        if self.installed_backups:
            self.log.info(
                "installed image set available: " + ", ".join(sorted(self.installed_backups))
            )

    # -- states ------------------------------------------------------------

    def _resolve_tools(self) -> None:
        self.transition(State.RESOLVING_WINDOWS_TOOLS)
        self.tools = resolve_windows_tools(self.log)
        self.interop = WindowsInterop(self.tools, log=self.log)

    def _download(self) -> None:
        self.transition(State.DOWNLOADING_AK3)
        version = self.config.ak3_source.remote_version()
        self.remote_zip_version = version
        self.remote_zip_name = f"{self.config.ak3_source.remote_zip_prefix}_{version}.zip"
        destination = self.config.work_dir / self.remote_zip_name
        self.log.info(f"pulling {self.remote_zip_name} from {self.config.ak3_source.host}")
        self.config.ak3_source.pull(
            version, destination, timeout=self.config.download_timeout
        )
        self.archive_path = destination
        self.log.info(f"pulled {destination} ({destination.stat().st_size} bytes)")

    def _validate_archive(self) -> None:
        self.transition(State.VALIDATING_AK3)
        if self.archive_path is None:
            raise InstallError("AK3 archive path was not set")
        self.archive = inspect_ak3_archive(self.archive_path, self.log)
        unexpected = [
            p
            for p in self.archive.touched_partitions
            if p not in REQUIRED_PARTITIONS and p not in ("dt", "recovery")
        ]
        if unexpected:
            self.log.warn(
                "installer references partitions outside the backed-up set: "
                + ", ".join(unexpected)
            )

    def _check_device(self) -> None:
        self.transition(State.CHECKING_DEVICE)
        assert self.interop is not None
        serial, state = select_device(self.interop, self.log, self.config.serial)
        if state != "device":
            raise InstallError(f"device {serial} is in state '{state}', expected 'device'")
        self.session = DeviceSession(self.interop, serial, self.log)
        self.device = read_device_info(self.session)
        self.log.info(f"device: {json.dumps(self.device.as_manifest())}")
        if not DEVICE_SERIAL_RE.match(self.device.serial):
            raise InstallError(f"implausible device serial: {self.device.serial!r}")

    def _check_root(self) -> None:
        self.transition(State.CHECKING_ROOT)
        assert self.session is not None
        if not self.session.has_root():
            raise InstallError(
                "root access unavailable via 'su'; cannot back up partitions or "
                "run the installer"
            )
        busybox = self._detect_busybox()
        self.log.info(f"root OK; busybox={busybox or 'none (will use toybox)'}")
        self.busybox = busybox
        free = self.session.script("df -k /data/local/tmp | tail -1", timeout=60)
        self.log.info(f"/data/local/tmp space: {free.stdout.strip()}")
        if not free.ok:
            raise InstallError("cannot determine free space on /data/local/tmp")

    def _detect_busybox(self) -> Optional[str]:
        assert self.session is not None
        for candidate in (
            "/data/adb/ksu/bin/busybox",
            "/data/adb/magisk/busybox",
            "/data/adb/modules/busybox/busybox",
            "/sbin/busybox",
            "/system/bin/busybox",
        ):
            result = self.session.script(f"[ -x {candidate} ] && echo yes", timeout=30)
            if result.ok and "yes" in result.stdout:
                return candidate
        return None

    def _push(self) -> None:
        self.transition(State.PUSHING_AK3)
        assert self.session is not None and self.archive is not None
        assert self.interop is not None
        remote = "/data/local/tmp/AnyKernel3.zip"
        source_windows = self.interop.stage_for_windows(
            self.archive.path, subdir=self.attempt_id
        )
        self.log.info(f"pushing {source_windows} -> {remote}")
        result = self.session.adb(
            ["push", source_windows, remote], timeout=self.config.push_timeout
        )
        if not result.ok:
            raise InstallError(f"adb push failed: {result.stderr.strip()[-400:]}")
        stat = self.session.script(f"stat -c %s {remote} 2>/dev/null", timeout=60)
        remote_size = int(stat.stdout.strip()) if stat.stdout.strip().isdigit() else -1
        if remote_size != self.archive.size:
            raise InstallError(
                f"transferred size mismatch: host={self.archive.size} device={remote_size}"
            )
        remote_sum = self.session.script(
            f"sha256sum {remote} 2>/dev/null | cut -d' ' -f1", timeout=300
        )
        device_sha = remote_sum.stdout.strip().split()[0] if remote_sum.stdout.strip() else ""
        if device_sha and device_sha != self.archive.sha256:
            raise InstallError(
                f"checksum mismatch: host={self.archive.sha256} device={device_sha}"
            )
        self.log.info(f"push verified: size={remote_size} sha256 match={bool(device_sha)}")

    def _extract(self) -> None:
        self.transition(State.EXTRACTING_AK3)
        assert self.session is not None
        work = "/data/local/tmp/anykernel"
        self.session.script(f"rm -rf {work} && mkdir -p {work}", timeout=60)
        extractor = self._detect_extractor()
        if extractor is None:
            raise InstallError("no unzip utility available on the device")
        result = self.session.script(
            f"cd {work} && {extractor} -o /data/local/tmp/AnyKernel3.zip", timeout=600
        )
        if not result.ok:
            raise InstallError(f"on-device extraction failed: {result.stderr.strip()[-400:]}")
        listing = self.session.script(f"ls -1 {work}", timeout=60)
        members = [line for line in listing.stdout.splitlines() if line.strip()]
        if not members:
            raise InstallError("extraction produced no files")
        self.device_installer = self._find_device_installer(work, members)
        self.log.info(f"extracted {len(members)} entries; installer={self.device_installer}")

    def _detect_extractor(self) -> Optional[str]:
        """Find an unzip implementation on the device."""
        assert self.session is not None
        plain = self.session.script("command -v unzip", timeout=30)
        if plain.ok and plain.stdout.strip():
            return "unzip"
        if self.busybox:
            probe = self.session.script(
                f"{self.busybox} unzip --help 2>&1 | head -1", timeout=30
            )
            if probe.ok and probe.stdout.strip():
                return f"{self.busybox} unzip"
        toybox = self.session.script("command -v toybox", timeout=30)
        if toybox.ok and toybox.stdout.strip():
            probe = self.session.script(
                "toybox unzip --help 2>&1 | head -1", timeout=30
            )
            if probe.ok and probe.stdout.strip():
                return "toybox unzip"
        return None

    def _find_device_installer(self, work: str, members: Sequence[str]) -> str:
        preferred = ("anykernel.sh",)
        for name in members:
            base = name.rsplit("/", 1)[-1]
            if base in preferred:
                return f"{work}/{name}"
        for name in members:
            if "anykernel" in name.lower() and name.endswith(".sh"):
                return f"{work}/{name}"
        for name in members:
            if name.endswith(".sh"):
                return f"{work}/{name}"
        raise InstallError("no installer script found in the extracted archive")

    def _discover(self) -> None:
        self.transition(State.DISCOVERING_PARTITIONS)
        assert self.session is not None and self.device is not None
        slot = self.device.slot or "_a"
        self.partitions = discover_partitions(self.session, self.log, slot)
        self.log.info(
            "partition map: "
            + json.dumps({k: v.as_manifest() for k, v in self.partitions.items()})
        )

    def _backup(self) -> None:
        self.transition(State.BACKING_UP_PARTITIONS)
        assert self.session is not None
        backup_dir = self.config.work_dir / f"backup-{self.attempt_id}"
        backup_dir.mkdir(parents=True, exist_ok=True)
        device_dir = "/data/local/tmp/ak3-backup"
        self.session.script(f"rm -rf {device_dir} && mkdir -p {device_dir}", timeout=60)
        for base in REQUIRED_PARTITIONS:
            partition = self.partitions[base]
            device_file = f"{device_dir}/{base}.original.img"
            result = self.session.script(
                f"dd if={partition.path} of={device_file} bs=4096 2>/dev/null",
                timeout=self.config.backup_timeout,
            )
            if not result.ok:
                raise InstallError(f"failed to read {base} from {partition.path}")
            stat = self.session.script(f"stat -c %s {device_file}", timeout=60)
            size = int(stat.stdout.strip()) if stat.stdout.strip().isdigit() else -1
            if size != partition.size:
                raise InstallError(
                    f"backup of {base} has size {size}, partition size is {partition.size}"
                )
            host_file = backup_dir / f"{base}.original.img"
            self._pull_to_host(device_file, host_file)
            self.backup_paths[base] = host_file
            self.log.info(f"backed up {base}: {host_file} ({partition.size} bytes)")

    def _pull_to_host(self, remote: str, host_file: Path) -> None:
        """Pull a device file into the persistent host directory.

        The Windows adb client cannot write into a WSL path, so the file is
        first pulled to the Windows staging directory and then copied into
        the persistent work directory.
        """
        assert self.interop is not None
        assert self.session is not None
        base = self.interop._windows_cwd() or "/mnt/c"
        staged_dir = Path(base) / "kernel-install-staging" / self.attempt_id
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged = staged_dir / host_file.name
        pull = self.session.adb(
            ["pull", remote, self.interop.wsl_to_windows(staged)], timeout=600
        )
        if not pull.ok:
            raise InstallError(
                f"adb pull of {remote} failed: {pull.stderr.strip()[-300:]}"
            )
        if not staged.is_file():
            raise InstallError(f"pulled file {remote} did not appear on the host")
        host_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged, host_file)
        expected = self.partitions[host_file.name.split(".")[0]].size
        if host_file.stat().st_size != expected:
            raise InstallError(
                f"host copy of {host_file.name} is {host_file.stat().st_size} bytes, "
                f"expected {expected}"
            )
        self.log.info(
            f"pulled {remote} -> {host_file} ({host_file.stat().st_size} bytes)"
        )

    def _verify_backups(self) -> None:
        self.transition(State.VERIFYING_BACKUPS)
        assert self.session is not None
        device_dir = "/data/local/tmp/ak3-backup"
        results = {}
        for base in REQUIRED_PARTITIONS:
            host_file = self.backup_paths.get(base)
            if host_file is None or not host_file.is_file():
                raise InstallError(f"host backup for {base} is missing")
            host_size = host_file.stat().st_size
            partition_size = self.partitions[base].size
            if host_size != partition_size:
                raise InstallError(
                    f"host backup for {base} is {host_size} bytes, expected {partition_size}"
                )
            host_sum = sha256_file(host_file)
            remote = self.session.script(
                f"sha256sum {device_dir}/{base}.original.img 2>/dev/null | cut -d' ' -f1",
                timeout=300,
            )
            device_sum = remote.stdout.strip().split()[0] if remote.stdout.strip() else ""
            if device_sum and device_sum != host_sum:
                raise InstallError(
                    f"backup checksum mismatch for {base}: host={host_sum} device={device_sum}"
                )
            results[base] = {
                "file": str(host_file),
                "size": host_size,
                "sha256": host_sum,
                "device_sha256": device_sum,
                "device_sha256_matched": bool(device_sum) and device_sum == host_sum,
            }
            self.log.info(f"verified {base} backup sha256={host_sum[:16]}...")
        self.backup_verification = results
        self._write_manifest()

    def _install(self) -> None:
        self.transition(State.INSTALLING_KERNEL)
        assert self.session is not None
        installer = self.device_installer
        if not installer:
            raise InstallError("installer script path was not determined")
        self.session.script(f"chmod +x {installer}", timeout=60)
        work_dir = installer.rsplit("/", 1)[0]
        # AnyKernel3 relies on busybox applets and a POSIX shell.  On Android
        # the stock shell is toybox's mksh, so the KernelSU busybox is
        # preferred when present.
        shell = "sh"
        if self.busybox:
            probe = self.session.script(
                f"{self.busybox} sh -c 'echo ok' 2>/dev/null", timeout=30
            )
            if probe.ok and "ok" in probe.stdout:
                shell = f"{self.busybox} sh"
        path_parts = [f"{work_dir}/tools"]
        if self.busybox:
            path_parts.append(str(Path(self.busybox).parent))
        path_parts.append("/system/bin")
        path_value = ":".join(path_parts)
        command = f"cd {work_dir} && PATH={path_value} {shell} {installer}"
        self.log.info(f"running installer: {command}")
        returncode, output = self._run_streaming(command, self.config.install_timeout)
        log_path = self.attempt_dir / "installer-stdout.log"
        log_path.write_text(output, encoding="utf-8")
        (self.attempt_dir / "installer-exitcode.txt").write_text(
            f"{returncode}\n", encoding="utf-8"
        )
        self.log.info(f"installer exit={returncode} (log: {log_path})")
        if returncode != 0:
            raise InstallError(
                f"AnyKernel3 installer failed with exit code {returncode}; "
                f"see {log_path}"
            )

    def _run_streaming(self, command: str, timeout: float) -> tuple[int, str]:
        """Run a device command, streaming its output while it runs.

        The installer can take many minutes.  Running it synchronously would
        block the whole orchestration, so it is started as a background
        process whose output is drained by a reader thread while the main
        loop polls the process state on a short interval.

        The device command is carried by a script file so that none of its
        shell syntax passes through the cmd.exe command string.
        """
        assert self.interop is not None
        assert self.session is not None
        name = self.session.next_script_name("ki_install")
        remote = f"/data/local/tmp/{name}"
        host_file = self.interop.stage_text(command, name, subdir=self.attempt_id)
        push = self.session.adb(["push", host_file, remote], timeout=120)
        if not push.ok:
            raise InstallError(
                f"could not stage installer script: {push.stderr.strip()[-300:]}"
            )
        argv = [
            self.interop.tools.cmd,
            "/d",
            "/s",
            "/c",
            build_cmd_line(
                self.interop._adb_win,
                ["-s", self.session.serial, "shell", "su", "0", "sh", remote],
            ),
        ]
        log_path = self.attempt_dir / "installer-stream.log"
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            cwd=self.interop._windows_cwd(),
        )
        lines: "queue.Queue[str | None]" = queue.Queue()
        collected: list[str] = []

        def reader() -> None:
            assert process.stdout is not None
            for line in process.stdout:
                lines.put(line)
            lines.put(None)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()

        deadline = time.monotonic() + timeout
        with log_path.open("w", encoding="utf-8") as handle:
            while True:
                try:
                    line = lines.get(timeout=self.config.poll_interval)
                except queue.Empty:
                    line = ""
                if line:
                    collected.append(line)
                    handle.write(line)
                    handle.flush()
                    if line.strip().startswith("[#]"):
                        self.log.info(f"installer: {line.strip()}")
                elif line is None:
                    break
                if process.poll() is not None and lines.empty():
                    break
                if time.monotonic() > deadline:
                    self._terminate(process)
                    raise InstallError(
                        f"installer exceeded its {timeout:.0f}s deadline and was terminated"
                    )
        returncode = process.wait(timeout=30)
        self.session.adb(["shell", "rm", "-f", remote], timeout=60)
        return returncode, "".join(collected)

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        """Terminate a timed-out subprocess cleanly."""
        try:
            process.terminate()
            process.wait(timeout=10)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    def _reboot(self) -> None:
        self.transition(State.REBOOTING)
        assert self.session is not None
        result = self.session.adb(["reboot"], timeout=60)
        if not result.ok:
            raise InstallError(f"adb reboot failed: {result.stderr.strip()[-200:]}")
        self.log.info("reboot requested")

    def _monitor_boot(self) -> None:
        self.transition(State.MONITORING_BOOT)
        outcome = self._monitor_until(
            deadline=time.monotonic() + self.config.boot_timeout,
            label="boot",
        )
        self.boot_outcome = outcome
        if outcome is BootOutcome.ANDROID_READY:
            self.log.info("android is up")
            return
        if outcome is BootOutcome.FASTBOOT:
            self.log.warn("device is in fastboot/bootloader mode")
            self.transition(State.BOOT_FAILURE_CONFIRMED, "device reported fastboot")
            return
        if outcome is BootOutcome.UNKNOWN:
            if self.config.force_recovery_on_timeout:
                self.log.warn("forcing recovery on timeout per operator request")
                self.transition(
                    State.BOOT_FAILURE_CONFIRMED, "operator-forced recovery after timeout"
                )
                return
            self.transition(
                State.STATE_UNKNOWN, "device state could not be classified within deadline"
            )
            return
        self.transition(
            State.BOOT_FAILURE_CONFIRMED, f"boot monitoring ended in {outcome.value}"
        )

    def _monitor_until(self, deadline: float, label: str) -> BootOutcome:
        """Poll the device state on a short interval until a decision is reached.

        A temporary ADB disconnection is never treated as a boot failure:
        only an explicit fastboot enumeration (or an operator-forced
        timeout) escalates to recovery.
        """
        assert self.interop is not None
        saw_disconnect = False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return BootOutcome.UNKNOWN
            outcome = self._probe_device_state()
            if outcome is BootOutcome.ANDROID_READY:
                if self._boot_completed():
                    return BootOutcome.ANDROID_READY
                return BootOutcome.ANDROID_BOOTING
            if outcome is BootOutcome.FASTBOOT:
                return BootOutcome.FASTBOOT
            if outcome is BootOutcome.DISCONNECTED:
                saw_disconnect = True
            self.log.info(f"[{label}] device state: {outcome.value}")
            time.sleep(min(self.config.poll_interval, max(remaining, 0.0)))

    def _probe_device_state(self) -> BootOutcome:
        assert self.interop is not None
        adb_result = self.interop.adb(["devices"], timeout=30)
        entries = parse_adb_devices(adb_result.stdout) if adb_result.ok else []
        for serial, state, _ in entries:
            if self.config.serial and serial != self.config.serial:
                continue
            if state == "device":
                return BootOutcome.ANDROID_READY
            if state == "unauthorized":
                return BootOutcome.UNAUTHORIZED
            if state == "offline":
                return BootOutcome.OFFLINE
        # Read-only enumeration only.  Distinguishing "the device is in
        # fastboot" from "the device is merely disconnected" requires it,
        # and it is the only fastboot call the ordinary path ever makes.
        # No fastboot command that writes to the device is reachable
        # outside the gated recovery branch.
        fb_result = self.interop.fastboot(["devices"], timeout=30)
        if fb_result.ok:
            for line in fb_result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "fastboot":
                    if not self.config.serial or parts[0] == self.config.serial:
                        return BootOutcome.FASTBOOT
        if entries:
            return BootOutcome.ANDROID_BOOTING
        return BootOutcome.DISCONNECTED

    def _boot_completed(self) -> bool:
        assert self.session is not None
        value = self.session.prop("sys.boot_completed", timeout=30)
        return value.strip() == "1"

    def _save_installed_images(self) -> None:
        """Capture the partitions as they are now that the new kernel booted.

        These are the known-good images: the device booted this kernel and
        reported it as running.  Keeping them means a later recovery can
        restore the working kernel instead of falling back to the older
        pre-install build.
        """
        self.transition(State.SAVING_INSTALLED_IMAGES)
        assert self.session is not None
        target_dir = self.attempt_dir / "installed"
        target_dir.mkdir(parents=True, exist_ok=True)
        device_dir = "/data/local/tmp/ak3-installed"
        self.session.script(f"rm -rf {device_dir} && mkdir -p {device_dir}", timeout=60)
        for base in REQUIRED_PARTITIONS:
            partition = self.partitions[base]
            device_file = f"{device_dir}/{base}.installed.img"
            result = self.session.script(
                f"dd if={partition.path} of={device_file} bs=4096 2>/dev/null",
                timeout=self.config.backup_timeout,
            )
            if not result.ok:
                raise InstallError(f"could not read the installed {base} partition")
            host_file = target_dir / f"{base}.installed.img"
            self._pull_to_host(device_file, host_file)
            digest = sha256_file(host_file)
            self.installed_backups[base] = {
                "file": str(host_file),
                "size": host_file.stat().st_size,
                "sha256": digest,
                "partition": partition.path,
                "slot": self.device.slot if self.device else "",
            }
            self.log.info(
                f"captured installed {base}: {host_file} "
                f"({host_file.stat().st_size} bytes, sha256={digest[:16]}...)"
            )
        self._write_manifest()

    # -- diagnostics --------------------------------------------------------

    def _collect_logs(self, phase: str) -> None:
        self.transition(
            State.COLLECTING_BOOT_LOGS if phase == "boot" else State.COLLECTING_FAILURE_LOGS
        )
        assert self.session is not None
        target = self.attempt_dir / f"logs-{phase}"
        target.mkdir(parents=True, exist_ok=True)

        logcat = self.session.adb(["logcat", "-b", "all", "-d"], timeout=180)
        (target / "logcat-all.txt").write_text(
            logcat.stdout + ("\n--- STDERR ---\n" + logcat.stderr), encoding="utf-8"
        )
        (target / "logcat-all.exitcode.txt").write_text(f"{logcat.returncode}\n", encoding="utf-8")
        kernel_logcat = self.session.adb(["logcat", "-b", "kernel", "-d"], timeout=120)
        (target / "logcat-kernel.txt").write_text(
            kernel_logcat.stdout + ("\n--- STDERR ---\n" + kernel_logcat.stderr),
            encoding="utf-8",
        )

        dmesg = self.session.script("dmesg 2>&1", timeout=120)
        (target / "dmesg.txt").write_text(
            dmesg.stdout + ("\n--- STDERR ---\n" + dmesg.stderr), encoding="utf-8"
        )
        (target / "dmesg.exitcode.txt").write_text(f"{dmesg.returncode}\n", encoding="utf-8")

        pstore = self.session.script(
            "ls -l /sys/fs/pstore/ 2>&1; echo '---'; "
            "for f in /sys/fs/pstore/*; do [ -f \"$f\" ] && { echo \"=== $f ===\"; "
            "cat \"$f\" 2>&1; }; done",
            timeout=120,
        )
        (target / "pstore-ramoops.txt").write_text(pstore.stdout, encoding="utf-8")

        props = self.session.script(
            "getprop 2>&1 | grep -Ei 'boot|reason|panic|watchdog' ; "
            "echo '--- cmdline ---'; cat /proc/cmdline 2>&1; "
            "echo '--- uname ---'; uname -a 2>&1",
            timeout=120,
        )
        (target / "boot-props.txt").write_text(props.stdout, encoding="utf-8")

        dropbox = self.session.script(
            "dumpsys dropbox --print 2>&1 | head -c 400000", timeout=240
        )
        (target / "dropbox.txt").write_text(
            dropbox.stdout + ("\n--- STDERR ---\n" + dropbox.stderr), encoding="utf-8"
        )
        (target / "dropbox.exitcode.txt").write_text(f"{dropbox.returncode}\n", encoding="utf-8")

        tombstones = self.session.script(
            "ls -lt /data/tombstones/ 2>&1 | head -40", timeout=120
        )
        (target / "tombstones-listing.txt").write_text(tombstones.stdout, encoding="utf-8")

        self.log.info(f"diagnostics written to {target}")

    # -- recovery -----------------------------------------------------------

    def _verify_recovery_gates(self) -> None:
        """Check every precondition before a single byte is written.

        The manifest must belong to the connected device, and every image
        that is about to be flashed must exist on the host and still match
        the checksum recorded for it.
        """
        if self.device is None or self.manifest.get("device", {}).get("serial") != self.device.serial:
            raise InstallError("recovery manifest does not match the connected device")
        source = (
            self.installed_backups if self.config.restore_installed else self.backup_verification
        )
        label = "installed" if self.config.restore_installed else "pre-install"
        for base in REQUIRED_PARTITIONS:
            path = self.backup_paths.get(base)
            if path is None or not path.is_file():
                raise InstallError(f"recovery backup for {base} is missing on the host")
            expected = source.get(base, {}).get("sha256")
            actual = sha256_file(path)
            if expected and actual != expected:
                raise InstallError(
                    f"recovery backup for {base} failed checksum verification "
                    f"({label} set)"
                )
        self.log.info(f"verified {label} image set for recovery")

    def _recover(self) -> State:
        self._require_recovery_entry()
        self.transition(State.VERIFYING_RECOVERY_BACKUPS)
        self._verify_recovery_gates()
        self.transition(State.FASTBOOT_RECOVERY, "prerequisites verified")

        assert self.interop is not None
        probe = self.interop.fastboot(["devices"], timeout=60)
        fastboot_devices = [
            line.split()[0]
            for line in probe.stdout.splitlines()
            if len(line.split()) >= 2 and line.split()[1] == "fastboot"
        ]
        if not fastboot_devices:
            self.transition(
                State.MANUAL_INTERVENTION_REQUIRED, "device is not reachable in fastboot"
            )
            return self.state
        if len(fastboot_devices) > 1 and not self.config.serial:
            self.transition(
                State.MANUAL_INTERVENTION_REQUIRED, "multiple fastboot devices present"
            )
            return self.state
        target = self.config.serial or fastboot_devices[0]
        if target not in fastboot_devices:
            self.transition(
                State.MANUAL_INTERVENTION_REQUIRED, "target device is not in fastboot"
            )
            return self.state

        self.transition(State.RESTORING_BOOT)
        self._flash_partition("boot", target)
        self.transition(State.RESTORING_VENDOR_BOOT)
        self._flash_partition("vendor_boot", target)
        self.transition(State.RESTORING_DTBO)
        self._flash_partition("dtbo", target)

        self.transition(State.REBOOTING_RESTORED_SYSTEM)
        reboot = self.interop.fastboot(["-s", target, "reboot"], timeout=120)
        self.log.command(reboot)

        self.transition(State.MONITORING_RESTORED_BOOT)
        outcome = self._monitor_until(
            deadline=time.monotonic() + self.config.boot_timeout, label="restored"
        )
        if outcome is BootOutcome.ANDROID_READY:
            self._collect_logs("failure")
            self.transition(State.RECOVERY_SUCCESS, "restored system booted")
            return self.state
        self.transition(
            State.RECOVERY_FAILED, f"restored system did not boot (state={outcome.value})"
        )
        return self.state

    def _flash_partition(self, base: str, serial: str) -> None:
        if self.state not in FASTBOOT_ALLOWED_STATES:
            raise InstallError(
                f"refusing to flash {base} from state {self.state.value}"
            )
        assert self.interop is not None
        image = self.backup_paths[base]
        if not image.is_file():
            raise InstallError(f"backup image for {base} is missing")
        windows_image = self.interop.stage_for_windows(image, subdir=self.attempt_id)
        partition = self.partitions.get(base)
        target_name = partition.path.rsplit("/", 1)[-1] if partition else base
        result = self.interop.fastboot(
            ["-s", serial, "flash", target_name, windows_image], timeout=300
        )
        if not result.ok:
            raise InstallError(
                f"fastboot flash of {target_name} failed (rc={result.returncode}): "
                f"{result.stderr.strip()[-300:]}"
            )
        self.log.info(f"restored {target_name} from {image}")

    # -- manifest -----------------------------------------------------------

    def _write_manifest(self) -> None:
        manifest: dict[str, object] = {
            "attempt_id": self.attempt_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "state": self.state.value,
            "device": self.device.as_manifest() if self.device else {},
            "archive": self.archive.as_manifest() if self.archive else {},
            "windows_tools": self.tools.as_manifest() if self.tools else {},
            "partitions": {k: v.as_manifest() for k, v in self.partitions.items()},
            "backups": self.backup_verification,
            "installed_backups": self.installed_backups,
            "recovery_procedure": {
                "requires_fastboot": True,
                "partitions": list(REQUIRED_PARTITIONS),
                "slot": self.device.slot if self.device else "",
                "note": "Flash the three original images to the slot recorded above, "
                "then reboot.",
            },
        }
        self.manifest = manifest
        path = self.attempt_dir / "recovery-manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install an AnyKernel3 kernel via ADB, with fastboot-only recovery."
    )
    parser.add_argument("--server", default="meowing@141.148.219.139")
    parser.add_argument("--remote-release-dir", default="~/KernelReleases")
    parser.add_argument("--remote-version-file", default="~/AnyKernel3/version.txt")
    parser.add_argument("--zip-prefix", default="MeowKernel")
    parser.add_argument("--work-dir", default="~/kernel-install-work")
    parser.add_argument("--state-dir", default="~/kernel-install-logs")
    parser.add_argument("--serial", default=None, help="target device serial")
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--boot-timeout", type=float, default=DEFAULT_BOOT_TIMEOUT)
    parser.add_argument("--op-timeout", type=float, default=DEFAULT_OP_TIMEOUT)
    parser.add_argument("--install-timeout", type=float, default=DEFAULT_INSTALL_TIMEOUT)
    parser.add_argument("--download-timeout", type=float, default=1800.0)
    parser.add_argument(
        "--force-recovery-on-timeout",
        action="store_true",
        help="treat an expired boot deadline as a confirmed failure (still gated by "
        "the full recovery verification)",
    )
    parser.add_argument("--dry-run", action="store_true", help="validate setup only")
    parser.add_argument(
        "--restore-installed",
        action="store_true",
        help="restore the images captured after the successful install instead "
        "of the pre-install originals.",
    )
    parser.add_argument(
        "--recover-only",
        action="store_true",
        help="enter the boot-failure recovery branch for a device that can be "
        "placed in fastboot. All verification gates (device identity, manifest "
        "match, backup checksums) still apply.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    config = Config(
        ak3_source=Ak3Source(
            host=args.server,
            remote_release_dir=args.remote_release_dir,
            remote_version_file=args.remote_version_file,
            remote_zip_prefix=args.zip_prefix,
        ),
        work_dir=Path(os.path.expanduser(args.work_dir)),
        state_dir=Path(os.path.expanduser(args.state_dir)),
        serial=args.serial,
        poll_interval=args.poll_interval,
        boot_timeout=args.boot_timeout,
        op_timeout=args.op_timeout,
        install_timeout=args.install_timeout,
        download_timeout=args.download_timeout,
        force_recovery_on_timeout=args.force_recovery_on_timeout,
        recover_only=args.recover_only,
        restore_installed=args.restore_installed,
        dry_run=args.dry_run,
    )
    attempt_dir = (
        config.state_dir
        / f"{time.strftime('%Y%m%d-%H%M%S')}-{config.serial or 'auto'}"
    )
    attempt_dir.mkdir(parents=True, exist_ok=True)
    log = Journal(attempt_dir)
    installer = KernelInstaller(config, log)
    final = installer.run()
    print(f"\nfinal state: {final.value}")
    return 0 if final in (State.BOOT_SUCCESS, State.RECOVERY_SUCCESS) else 1


if __name__ == "__main__":
    sys.exit(main())
