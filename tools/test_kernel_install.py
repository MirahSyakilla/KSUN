#!/usr/bin/env python3
"""Unit tests for tools/kernel_install.py.

These use mocks and dry-run harnesses only.  No real device is contacted
and no partition is ever written.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kernel_install as ki  # noqa: E402


# --------------------------------------------------------------------------
# CMD interop and quoting
# --------------------------------------------------------------------------


class TestCmdQuoting(unittest.TestCase):
    """cmd.exe receives one string and cannot delimit spaced arguments.

    These tests encode the behaviour that was established empirically
    against the real Windows tooling: a double quote is passed through
    verbatim by cmd and corrupts the argument, and shell metacharacters
    are interpreted unless caret-escaped.
    """

    def test_simple_argument_unquoted(self):
        self.assertEqual(ki.escape_cmd_arg("devices"), "devices")
        self.assertEqual(ki.escape_cmd_arg("-s"), "-s")

    def test_shell_metacharacters_are_caret_escaped(self):
        for char in "|<>&^()":
            escaped = ki.escape_cmd_arg(f"a{char}b")
            self.assertTrue(escaped.startswith("a^"), (char, escaped))
            self.assertIn(f"^{char}", escaped)

    def test_embedded_quote_is_rejected(self):
        # cmd /s forwards double quotes verbatim, which corrupts the arg.
        with self.assertRaises(ki.InstallError):
            ki.escape_cmd_arg('a"b')

    def test_percent_is_rejected(self):
        # %VAR% expands at parse time; a caret cannot prevent it.
        with self.assertRaises(ki.InstallError):
            ki.escape_cmd_arg("100%")

    def test_control_characters_rejected(self):
        for bad in ("a\nb", "a\rb", "a\x00b"):
            with self.assertRaises(ki.InstallError):
                ki.escape_cmd_arg(bad)

    def test_empty_string_allowed(self):
        self.assertEqual(ki.escape_cmd_arg(""), "")

    def test_build_cmd_line_plain(self):
        line = ki.build_cmd_line(r"C:\platform-tools\adb.exe", ["-s", "abc", "shell", "id"])
        self.assertEqual(line, r"C:\platform-tools\adb.exe -s abc shell id")

    def test_build_cmd_line_allows_spaces_in_exe(self):
        # The executable path may contain spaces; short_path() deals with it.
        line = ki.build_cmd_line(r"C:\Program Files\adb.exe", ["devices"])
        self.assertEqual(line, r"C:\Program Files\adb.exe devices")

    def test_build_cmd_line_rejects_spaces_in_args(self):
        with self.assertRaises(ki.InstallError):
            ki.build_cmd_line(r"C:\adb.exe", ["shell", "getprop ro.model"])

    def test_build_cmd_line_escapes_metacharacters(self):
        line = ki.build_cmd_line(r"C:\adb.exe", ["shell", "a|b"])
        self.assertIn("a^|b", line)


class TestExitCodePropagation(unittest.TestCase):
    def test_nonzero_exit_code_is_preserved(self):
        result = ki.run_host_command(["sh", "-c", "exit 42"], timeout=30)
        self.assertEqual(result.returncode, 42)
        self.assertFalse(result.ok)

    def test_stderr_is_captured(self):
        result = ki.run_host_command(["sh", "-c", "echo boom >&2; exit 1"], timeout=30)
        self.assertIn("boom", result.stderr)
        self.assertEqual(result.returncode, 1)

    def test_timeout_is_reported_not_hung(self):
        result = ki.run_host_command(["sleep", "5"], timeout=0.3)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)
        self.assertFalse(result.ok)

    def test_exit_status_not_masked_by_pipeline(self):
        # The implementation must not wrap the command in a shell pipeline.
        result = ki.run_host_command(["sh", "-c", "exit 7 | cat"], timeout=30)
        self.assertEqual(result.returncode, 0)  # shell reports the pipeline status
        result = ki.run_host_command(["sh", "-c", "exit 7"], timeout=30)
        self.assertEqual(result.returncode, 7)


# --------------------------------------------------------------------------
# Windows path conversion and tool discovery
# --------------------------------------------------------------------------


class TestWindowsInterop(unittest.TestCase):
    def test_wsl_to_windows_uses_wslpath(self):
        interop = ki.WindowsInterop(ki.WindowsTools(Path("/a/adb.exe"), Path("/a/fastboot.exe")))
        with mock.patch.object(ki, "run_host_command") as run:
            run.return_value = ki.CommandResult(["wslpath"], 0, "C:\\tmp\\x.zip\n", "", 0.01)
            self.assertEqual(interop.wsl_to_windows("/tmp/x.zip"), "C:\\tmp\\x.zip")
        run.assert_called_once()
        argv = run.call_args[0][0]
        self.assertTrue(argv[0].endswith("wslpath"), argv)
        self.assertEqual(argv[1], "-w")
        self.assertEqual(argv[2], "/tmp/x.zip")

    def test_wsl_to_windows_fallback(self):
        interop = ki.WindowsInterop(ki.WindowsTools(Path("/a/adb.exe"), Path("/a/fastboot.exe")))
        with mock.patch.object(ki.shutil, "which", return_value=None):
            self.assertEqual(interop.wsl_to_windows("/tmp/x.zip"), "C:\\tmp\\x.zip")

    def test_interop_invokes_cmd_exe(self):
        tools = ki.WindowsTools(Path("/a/adb.exe"), Path("/a/fastboot.exe"))
        interop = ki.WindowsInterop(tools)
        with mock.patch.object(ki, "run_host_command") as run:
            run.return_value = ki.CommandResult([], 0, "", "", 0.01)
            interop.adb(["devices"])
        argv = run.call_args[0][0]
        self.assertEqual(argv[0], "cmd.exe")
        self.assertIn("/d", argv)
        self.assertIn("/s", argv)
        self.assertIn("/c", argv)

    def test_resolution_refuses_linux_binaries(self):
        """Discovery must not silently accept a non-Windows executable."""
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "adb"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            with mock.patch.dict(os.environ, {"WINDOWS_ADB": str(fake)}, clear=False):
                with mock.patch.object(ki, "run_host_command") as run:
                    # A Linux binary cannot report a version banner.
                    run.return_value = ki.CommandResult([], 1, "", "not a valid app", 0.01)
                    with self.assertRaises(ki.InstallError):
                        ki.resolve_windows_tools(ki.Journal(Path(tmp) / "log"))


# --------------------------------------------------------------------------
# AK3 archive validation
# --------------------------------------------------------------------------


def _make_zip(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in members.items():
            archive.writestr(name, text)


class TestAk3Validation(unittest.TestCase):
    def test_valid_archive_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "MeowKernel_test.zip"
            _make_zip(
                zip_path,
                {
                    "anykernel.sh": "BLOCK=boot;\nflash boot;\n",
                    "Image": "x" * 2048,
                    "dtbo.img": "y" * 2048,
                    "tools/magiskboot": "z" * 4096,
                },
            )
            log = ki.Journal(Path(tmp) / "logs")
            archive = ki.inspect_ak3_archive(zip_path, log)
            self.assertEqual(archive.installer, "anykernel.sh")
            self.assertIn("boot", archive.touched_partitions)
            self.assertEqual(len(archive.sha256), 64)

    def test_corrupt_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "broken.zip"
            zip_path.write_bytes(b"PK\x03\x04not-a-real-zip")
            log = ki.Journal(Path(tmp) / "logs")
            with self.assertRaises(ki.InstallError):
                ki.inspect_ak3_archive(zip_path, log)

    def test_archive_without_installer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "noinstaller.zip"
            _make_zip(zip_path, {"Image": "x" * 2048})
            log = ki.Journal(Path(tmp) / "logs")
            with self.assertRaises(ki.InstallError):
                ki.inspect_ak3_archive(zip_path, log)

    def test_installer_discovery_does_not_assume_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "odd.zip"
            _make_zip(zip_path, {"scripts/install_me.sh": "flash boot;\n", "Image": "x" * 4096})
            log = ki.Journal(Path(tmp) / "logs")
            archive = ki.inspect_ak3_archive(zip_path, log)
            self.assertEqual(archive.installer, "scripts/install_me.sh")

    def test_partition_intent_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            zip_path = Path(tmp) / "p.zip"
            _make_zip(
                zip_path,
                {"anykernel.sh": "flash vendor_boot;\nflash dtbo;\nflash vbmeta;\n",
                 "Image": "x" * 4096},
            )
            log = ki.Journal(Path(tmp) / "logs")
            archive = ki.inspect_ak3_archive(zip_path, log)
            for expected in ("vendor_boot", "dtbo", "vbmeta"):
                self.assertIn(expected, archive.touched_partitions)


# --------------------------------------------------------------------------
# Device parsing
# --------------------------------------------------------------------------


class TestDeviceParsing(unittest.TestCase):
    def test_parse_adb_devices(self):
        text = (
            "List of devices attached\n"
            "2be1ac0f       device product:lisa model:Redmi_K40_Pro device:lisa\n"
            "emulator-5554  offline\n"
        )
        entries = ki.parse_adb_devices(text)
        self.assertEqual(entries[0][0], "2be1ac0f")
        self.assertEqual(entries[0][1], "device")
        self.assertEqual(entries[1][1], "offline")

    def test_parse_empty(self):
        self.assertEqual(ki.parse_adb_devices("List of devices attached\n"), [])

    def test_parse_ignores_daemon_noise(self):
        text = (
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\n"
            "abc123   device\n"
        )
        entries = ki.parse_adb_devices(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][0], "abc123")


# --------------------------------------------------------------------------
# State machine gating
# --------------------------------------------------------------------------


class TestStateMachineGating(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = ki.Config(
            ak3_source=ki.Ak3Source(),
            work_dir=Path(self.tmp.name) / "work",
            state_dir=Path(self.tmp.name) / "logs",
        )
        self.log = ki.Journal(Path(self.tmp.name) / "logs" / "attempt")
        self.installer = ki.KernelInstaller(config, self.log)

    def test_fastboot_recovery_rejected_from_normal_states(self):
        for state in (
            ki.State.INITIALIZING,
            ki.State.INSTALLING_KERNEL,
            ki.State.MONITORING_BOOT,
            ki.State.BOOT_SUCCESS,
            ki.State.VERIFYING_BACKUPS,
        ):
            self.installer.state = state
            with self.assertRaises(ki.InstallError):
                self.installer._require_recovery_entry()

    def test_fastboot_recovery_allowed_after_confirmed_failure(self):
        self.installer.state = ki.State.BOOT_FAILURE_CONFIRMED
        self.installer._require_recovery_entry()  # must not raise

    def test_flash_refused_outside_recovery_states(self):
        self.installer.state = ki.State.MONITORING_BOOT
        with self.assertRaises(ki.InstallError):
            self.installer._flash_partition("boot", "serial")

    def test_flash_allowed_inside_recovery_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp) / "boot.original.img"
            img.write_bytes(b"original")
            interop = mock.MagicMock()
            interop.fastboot.return_value = ki.CommandResult([], 0, "OKAY", "", 0.01)
            interop.wsl_to_windows.return_value = r"C:\\tmp\\boot.original.img"
            self.installer.interop = interop
            self.installer.state = ki.State.RESTORING_BOOT
            self.installer.backup_paths = {"boot": img}
            self.installer.partitions = {
                "boot": ki.Partition("boot", "/dev/block/by-name/boot_a", "/dev/block/sde11", 1)
            }
            self.installer._flash_partition("boot", "2be1ac0f")
        args = interop.fastboot.call_args[0][0]
        self.assertEqual(args[:4], ["-s", "2be1ac0f", "flash", "boot_a"])
        self.assertTrue(args[4].endswith("boot.original.img"))

    def test_state_transitions_are_logged(self):
        self.installer.transition(ki.State.CHECKING_DEVICE, "test")
        self.assertEqual(self.installer.state, ki.State.CHECKING_DEVICE)
        kinds = {entry["kind"] for entry in self.log.entries}
        self.assertIn("state", kinds)


# --------------------------------------------------------------------------
# Boot monitoring
# --------------------------------------------------------------------------


class TestBootMonitoring(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = ki.Config(
            ak3_source=ki.Ak3Source(),
            work_dir=Path(self.tmp.name) / "work",
            state_dir=Path(self.tmp.name) / "logs",
            poll_interval=0.05,
            boot_timeout=5.0,
        )
        self.log = ki.Journal(Path(self.tmp.name) / "logs" / "attempt")
        self.installer = ki.KernelInstaller(config, self.log)

    def _install_interop(self, adb_out, fb_out, states):
        interop = mock.MagicMock()
        state_iter = iter(states)

        def adb(args, timeout=30):
            return ki.CommandResult(args, 0, adb_out, "", 0.01)

        def fastboot(args, timeout=30):
            return ki.CommandResult(args, 0, fb_out, "", 0.01)

        interop.adb.side_effect = adb
        interop.fastboot.side_effect = fastboot
        self.installer.interop = interop
        self.installer.session = mock.MagicMock()
        self.installer.session.prop.return_value = "1"
        return interop

    def test_temporary_disconnect_is_not_a_bootfailure(self):
        # ADB empty, fastboot empty -> DISCONNECTED, never FASTBOOT.
        self._install_interop("", "", [])
        self.installer.config.boot_timeout = 0.4
        outcome = self.installer._monitor_until(
            deadline=__import__("time").monotonic() + 0.4, label="t"
        )
        self.assertEqual(outcome, ki.BootOutcome.UNKNOWN)
        self.assertNotEqual(outcome, ki.BootOutcome.FASTBOOT)

    def test_fastboot_detection_escalates(self):
        self._install_interop("", "2be1ac0f\tfastboot\n", [])
        outcome = self.installer._monitor_until(
            deadline=__import__("time").monotonic() + 5, label="t"
        )
        self.assertEqual(outcome, ki.BootOutcome.FASTBOOT)

    def test_android_ready_detected(self):
        self._install_interop(
            "List of devices attached\n2be1ac0f\tdevice\n", "", []
        )
        outcome = self.installer._monitor_until(
            deadline=__import__("time").monotonic() + 5, label="t"
        )
        self.assertEqual(outcome, ki.BootOutcome.ANDROID_READY)

    def test_monitoring_is_bounded_by_deadline(self):
        self._install_interop("", "", [])
        started = __import__("time").monotonic()
        self.installer._monitor_until(
            deadline=__import__("time").monotonic() + 0.3, label="t"
        )
        elapsed = __import__("time").monotonic() - started
        self.assertLess(elapsed, 3.0, "monitor must respect its deadline")

    def test_poll_interval_is_bounded(self):
        with self.assertRaises(ki.InstallError):
            ki.Config(
                ak3_source=ki.Ak3Source(),
                work_dir=Path(self.tmp.name),
                state_dir=Path(self.tmp.name),
                poll_interval=30.0,
            )
        with self.assertRaises(ki.InstallError):
            ki.Config(
                ak3_source=ki.Ak3Source(),
                work_dir=Path(self.tmp.name),
                state_dir=Path(self.tmp.name),
                poll_interval=0,
            )

    def test_no_long_sleeps_in_source(self):
        source = Path(ki.__file__).read_text()
        import re

        for match in re.finditer(r"sleep\s*\(?\s*(\d+)", source):
            self.assertLessEqual(
                int(match.group(1)), 1, f"long sleep found: {match.group(0)}"
            )
        for match in re.finditer(r"time\.sleep\(\s*([0-9.]+)\s*\)", source):
            self.assertLessEqual(float(match.group(1)), 1.0)


# --------------------------------------------------------------------------
# Manifest and recovery binding
# --------------------------------------------------------------------------


class TestManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        config = ki.Config(
            ak3_source=ki.Ak3Source(),
            work_dir=Path(self.tmp.name) / "work",
            state_dir=Path(self.tmp.name) / "logs",
        )
        self.log = ki.Journal(Path(self.tmp.name) / "logs" / "attempt")
        self.installer = ki.KernelInstaller(config, self.log)
        self.installer.device = ki.DeviceInfo(serial="2be1ac0f", state="device", slot="_a")

    def test_manifest_contains_recovery_binding(self):
        self.installer._write_manifest()
        path = self.installer.attempt_dir / "recovery-manifest.json"
        self.assertTrue(path.is_file())
        data = json.loads(path.read_text())
        self.assertEqual(data["device"]["serial"], "2be1ac0f")
        self.assertTrue(data["recovery_procedure"]["requires_fastboot"])
        self.assertEqual(
            sorted(data["recovery_procedure"]["partitions"]),
            sorted(["boot", "vendor_boot", "dtbo"]),
        )

    def test_manifest_records_installed_backups(self):
        self.installer.installed_backups = {
            "boot": {"file": "/tmp/boot.installed.img", "sha256": "a" * 64}
        }
        self.installer._write_manifest()
        data = json.loads(
            (self.installer.attempt_dir / "recovery-manifest.json").read_text()
        )
        self.assertIn("installed_backups", data)
        self.assertIn("boot", data["installed_backups"])

    def test_saving_installed_images_state_exists(self):
        self.assertIn(ki.State.SAVING_INSTALLED_IMAGES, list(ki.State))

    def test_recovery_can_select_installed_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp) / "boot.installed.img"
            img.write_bytes(b"new-kernel")
            self.installer.installed_backups = {
                "boot": {"file": str(img), "sha256": ki.sha256_file(img)},
                "vendor_boot": {"file": str(img), "sha256": ki.sha256_file(img)},
                "dtbo": {"file": str(img), "sha256": ki.sha256_file(img)},
            }
            self.installer.backup_verification = {
                base: {"sha256": "0" * 64} for base in ("boot", "vendor_boot", "dtbo")
            }
            self.installer._write_manifest()
            self.installer.config.restore_installed = True
            self.installer.state = ki.State.BOOT_FAILURE_CONFIRMED
            self.installer.transition(ki.State.VERIFYING_RECOVERY_BACKUPS)
            # the installed set verifies; the pre-install set would not
            self.installer.backup_paths = {
                base: Path(str(info["file"]))
                for base, info in self.installer.installed_backups.items()
            }
            self.installer._verify_recovery_gates()

    def test_recovery_rejects_mismatched_device(self):
        self.installer._write_manifest()
        self.installer.manifest["device"]["serial"] = "someoneelse"
        self.installer.state = ki.State.BOOT_FAILURE_CONFIRMED
        self.installer.transition(ki.State.VERIFYING_RECOVERY_BACKUPS)
        with self.assertRaises(ki.InstallError):
            self.installer._recover()

    def test_recovery_rejects_missing_backup(self):
        self.installer._write_manifest()
        self.installer.backup_paths = {}
        self.installer.state = ki.State.BOOT_FAILURE_CONFIRMED
        self.installer.transition(ki.State.VERIFYING_RECOVERY_BACKUPS)
        with self.assertRaises(ki.InstallError):
            self.installer._recover()

    def test_recovery_rejects_tampered_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp) / "boot.original.img"
            img.write_bytes(b"tampered")
            self.installer.backup_paths = {"boot": img}
            self.installer.backup_verification = {
                "boot": {"sha256": "0" * 64},
                "vendor_boot": {"sha256": "0" * 64},
                "dtbo": {"sha256": "0" * 64},
            }
            self.installer._write_manifest()
            self.installer.state = ki.State.BOOT_FAILURE_CONFIRMED
            self.installer.transition(ki.State.VERIFYING_RECOVERY_BACKUPS)
            with self.assertRaises(ki.InstallError):
                self.installer._recover()


# --------------------------------------------------------------------------
# Partition discovery
# --------------------------------------------------------------------------


class TestPartitionDiscovery(unittest.TestCase):
    def test_discovery_resolves_symlinks_and_sizes(self):
        session = mock.MagicMock()

        def script(command, timeout=60):
            if "ls -l" in command:
                return ki.CommandResult(
                    [],
                    0,
                    "boot_a -> /dev/block/sde11\n"
                    "vendor_boot_a -> /dev/block/sde22\n"
                    "dtbo_a -> /dev/block/sde15\n",
                    "",
                    0.01,
                )
            return ki.CommandResult([], 0, "201326592\n", "", 0.01)

        session.script.side_effect = script
        with tempfile.TemporaryDirectory() as tmp:
            log = ki.Journal(Path(tmp) / "log")
            parts = ki.discover_partitions(session, log, "_a")
        self.assertEqual(parts["boot"].resolved, "/dev/block/sde11")
        self.assertEqual(parts["boot"].size, 201326592)
        self.assertEqual(parts["dtbo"].path, "/dev/block/by-name/dtbo_a")

    def test_missing_partition_is_fatal(self):
        session = mock.MagicMock()
        session.script.return_value = ki.CommandResult([], 0, "boot_a -> /dev/x\n", "", 0.01)
        with tempfile.TemporaryDirectory() as tmp:
            log = ki.Journal(Path(tmp) / "log")
            with self.assertRaises(ki.InstallError):
                ki.discover_partitions(session, log, "_a")


if __name__ == "__main__":
    unittest.main(verbosity=2)
