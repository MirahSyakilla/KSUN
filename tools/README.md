# `kernel_install.py` — AnyKernel3 installer with gated fastboot recovery

Installs an AnyKernel3 (AK3) kernel onto a connected Android device over
ADB, and restores the original `boot`, `vendor_boot` and `dtbo` partitions
through fastboot **only** if the device fails to boot.

```
just kernel_install                    # install the current server release
just kernel_install_test               # unit tests (no device touched)
python3 tools/kernel_install.py --help # all options
```

## Tools in this directory

| Tool | Purpose |
|---|---|
| `kernel_install.py` | the installer and recovery state machine |
| `test_kernel_install.py` | unit tests; never contact a device |
| `set_test_version.sh` | tags a build with a test id, in the kernel version string and the release name |
| `deploy_server.sh` | provisions a build server from this repository alone |
| `build/` | the build wrappers deployed to the server as `~/bin` |
| `anykernel/anykernel.sh` | the authoritative AnyKernel3 installer script |

## Tagging a build

```
./tools/set_test_version.sh v2.1 test02
```

writes both

```
~/AnyKernel3/version.txt                              ->  v2.1-test02
arch/arm64/configs/vendor/localversion.config          ->  CONFIG_LOCALVERSION="-MeowKernel-v2.1-test02"
```

so the published archive and the running kernel's `uname` carry the same
identifier.  The running build can then be identified directly:

```
$ adb shell uname -r
5.4.302-MeowKernel-v2.1-test02
```

## Provisioning a server

The repository is the source of truth; a rented server is disposable.

```
./tools/deploy_server.sh meowing@203.0.113.10
```

publishes the kernel tree, the build wrappers and the AnyKernel3 release
directory, and tags the release.  Anything changed on the server should be
made here and pushed, never edited in place, so that losing the server
loses nothing.

## Normal path

```
INITIALIZING -> RESOLVING_WINDOWS_TOOLS -> DOWNLOADING_AK3 -> VALIDATING_AK3
  -> CHECKING_DEVICE -> CHECKING_ROOT -> PUSHING_AK3 -> EXTRACTING_AK3
  -> DISCOVERING_PARTITIONS -> BACKING_UP_PARTITIONS -> VERIFYING_BACKUPS
  -> INSTALLING_KERNEL -> REBOOTING -> MONITORING_BOOT -> COLLECTING_BOOT_LOGS
  -> BOOT_SUCCESS
```

The device is never flashed by hand. The complete AK3 archive is pushed to
`/data/local/tmp/AnyKernel3.zip`, extracted **on the device**, and the
archive's own installer runs as root, so it performs whatever device-specific
partition work it was written to perform.

## Failure path

```
... -> MONITORING_BOOT -> BOOT_FAILURE_CONFIRMED
  -> VERIFYING_RECOVERY_BACKUPS -> FASTBOOT_RECOVERY
  -> RESTORING_BOOT -> RESTORING_VENDOR_BOOT -> RESTORING_DTBO
  -> REBOOTING_RESTORED_SYSTEM -> MONITORING_RESTORED_BOOT
  -> COLLECTING_FAILURE_LOGS -> RECOVERY_SUCCESS | RECOVERY_FAILED
```

`BOOT_FAILURE_CONFIRMED` is only reached when the device is actually
enumerated in fastboot, or when the operator passes
`--force-recovery-on-timeout` explicitly. A temporary ADB disconnection is
never treated as a boot failure, and an expired deadline without evidence
ends in `STATE_UNKNOWN` — a safe stop, not blind flashing.

The only fastboot call the ordinary path makes is the read-only
`fastboot devices` enumeration used while monitoring a boot, because
distinguishing "the device is in fastboot" from "the device is merely
disconnected" requires it.  No fastboot command that writes to the device
is reachable outside the gated recovery branch.

Fastboot is unreachable from every other state. `KernelInstaller._flash_partition`
refuses to run unless the current state is one of the recovery states, and
`KernelInstaller._require_recovery_entry` refuses to enter the branch at all
from an ordinary installation state.

## Windows interop

All host-side `adb` and `fastboot` calls go through `cmd.exe`
(`/d /s /c`) so the Windows binaries are used, not the Linux ones. The
Windows executables are discovered from `WINDOWS_ADB` / `WINDOWS_FASTBOOT`,
then the usual WSL mount points, then `where` via `cmd.exe`. Linux
`adb`/`fastboot` are never used as a fallback.

Three quoting rules were established empirically against the real tooling
and are enforced by `escape_cmd_arg` / `build_cmd_line`:

* **Double quotes are rejected.** With `/s`, `cmd.exe` forwards quotes
  verbatim instead of using them as delimiters, so a quoted argument
  arrives corrupted.
* **An argument may not contain a space.** `cmd.exe` receives one string
  and cannot know where an argument ends.
* **Shell metacharacters are caret-escaped.** `| < > & ^ ( )` are
  interpreted by `cmd.exe`; a caret in front of them passes them through
  literally. `%` cannot be escaped this way and is rejected.

Consequently, anything richer than a single word — pipes, redirection,
`&&`, quoted strings — is carried by a **script file** rather than by the
command line. `DeviceSession.words` / `DeviceSession.su` pass a list of
simple shell words; `DeviceSession.script` stages a script on the device
and executes it, and the script's exit status is propagated by adb.

Files are staged on the Windows filesystem (`C:\kernel-install-staging\`)
before being handed to adb or fastboot, because the Windows tools cannot
reliably read files through the WSL UNC share and cannot write into a WSL
path at all.

## Backups and the recovery manifest

Before the installer is allowed to run, all three partitions are read on
the device, pulled to the host, and verified:

* the device-side copy must match the partition size,
* the host copy must match the partition size,
* the host and device SHA-256 must agree.

A failure at any of those points aborts before the installer runs.

`recovery-manifest.json` records the device identity, the archive
checksum, the resolved partition paths and sizes, the backup filenames and
checksums, the verification results, the Windows tool paths, and the
recovery procedure. The recovery branch refuses to restore anything unless
the manifest's serial matches the connected device and every backup still
matches its recorded checksum.

Two sets of images are kept.

* **Pre-install originals** — read before the installer runs, so a failure
  can be undone completely.
* **Installed images** — captured after the new kernel has booted and
  reported itself running (`installed/<name>.installed.img`). These are
  known-good: the device booted them. A later recovery can therefore
  restore the working kernel instead of falling back to the older build.

```
python3 tools/kernel_install.py --recover-only               # restore the originals
python3 tools/kernel_install.py --recover-only --restore-installed
```

Backups and logs are written to `~/kernel-install-logs/<timestamp>-<serial>/`
and are never deleted automatically.

## Diagnostics

After every boot attempt the following are collected into `logs-boot/` or
`logs-failure/`: `logcat -b all`, `logcat -b kernel`, `dmesg`, the
pstore/ramoops records under `/sys/fs/pstore`, boot properties and
`/proc/cmdline`, `dumpsys dropbox`, and a tombstone listing. Missing
sources are recorded as permission errors rather than silently dropped.

## Device assumptions

These are specific to the Xiaomi `lisa` (sm8350) and were confirmed on
the connected device:

* A/B device with a single logical slot. The active slot comes from
  `ro.boot.slot_suffix`; partitions are resolved as
  `/dev/block/by-name/<name><slot_suffix>` and fall back to the
  unsuffixed name.
* The kernel lives in `boot`, the vendor ramdisk in `vendor_boot`, and the
  device tree overlays in `dtbo`. There is no `init_boot`.
* Root is available through KernelSU's `su`, and a busybox is present at
  `/data/adb/ksu/bin/busybox`. AK3 is executed with that busybox as the
  shell because the stock Android shell is toybox's mksh.
* `/dev/block/bootdevice` does not exist, but AK3 falls back to
  `/dev/block/by-name`, which is what it uses.
* The AK3 archive ships only `Image` and `dtbo.img`. With no `dtb` file
  and no `vendor_ramdisk/` directory, `ak3-core.sh` skips the vendor_boot
  setup entirely, so `vendor_boot` is never repacked or flashed.

## Known behaviours of the AK3 installer on Android

* `anykernel.sh: line 18: can't create /proc/self/fd/: Is a directory` —
  an ash redirection quirk in the dump helper. Harmless; the install
  continues and completes.
* `rev: not found` — AK3 asks for `rev` to build a version string. The
  release version comes from `version.txt` instead.
* `unexpected ASN.1 DER tag` from `magiskboot` while re-signing — the
  device's AVB key is not understood by the bundled avbtool. The
  bootloader is unlocked, so this does not block the boot.

## Testing

`tools/test_kernel_install.py` covers the quoting rules, exit-code
propagation, path conversion, archive validation, device parsing,
partition discovery, the state-machine gates, the fastboot-only
restriction, the manifest binding, and the bounded monitoring loop. It
never contacts a device and never writes a partition.
