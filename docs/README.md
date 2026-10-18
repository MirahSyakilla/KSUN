**English** | [简体中文](README_CN.md) | [繁體中文](README_TW.md) | [Türkçe](README_TR.md) | [Português (Brasil)](README_PT-BR.md) | [한국어](README_KO.md) | [Français](README_FR.md) | [Bahasa Indonesia](README_ID.md) | [Русский](README_RU.md) | [Українська](README_UA.md) | [ภาษาไทย](README_TH.md) | [Tiếng Việt](README_VI.md) | [Italiano](README_IT.md) | [Polski](README_PL.md) | [Български](README_BG.md) | [日本語](README_JA.md) | [Español](README_ES.md)

---

<div align="center">
  <img src="/assets/kernelsu_next.png" width="96" alt="KernelSU Next Logo">

  <h2>KernelSU Next — susfs+nomount-hookless</h2>
  <p><strong>A zero-kprobe, hookless root solution integrated at kernel build time.</strong></p>
</div>

---

## What is this branch?

This branch of KernelSU Next hosts a **hookless SUSFS and NoMount runtime** entirely
inside KernelSU-Next, with **zero runtime kprobe/kretprobe machinery** on its
interception paths.

"Hookless" does **not** mean "no interception". It means the interception paths use
**already-existing compiled kernel structures** instead of runtime probe machinery:

- **ARM64 Branch Link (BL) call-site patching** — direct branch rewrites of existing
  compiled call sites to KSU wrappers (VFS permission, `d_path`, getattr,
  `getname_flags`, `getname_kernel`, `iterate_dir`, and the stat/exec/mount families).
- **Syscall-table tampering** — hooked syscall table slots (native
  `sys_call_table` plus the AArch32 `compat_sys_call_table` mirror) are replaced with
  a KSU dispatcher.
- **Existing function-pointer / operation-table replacement** where applicable
  (e.g. `mntns_operations.get`).
- **Runtime LSM slot patching** of already-registered hook entries
  (`security_hook_heads`), using only existing vendor LSM hook types.

The vendor kernel sources are **not modified** to add interception points. The
`drivers/kernelsu` tree is integrated at build time; everything else is runtime
binary patching of structures that already exist in the compiled kernel.

**Versions:** SUSFS runtime `v2.3.0` (project-local variant designation
`hookless-v0.4`; not an upstream susfs release) · NoMount netlink family version `1`,
module ABI version `13`.

---

## Project status

- Hookless SUSFS (`sus_path`, `open_redirect`, `sus_mount`, `sus_kstat`, `sus_map`,
  `spoof_cmdline_or_bootconfig`, `spoof_uname`, `avc_log_spoofing` — the last one requires
  `CONFIG_AUDIT=y` (the common `CONFIG_AUDIT=n` configuration has no AVC
  audit path to spoof and the feature is absent by design) and is
  implemented as a 7-callsite branch-link rewrite of the compiled
  `slow_avc_audit()` callers; runtime validated on the reference device).
- Hookless NoMount (path redirection, whiteouts, synthetic directories, UID blocking,
  packed netlink ABI).
- Syscall-table tampering, native and AArch32 compat.
- ARM64 Branch Link families (permission / d_path / getattr / getname / iterate_dir /
  stat / exec / mount).
- Zero-kprobe configuration validated on device (`CONFIG_KPROBES=n`,
  `CONFIG_KRETPROBES=n`).
- Native + AArch32 compat validation, long-duration soak, adversarial code review.

Validated on a Xiaomi lisa (SM7325, ARM64, Android 16, stock-style 5.4.302). This is
**not** a claim of universal kernel compatibility — see
[Compatibility](#-compatibility).

---

## Installation (kernel-source integration)

This is a **kernel-source integration mechanism** for kernel developers building an
Android ARM64 kernel — not an Android APK installation.

From the root of your kernel source tree:

```bash
curl -LSs "https://raw.githubusercontent.com/MirahSyakilla/KSUN/susfs-nomount/kernel/setup.sh" | bash -
```

What the script does:

1. Locates your kernel's `drivers/` directory (`common/drivers` or `drivers`).
2. Clones this repository into `KernelSU-Next/` (branch `susfs+nomount-hookless`) or
   updates an existing checkout (supports `--cleanup` and pinning to a commit/tag).
3. Refreshes the KernelSU version stamp from git.
4. Symlinks `drivers/kernelsu` → the KSU `kernel/` tree.
5. Appends `obj-$(CONFIG_KSU) += kernelsu/` to the drivers `Makefile` and sources
   `drivers/kernelsu/Kconfig` from the drivers `Kconfig`, so `CONFIG_KSU*` options
   appear in your normal kernel configuration flow.

Re-run with `--cleanup` to revert all of the above.

## Required kernel configuration

Add to your defconfig:

```text
CONFIG_KSU=y
CONFIG_KSU_HOOK_CORE=y
CONFIG_KSU_TAMPER_SYSCALL_TABLE=y
CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y
CONFIG_KSU_HOOKLESS_SUSFS=y
CONFIG_KSU_HOOKLESS_NOMOUNT=y
```

### Additional requirements (from source audit)

- `CONFIG_KALLSYMS=y` and `CONFIG_KALLSYMS_ALL=y` — required by the branch-link
  symbol scanner (`KSU_HOOKLESS_NOMOUNT` depends on `KALLSYMS`; the scanner resolves
  call sites and boundaries through kallsyms).
- `CONFIG_KSU_HOOKLESS_NOMOUNT` additionally `depends on NET` (Generic Netlink
  family `nomount`) and `ARM64`.
- `CONFIG_EXT4_FS` is required by `CONFIG_KSU` itself.
- The branch-link scanner and SUSFS/NoMount Kbuild probes read your kernel sources at
  build time to select compatibility paths (e.g. hlist vs list LSM hooks,
  `iterate_shared`, genetlink policy layout); no manual action is needed, but exotic
  trees may fail the probes and disable the affected optional path.

### KPROBES / KRETPROBES

**The normal hookless configuration does NOT require `CONFIG_KPROBES` or
`CONFIG_KRETPROBES`.** The preferred configuration is:

```text
# CONFIG_KPROBES is not set
# CONFIG_KRETPROBES is not set
```

The purpose of this branch is specifically to remove runtime kprobe/kretprobe
interception from the KSU hot paths and replace it with more direct mechanisms
(syscall-table tampering, ARM64 Branch Link call-site patching, existing
operation/function-pointer structures, existing binary dispatch infrastructure).
The motivation is architectural as well as practical: no int3 traps, no
single-step emulation, no kretprobe instance buffers on the VFS hot path.

To be precise: generic kernel `CONFIG_KPROBES`/`CONFIG_KRETPROBES` remain independent
kernel facilities. A kernel developer may enable them for unrelated debugging or
instrumentation, but they are not required by this hookless configuration and should
not be enabled merely for KSU. Enabling them does **not** change KSU's behavior.

### Why `CONFIG_KSU_HOOK_CORE`?

The umbrella symbol was previously named `CONFIG_KSU_KPROBES_HOOK` — a name inherited
from an earlier kprobe-based architecture. The implementation no longer uses kprobes
at all, so the symbol was renamed to `CONFIG_KSU_HOOK_CORE`. It selects the runtime
interception core (syscall-table tamper dispatch, ARM64 branch-link patching, runtime
LSM slot patching) as opposed to `CONFIG_KSU_MANUAL_HOOK`, the legacy mode for
kernels whose sources already contain manual `ksu_handle_*` calls. Nothing in the
hookless configuration depends on the kernel's kprobe facilities.

## Hook modes

KSU reports its active interception mechanisms through the `GET_HOOK_MODE` supercall
(shown on the Manager home screen):

| Mode | Configuration | Mechanism |
|---|---|---|
| `SyscallTable` | `CONFIG_KSU_TAMPER_SYSCALL_TABLE=y` | hooked syscall table slots dispatch to KSU handlers |
| `BranchLink` | `CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y` | compiled BL call sites branch to KSU wrappers |
| `SyscallTable+BranchLink` | both enabled (**shipped configuration**) | both mechanisms composed; table slots for hooked syscalls, BL for the VFS families |
| `Manual` | `CONFIG_KSU_MANUAL_HOOK=y` | legacy mode: your kernel sources call `ksu_handle_*` directly; no runtime patching |

Legacy `Tracepoint` and `Kprobes` dispatch profiles remain compiled only for
non-TAMPER configurations when the kernel provides
`CONFIG_HAVE_SYSCALL_TRACEPOINTS`/`CONFIG_KPROBES`/`CONFIG_KRETPROBES`. They are
**not** part of the zero-probe architecture and are not used by this branch's shipped
configuration.

## Measured overhead

Measured overhead data for the `SyscallTable+BranchLink` configuration
(README updated 2026-09-12):

|         Run | sucompat=0 | sucompat=1 |    Overhead |
| ----------: | ---------: | ---------: | ----------: |
|           1 |     13,494 |     13,531 |     +0.274% |
|           2 |     13,444 |     13,292 |     +1.144% |
|           3 |     13,272 |     13,296 |     +0.181% |
|           4 |     13,152 |     13,172 |     +0.152% |
|           5 |     13,215 |     13,360 |     +1.097% |
|           6 |     13,279 |     13,231 |     −0.361% |
| **Average** |            |            | **+0.415%** |

Measured result: **+0.415% average overhead with KSU's sucompat path active**.
The architectural motivation beyond this single measurement is the complete removal
of kprobe/kretprobe runtime machinery (int3 traps, single-stepping, kretprobe
instance management) from the interception paths. The table above is the only
quantified claim made here.

## Compatibility

Claims below are scoped to what this branch's code and validation actually support.
The upstream "Android 4.4 – 6.6" compatibility table does **not** apply to the
hookless SUSFS/NoMount runtimes.

| Kernel | Status | Notes |
|---|---|---|
| **5.4 (ARM64, stock-style)** | **Validated** | Live-device validated end-to-end on a stock-style 5.4.302 Android ARM64 kernel: full deterministic suite, AArch32 compat, long-duration soak, adversarial review. This is the reference target. |
| **4.19 (ARM64, stock-style)** | **Untested, likely missing API** | The Kconfig/build probes and the legacy compatibility paths target 4.19, but stock 4.19 lacks several APIs the runtimes use — notably the modern `vfs_create_mount()` API used by the SUSFS mount runtime paths (added in 5.x). A 4.19 build requires resolving those API gaps (backport or alternative path) and is **not live-device validated** from this branch. |
| **4.9** | **Untested, likely missing API** | Compatibility shims exist (linked-list VMAs, old page walker, flex arrays, raw-argument syscall table, list-based LSM hooks), but the combination is not live-device validated and additionally requires syscall tracepoints and the Android vendor interfaces consumed by `KSU_HOOK_CORE`. |
| **3.10 / 3.18** | **Unsupported** by hookless SUSFS | Predate several required VFS and KSU hook interfaces. |

Architecture: the branch-link scanner, syscall-table tamper, and NoMount are
**ARM64**; `KSU_TAMPER_SYSCALL_TABLE` also supports `X86_64`. Older kernels may
require the backports above; do not assume conditional code equals validated support.

### Branch Link portability and manifests

Branch Link manifests are **intentionally target-build-specific**: the scanner
discovers the compiled call sites of each family from the target kernel's own
Image/System.map at boot, validates every record (symbol identity, function
boundaries, BL reach, duplicates), and fails closed if any REQUIRED site is
missing. Addresses and site counts are therefore expected to differ between
kernels, compilers, and configurations — that is the design, not a limitation.
What is portable is the discovery/validation/patching/rollback machinery itself.
Binary validation against official GKI prebuilts confirmed every hook family
has discoverable call sites on android13-5.15 and android14-6.1, and static
source analysis confirms the family boundaries on 6.12 (site counts are
deliberately per-build: e.g. `vfs_getattr_nosec` is standalone with 21 sites
on 5.15 and 5 sites on 6.1 vs a single site on the lisa 5.4 build, and the
fd-stat wrappers call `vfs_fstat` on 5.15/6.1 but inline through
`vfs_getattr` on 5.4). Runtime validation on those targets has not been
performed.

Note on `stat-fd`: on the lisa 5.4 build `vfs_fstat()` is fully inlined into the
fd-stat syscall wrappers (which call `vfs_getattr()` directly), so that family
has no independent patch point and reports not-ready. This is **not** a missing
feature: the old symbol-scoped kretprobe never fired on this build's fd-stat
path either, and the user-visible stat family is covered by the stat-path +
kstat layers. On 5.15-style builds where the fd wrappers keep their
`vfs_getattr_nosec` call, the existing stat-fd manifest routes resolve and the
family activates.

For detailed design notes see [docs/susfs-hookless.md](susfs-hookless.md) and
[docs/nomount-hookless.md](nomount-hookless.md).

---

## 📜 License

- **`/kernel` directory:** [GPL-2.0-only](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- **All other files:** [GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

---

## 🙏 Credits

- [Kernel-Assisted Superuser](https://git.zx2c4.com/kernel-assisted-superuser/about/) – Concept inspiration
- [Magisk](https://github.com/topjohnwu/Magisk) – Core root implementation
- [Genuine](https://github.com/brevent/genuine/) – APK v2 signature validation
- [Diamorphine](https://github.com/m0nad/Diamorphine) – Rootkit techniques
- [KernelSU](https://github.com/tiann/KernelSU) – The original base that made KernelSU Next possible
- [Magic Mount Port](https://github.com/5ec1cff/KernelSU/blob/main/userspace/ksud/src/magic_mount.rs) – For Magic Mount support
- [SUSFS](https://gitlab.com/samsungerman/android_kernel_samsung_msm8917/-/tree/lineage-18.1/drivers/kernelsu/susfs.c) – SUSFS feature model
- [maxsteeel/nomount](https://github.com/maxsteeel/nomount) – NoMount behavior model
