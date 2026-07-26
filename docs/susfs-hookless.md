# SUSFS Hookless

## Overview

`susfs-hookless` moves SUSFS integration out of main-kernel source patches and
into `KernelSU-Next` only.

The target configuration is:

- `CONFIG_KSU_KPROBES_HOOK=y`
- `CONFIG_KSU_KPROBES_SUSFS=y`

On the Lisa kernel tree, `drivers/kernelsu` resolves to
`KernelSU-Next/kernel`, so the hookless SUSFS layer is consumed through the
existing KernelSU build path without adding new `fs/` or `include/` files to
the main kernel tree.

## Origins

This implementation was inspired by two prior directions:

- the branch-hack approach used in
  [`backslashxx/KernelSU`](https://github.com/backslashxx/KernelSU)
- the hookless runtime design explored in
  [NoMount's `experimental/hookless` branch](https://github.com/maxsteeel/nomount/tree/experimental/hookless)

The current `susfs-hookless` port is not a direct copy of either project, but
it follows the same general maintenance goal: keep main-kernel patching to a
minimum and move feature logic into a smaller runtime-owned layer.

## Goal

The goal is not "zero hooks anywhere".

The goal is:

- no manual source patching across generic kernel files such as `fs/*`,
  `mm/*`, `kernel/sys.c`, or `security/selinux/*`
- all SUSFS maintenance kept inside `KernelSU-Next`
- runtime behavior that stays close to upstream SUSFS where it matters for
  userspace compatibility

## Design Model

Hookless SUSFS uses a hybrid model.

Path-facing features follow the same general idea as NoMount:

- store policy inside a KSU-owned rule engine
- hijack only affected per-object operation tables at runtime
- avoid global VFS edits

Global proc/mm surfaces use small KSU-owned runtime instrumentation:

- kprobes and kretprobes
- runtime procfs file-operation replacement
- runtime `seq_operations` replacement
- existing KSU hooks where they are already available

This keeps the maintenance boundary narrow while still covering SUSFS features
that cannot be expressed as a pure VFS overlay.

## Source Layout

The hookless implementation lives under `KernelSU-Next/kernel/`:

- `kernel/susfs/`
- `kernel/hook/`
- `kernel/infra/`
- `kernel/supercall/`

There is no dependency on the old `susfs4ksu/kernel_patches/50_add_*` main
kernel patch path.

## Runtime Architecture

### Path and redirect layer

`sus_path` is implemented as a local runtime overlay:

- rules are stored inside `KernelSU-Next`
- affected parent directories have their `i_op.lookup` replaced
- affected parent directories have their `i_fop.iterate*` replaced

`open_redirect` uses the ARM64 branch-link runtime when
`CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y`:

- the runtime locates `do_filp_open()` and patches its syscall callsites
- the wrapper resolves the visible object without opening or creating it,
  resolves the inode-keyed rule, then opens the backend pathname
- `O_TRUNC` and `O_EXCL` retain native create/truncate semantics because the
  redirect decision never performs a probe open
- redirect metadata is restored by inode/device-keyed SUSFS kstat and d_path
  helpers

No synthetic inode, proxy file, or permanent `fs/open.c` change is involved.
If the required callsite patch cannot be installed, redirect rules fail closed
with `-EOPNOTSUPP`.

### Metadata spoofing

`sus_kstat` uses inode/device-keyed metadata overlays for redirected backend
objects and a KSU-owned compatibility layer for standalone files.  In
branch-link mode, the existing NoMount `vfs_getattr_nosec` return probe also
dispatches the SUSFS kstat layer for direct callers; ARM64 `stat*`/`fstat*`
wrappers cover vendor builds that inline that helper.

The standalone compatibility layer currently uses:

- a `vfs_getattr_nosec()` kretprobe (or the branch-link stat wrappers when the
  target callsite is inlined)
- runtime replacement of proc `maps` and `smaps` `seq_operations.show`

### Mount hiding

Mount hiding is implemented from inside KernelSU by rewriting procfs mount
views at runtime instead of patching procfs source files.

The current layer covers:

- `/proc/*/mounts`
- `/proc/*/mountinfo`
- `/proc/*/mountstats`
- `/proc/*/fdinfo/*`

The rewritten view is intentionally scoped to the same SUSFS-targeted app and
isolated UIDs. Root and zygote-side readers stay on the stock kernel path.

### Mount namespace normalization

Helper and isolated app processes can start in a different mount namespace even
when they belong to the same package. To keep SUSFS mount hiding coherent, the
hookless layer normalizes package-local helpers onto the package's visible main
namespace.

The current flow is:

1. SUSFS receives the KSU setuid callback.
2. Work is deferred through task work so the logic does not run in atomic
   kprobe context.
3. The main package process is cached as a package anchor.
4. Same-package helpers such as `:tools` or isolated children try to join the
   anchor's mount namespace.
5. `ksu_join_task_mount_ns()` duplicates `current->fs` with
   `unshare_fs_struct()` when needed so `setns(CLONE_NEWNS)` satisfies the
   5.4 kernel `mntns_install()` requirement.

Namespace identity readback is normalized separately through the KSU-owned
`mntns_get()` kretprobe so `/proc/*/ns/mnt`, `readlink()`, and namespace-fd
identity stay aligned with the visible namespace.

### Proc/mm hiding

`sus_map` is implemented through runtime proc/mm compatibility hooks rather than
through main-kernel patches.

Today the live hookless coverage is intentionally limited to:

- `/proc/*/maps`
- `/proc/*/smaps`
- `/proc/*/fd` readlink targets
- `/proc/*/map_files` readlink targets

This masks `sus_map` backing paths from link-target scanners while keeping the
underlying proc fd/map_files symlinks followable for Zygisk-style loader and
module handoff. The previously unstable direct map_files lookup/revalidate and
`/proc/<pid>/mem` paths remain untouched.

### Cmdline, uname, AVC, and property hygiene

Other SUSFS-adjacent behaviors are handled inside KernelSU:

- `/proc/cmdline` spoofing swaps the KSU-visible `saved_command_line` pointer
  instead of patching proc entry source
- `uname` spoofing reuses a KSU syscall hook instead of patching
  `kernel/sys.c`
- AVC spoofing reuses the existing KSU AVC path
- delayed property hygiene restores BRENE-style resetprop coherence from a
  kernel-owned post-boot retry window

## Feature Coverage

### Implemented

The current branch covers the following SUSFS-facing operations inside
`KernelSU-Next`:

- `add_sus_path`
- `add_sus_path_loop`
- `add_open_redirect`
- `hide_sus_mnts_for_non_su_procs`
- `add_sus_kstat`
- `update_sus_kstat`
- `add_sus_kstat_statically`
- `add_sus_map`
- `set_cmdline_or_bootconfig`
- `set_uname`
- `enable_avc_log_spoofing`
- compat reporting for `show_version`, `show_variant`, and
  `show_enabled_features`
- delayed property hygiene for BRENE-style resetprop cleanup

There is also a built-in default hide for
`/product/overlay/LineageSDKOverlaySM8350.apk`, seeded from inside SUSFS init
and retried again from the boot-complete path so late-mounted overlays are
still covered.

### Partial or intentionally narrow

- `sus_map` direct `map_files` lookup/revalidate and `/proc/<pid>/mem` hiding
  remain disabled pending narrower live validation
- `/proc/bootconfig` is not implemented on this Lisa 5.4 target because the
  kernel exposes `/proc/cmdline` but not `/proc/bootconfig`
- procfs rewriting is scoped to app and isolated readers that are already under
  KSU's umount policy

### Not part of this branch

- `CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS`

That knob is symbol-hardening work, not required for the hookless migration.

## Safety Rules

The hookless layer is intentionally conservative in a few places:

- root and zygote-side readers keep the stock procfs path
- SUSFS compat work is deferred out of atomic kprobe context
- package-helper namespace joins only apply to app or isolated processes that
  are already eligible for the KSU mount-hide view

This is important for keeping ReZygisk, TreatWheel, manager state persistence,
and module-side behavior stable.

## Verified Status

The current live-device validation on Lisa confirms:

- TNG helper mount drift is fixed
- the package main process and `:tools` helper now converge on the same mount
  namespace
- the kernel-side path no longer relies on main-kernel manual hooks
- the earlier BRENE `sus_map` atomic-context crash path is fixed by deferring
  compat work through task work

One concrete live replay after the `unshare_fs_struct()` fix showed:

- main process `my.com.tngdigital.ewallet` in `mnt:[4026534906]`
- helper process `my.com.tngdigital.ewallet:tools` also in
  `mnt:[4026534906]`

That replay replaced the earlier failing behavior where the helper stayed in a
different namespace and `setns(CLONE_NEWNS)` returned `-EINVAL` because the
process still shared its `fs_struct`.

## Configuration

Enable SUSFS hookless with:

- `CONFIG_KSU_KPROBES_HOOK=y`
- `CONFIG_KSU_KPROBES_SUSFS=y`
- `CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y` for `open_redirect` and the direct
  ARM64 kstat/mount runtime paths

The hookless path is designed to work with kernel-side changes only. It does
not require a separate manager-side migration to function.

## Kernel Compatibility

The SUSFS build does not infer MM and VFS capabilities from
`LINUX_VERSION_CODE` alone. Android vendor kernels often backport only part of
a newer subsystem, so `kernel/Kbuild` probes the source tree and selects the
matching implementation at compile time.

The compatibility layer covers:

- maple-tree and legacy linked-list VMA traversal
- `mmap_lock` and legacy `mmap_sem` locking
- modern `mm_walk_ops` and legacy embedded `mm_walk` callbacks
- generic-radix and flex-array storage for `/proc/<pid>/map_files`
- kernels with and without VMA anonymous names and 16K page-size padding
- both `iterate_shared` and legacy `iterate` directory operations
- pre-4.11 VFS `getattr` and kernels without `smaps_rollup`
- const, mutable, and legacy raw-argument ARM64 syscall-table entries
- hlist-based and older list-based LSM hook chains
- kernels with and without Android's `__nocfi` compiler annotation

Stock-style ARM64 4.19 and 5.4 trees are the primary legacy compatibility
targets. The 4.19 lower bound matches the proven range of the branch-link work
used as a design reference. This implementation keeps KernelSU-Next's
dispatcher and hosts its ARM64 callsite scanner entirely inside the KSU runtime.

Linux 4.9 is the lower best-effort source boundary. Its linked-list VMAs, old
page walker, flex arrays, raw-argument syscall table, and list-based LSM hooks
have compatibility paths, but this combination is not live-device validated.
The target must still provide Kprobes, kretprobes, syscall tracepoints, procfs,
and the Android vendor interfaces required by `CONFIG_KSU_KPROBES_HOOK`.

Linux 3.10 and 3.18 are not supported by hookless SUSFS. They predate several
required VFS and KernelSU hook interfaces; supporting them would amount to a
separate infrastructure backport rather than a maintainable compatibility
layer.

## Summary

`susfs-hookless` keeps SUSFS inside `KernelSU-Next`, replaces the old broad
main-kernel patch set with a mix of:

- NoMount-style per-object VFS hijacking for path features
- KSU-owned runtime instrumentation for proc/mm and namespace surfaces

This is the intended long-term maintenance model for the Lisa target:

- no generic-kernel manual hooks
- no SUSFS files spread through the main tree
- all feature work isolated inside `KernelSU-Next`
