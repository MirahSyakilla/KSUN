# PHASE 19 — GENERATED RUNTIME DATA OBJECT, GUARDED TWO-STAGE COORDINATOR,
# MOUNT/NOMOUNT INTEGRITY VALIDATION

**Branch:** `susfs+nomount-hookless` · base `9685c60f`
**Verdict:** **PASS WITH DOCUMENTED LIMITATIONS**
**Kernel:** `5.4.302-MeowKernel-v2.03-e380c91` (generated-manifest profile, flashed, reboot-stable)
**Push:** none performed

---

## 1. Executive Summary

Phase 19 completed both tracks:

**Track A** — the generated runtime data object now exists, validates at
boot, and is consumed by the runtime with fail-closed semantics. On the
reference build with `CONFIG_KSU_BL_GENERATED=y`, the boot log reads:

```
branch_link: generated manifest accepted (schema 3, routes 23, callers 168, nonce 0x19a5b41b)
```

with `records=162` and every family READY — **identical to the Phase 18
hand-maintained baseline**. The bootstrap profile (zero-row object) links,
boots, and fails closed. The guarded two-stage coordinator skeleton
(`Makefile.postlink` + `bl-coordinator.sh`) is committed with the bounded
fixed-point and READY-stamp design; the end-to-end generation used the
analyzer directly in this phase (documented limitation below).

**Track B** — the mount/NoMount integrity audit is complete:

- `vfs_kern_mount` exclusion **re-evaluated from actual control flow** and
  classified **SAFE_TO_EXCLUDE** with config-scoped evidence.
- Complete mount-table/dispatch inventory (20+ paths) with per-path coverage
  classification; **one actionable potential leak found**
  (`name_to_handle_at` mnt_id — kernel-side, documented design boundary).
- New permanent **NoMount leakage suite: 20 PASS / 0 FAIL** on device.
- New permanent **NoMount latency benchmark**: matched A–E cases, root and
  app-UID variants, full percentile reporting.

Device validation: full suite **99 PASS / 0 FAIL / 10 SKIP** (identical to
the Phase 18 baseline) **plus** the new leak suite 20/0, reboot-stable.

## 2. Delegated-Agent Findings

| Agent | Key conclusion |
|---|---|
| A — data object | Two-object design (bootstrap zero-row + census-derived final); extern symbol consumption; 9-point boot validation; names/IDs only, no absolute addresses |
| B — parity | Runtime/policy/generated in lockstep; parity test has 4 blind spots (legacy-exec rows, unknown macros, targets/hooks/groups, duplicate tolerance) — hardening queued for the coordinator integration phase |
| C — recursion | Two wrapper classes (slot wrappers vs full replacements); all KSU-internal callers safe; one bounded chain (`getname_kernel` → `build_path_from_dfd` → `ksu_do_dpath` → slot) terminates at depth 5 with no cycle; 6 invariants + 6 test designs recorded |
| D — two-stage Kbuild | `ARCH_POSTLINK` runs inside `cmd_link-vmlinux` so a relink completes before the parent Image objcopy; module-postlink no-op guard mandatory; nonce-based stage markers; bounded 2-iteration fixed point |
| E/F — identity & attacks | Transaction directory + nonce + READY; payload digest as the master invariant; 18-row attack matrix with exact detection points; 3 analyzer gaps to close (`analyzer_sha256`, mandatory `--image` in stage 2, `EXIT_IDENTITY=16`) |
| G — final image | Final-image analysis must be independent of the generator; payload digest comparison is the fixed-point criterion |
| H — 4.19 | Consumer architecture portable; no new APIs; runtime support still not claimed |
| I — `vfs_kern_mount` | Traced to `fc_mount` → `vfs_create_mount`; on this build its callers are boot-rootfs, `MNT_INTERNAL`/`MNT_NS_INTERNAL` pins, and tracefs automount — none app-reachable or hide-worthy; NFS/BTRFS/CIFS/devtmpfs **not built** (config-verified); the SUSFS kretprobe fallback is dead code (KPROBES=n) |
| J — mount inventory | 20+ paths inventoried; A1–A7 covered by the fops/show patches; D4 `name_to_handle_at` = potential leak; G2 `mntns_install` = intentionally excluded/needs-validation |
| K — leakage matrix | 50+ probes designed with expected semantics cited from `core.c`/`procfs.c`; gated-UID observation constraint identified |
| L — benchmark | `stat()` crosses all three NoMount layers; nm CLI as the proven toggle; A–E cases + F–I workloads; warm/cold separation |
| M/N — races & security | Race matrix H1–H8; security review folded into the identity design |

## 3. `vfs_kern_mount` Final Classification

**SAFE_TO_EXCLUDE** (evidence-backed, replacing the Phase 18 inference):

1. `vfs_kern_mount()` → `fs_context_for_mount()` → `fc_mount()` → `vfs_create_mount()` — the wrapped function is the actual creator.
2. On this build its only callers are: `init_mount_tree` (boot rootfs), `kern_mount` (SB_KERNMOUNT → `MNT_NS_INTERNAL`, never grafted into any mount namespace), `simple_pin_fs` (MNT_INTERNAL), and `vfs_submount` (tracefs automount — legitimately visible).
3. NFS/BTRFS/CIFS/devtmpfs are **not built** (`out/.config` verified); overlayfs uses the sget path (zero `vfs_kern_mount` references); `fuse_dentry_automount` calls `vfs_create_mount` directly and is already a covered row.
4. No hide-worthy mount (KSU-domain, boot-window) flows through `vfs_kern_mount`; the reporting-time SUSFS filter is flag-based and cannot rescue unflagged mounts, but no hide-worthy mount is unflagged.
5. Re-audit required if NFS/BTRFS/CIFS/devtmpfs are ever enabled (encoded in the runtime comment and policy note).

## 4. Generated Runtime-Data Design (implemented)

- `kernel/hook/arm64/bl_manifest_schema.h` — schema v3 contract; classification enum and capacity constants shared with the runtime.
- `kernel/hook/arm64/bl_manifest.c` — boot validator (magic, schema, policy revision, nonce pairing, route count, slice bounds, caller uniqueness within route, classification vocabulary, min_sites semantics, width ≤ 0xFFFF, budget ≤ 176) + accessors.
- `branch_link_hook.c` — `ksu_branch_link_patch_init()` gated on the validated manifest under `CONFIG_KSU_BL_GENERATED`; bootstrap objects fail closed.
- Analyzer `--output-ids` / `--output-object` / `--bootstrap` emitters.

## 5. Two-Stage Design (committed; exercise path documented)

`kernel/build/Makefile.postlink` (module-postlink no-op guard, stage=final re-entry guard) + `kernel/build/bl-coordinator.sh` (stage 0→READY, bounded fixed point, fail-closed cleanup). The end-to-end generation in this phase used the analyzer directly (bootstrap build → census → final object → relink), which is the same stage sequence without the recursive-make plumbing; wiring the coordinator into `setup.sh` and exercising the recursive relink is the remaining integration step.

## 6–8. Stale Protection, Final-Image Verification, Fixed Point

- Nonce binds ids.h ↔ data object; the boot validator rejects mismatched pairs.
- Payload digest (`7727a120c0d59204…`) is the fixed-point criterion: the final-image census must equal the stage-1 census.
- Final-image verification performed independently (analyzer run against the final vmlinux/System.map with the full identity stamp) — result: `OK: 22 routes, 162 sites`, same payload.

## 9. Runtime Policy/Generated Parity

Phase 18 parity test still passes (the bootstrap arrays remain the non-generated profile's data). The generated profile's rows were verified against the policy by the analyzer's own policy-join (exit 0) and by the device census (162 records identical).

## 10. KSU-Internal Recursion

All KSU-internal callers verified safe (Agent C): slot wrappers call the original through fn_slots; full replacements contain zero BLs to their targets; the one deep chain terminates without a cycle. Invariants recorded for the generated-data contract.

## 11–13. Mount Inventory & vfs_kern_mount

See sections 3 and the Agent J inventory (20+ paths; covered / intentionally-excluded / not-relevant / potential-leak classifications). `name_to_handle_at` mnt_id is the one actionable potential leak — kernel-side syscall, not coverable hooklessly without a new interception point; documented as a design boundary.

## 14–19. NoMount Leakage, Namespace, Bind/Propagation, Overlay, Mountinfo, Races, Latency

**Leakage suite results (device, 20/20 PASS):** exact/recursive redirect content, canonicalization forms, synthetic identity for virtual-only objects, cross-filesystem statfs virtualization, fd readlink d_path rewrite, readdir merge, private-backend root control, mountinfo backend-path non-exposure, negative controls, lifecycle (add/del/re-add/clear-all/toggle-loop), concurrency (rule churn + mount churn).

**Documented design boundaries** (not leaks; recorded in the report and suite comments): symlink-body escape (name-scope policy limit), post-boot mounts unmarked (window gate), overlay mount-option strings, root exclusions.

**Latency benchmark (stat, /data f2fs, CPU-pinned, n=1000):**

| Case | Root mean | Δ vs A | App-UID mean | Δ vs A |
|---|---:|---:|---:|---:|
| A disabled | 4711.9 ns | — | 5570.3 ns | — |
| B enabled-no-match | 6014.7 ns | +27.6% | — | — |
| C match | 5616 ns | +19.2% | 6696.2 ns | +20.1% |
| D hot match | 5556.8 ns | +17.9% | — | — |
| E hot non-match | 5958.9 ns | +26.5% | 6125.5 ns | +9.9% |

Notable: an exact-rule hit (C/D) is **cheaper** than a miss (B/E) because the miss path walks ancestor prefixes. App-UID match cost includes the access-scope allocation + task_work. Full percentile data in `validation/audit/phase19/` logs.

## 20–26. Build, Flash, Reboot, Suite

```text
build:    -j1, CONFIG_KSU_BL_GENERATED=y, zero-probe config verified
package:  MeowKernel_v2.03-e380c91.zip md5 406d959b984b27ca7db8e3db58530fe6
flash:    established magiskboot workflow; block md5 verified
boot:     ~35 s; generated manifest accepted (schema 3, routes 23,
          callers 168, nonce 0x19a5b41b); records=162; all families READY
suite:    99 PASS / 0 FAIL / 10 SKIP (identical to Phase 18 baseline)
          + NoMount leak suite 20 PASS / 0 FAIL
reboot:   stable; identical manifest acceptance and records
```

## 27–28. Limitations & 4.19

Limitations: (1) coordinator recursive-relink not yet exercised end-to-end via `make` (analyzer-driven generation used instead); (2) parity-test blind spots (legacy-exec rows, unknown macros, target/hook/group metadata) queued for hardening; (3) `name_to_handle_at` mnt_id documented boundary; (4) analyzer gaps A–C from Agent E pending. 4.19: architecture portable, no runtime support claimed.

## 29–30. Files Changed & Commits

```text
506eebd6 tests: add NoMount metamodule leakage suite and latency benchmark
a0a5b41b branch-link: generated manifest data object + guarded two-stage coordinator
e7278a35 branch-link: generated manifest consumed at runtime; bootstrap profile
```

Key files: `bl_manifest_schema.h`, `bl_manifest.c`, `branch_link_hook.{c,h}`, `kernel/Kconfig`, `kernel/Kbuild`, `bl_analyzer_v2.py`, `bl-coordinator.sh`, `Makefile.postlink`, `test_nomount_leak.sh`, `nomount_bench.c`.

## 31. Final Verdict

```text
PASS WITH DOCUMENTED LIMITATIONS
```

Worktree: clean. **NO PUSH PERFORMED.**
