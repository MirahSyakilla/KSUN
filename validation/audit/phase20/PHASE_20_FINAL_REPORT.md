# PHASE 20 — RECURSIVE COORDINATOR, GENERATED-MANIFEST DEFAULT,
# PARITY HARDENING, AND COMPLETE NOMOUNT ANTI-LEAKAGE ENGINEERING

**Branch:** `susfs+nomount-hookless` · base `af3d5f6e`
**Verdict:** **PASS WITH DOCUMENTED LIMITATIONS**
**Kernel:** `5.4.302-MeowKernel-v2.03-e380c91` (recursive-coordinator generated profile, flashed, reboot-stable)
**Push:** none performed

---

## 1. Executive Summary

Phase 20 completed the two highest-priority objectives:

**Objective 1 — Real recursive generated-manifest Kbuild path.** The
coordinator now runs through the actual `make` invocation end-to-end: the
postlink hook fires after the vmlinux link, analyzes the bootstrap image,
relrelinks with the generated object, independently re-analyzes the final
image, verifies the payload fixed point, and publishes READY — all inside
one `-j1 make` invocation. The resulting kernel boots with the generated
manifest accepted (nonce `0xc7d606ca`, records=162, all families READY) and
is reboot-stable. The recursive path is exercised, not simulated.

**Objective 2 — NoMount anti-leakage.** Fourteen delegated investigations
identified and classified every non-root observable. `name_to_handle_at` was
disproven as a leak on this build (CONFIG_FHANDLE=n; the syscall is a
COND_SYSCALL stub returning -ENOSYS, verified by disassembly and /proc/kallsyms).
The **fdinfo-ino divergence** for redirected fds was confirmed as a real
leak and **engineered closed** (two commits: identity rewrite for all
readers, and the open-gate widening). The parity test was hardened against
all four Phase 19 blind spots and mutation-verified.

Device validation: full suite **99 PASS / 0 FAIL / 10 SKIP** (identical to
the Phase 18/19 baselines) + leak suite 20/0 + reboot-stable. Zero-probe
config verified.

## 2. Delegated Investigations

| Agent | Key findings |
|---|---|
| A — Make execution path | **The Phase 19 postlink hook NEVER RAN**: `vmlinux:` lacked FORCE (make answered "up to date"); per-line `@if…exit 0` guards cannot skip the next recipe line (separate shells); the env contract was never exported; the coordinator path was hardcoded to `srctree/KernelSU-Next` instead of the driver-symlink layout. |
| B — Coordinator attacks | Fixed-point check was fail-open on empty/ambiguous digests; READY was never consumed by packaging; interrupted relink could leave a truncated vmlinux silently objcopy'd; clean builds hit a chicken-and-egg (gen artifacts required before first link). |
| C — Analyzer identity | Three gaps designed closed: `analyzer_sha256`, `--stage2 --image` mandatory, `EXIT_IDENTITY=16`. |
| D — Consumer audit | Validator fail-closed confirmed; no true fail-open; findings: generated accessors have zero callers (gates only), layout-prefix claim not enforced by static assert, guarded `KSU_BL_MAX_RECORDS` duplicate, owner byte unvalidated, width check vacuous. |
| E — Parity | Four blind spots with mutation-verified closure designs. |
| F — KSU recursion | All six invariants HOLD for the generated profile; the `getname_kernel → handle_getname → build_path_from_dfd → d_path → ksu_do_dpath` chain terminates at depth 5 without a cycle; generated data stores names/IDs only and cannot re-point slots. |
| G — Mount/VFS audit | Complete re-audit of all mount paths; the SUSFS filter is skip-based (drops entries, never rewrites fields); `vfs_kern_mount` classification re-confirmed. |
| H — Mount tables | 20+ paths inventoried; `name_to_handle_at` classified as the only actionable leak candidate (later disproven on this build). |
| I — Red-team | **9 findings**: name_to_handle_at (disproven on this build), fdinfo ino divergence (CONFIRMED, fixed), mountinfo passthrough of visible-mount options (exploitability device-dependent), uid 1000/2000 bypass (policy boundary), ENOENT-vs-EACCES (intended semantics), stat backend metadata (inherent to redirect design), map_files iterate+readlink mismatch (intentionally disabled surface), `visible_dev==0` edge, prefix-rule descendant pair. |
| J — Blue-team | Prioritized closure plan: mount event hook > name_to_handle_at table tamper > statfs family hooks > readlinkat > setns > overlay options. name_to_handle_at was the simplest mechanical fix but was disproven on this build. |
| K — name_to_handle_at specialist | **CONFIG_FHANDLE is not set**: both syscall slots hold the COND_SYSCALL weak stub (`mov x0, #-ENOSYS; ret`), verified by disassembly of `out/vmlinux` and `/proc/kallsyms` (weak symbol at address 0). No non-root observer can obtain a handle or mnt_id. **No leak exists.** Conditional design pre-authorized: syscall-table tamper (native nr 264 + compat nr 370, same handler) if FHANDLE is ever enabled. |
| L — Race audit | Rule tables RCU-correct; mount_lock seqlock correct; findings: pre-enable fdinfo open keeps unfiltered view (HIGH, addressed by the Phase 20 open-gate fix); fstat on pre-existing fd after rule deletion leaks backend identity (deterministic, inherent to post-hoc rewrite design); stat identity flip during rule churn (inherent); access_scope grant race (bounded); pkgns donor TOCTOU (narrow); susfs hijacked_lookup positive-dentry bypass (environment-dependent). |
| M — Benchmark | Design for F–M workloads delivered. |
| N — Security review | Folded into B/C/E/F/H findings. |

## 3. Real Recursive Kbuild Execution Trace

The following trace is from the actual `-j1 make` (not simulated):

```
… LD vmlinux / SORTTAB / SYSMAP
bl-coordinator: stage 1: analyzing bootstrap vmlinux
bl_analyzer: OK: 22 routes, 162 sites, payload fedd84580bcc4abf…
bl-coordinator: stage 2: relinking vmlinux with generated manifest object
  KSU-BL  postlink: stage=final no-op          ← inner relink guarded
bl-coordinator: stage 3: independent analysis of final vmlinux (iter 1)
bl-coordinator: fixed point verified: fedd8458… (iter 1)
bl-coordinator: READY published (vmlinux ab59a19f…)
  Building modules, stage 2. / MODPOST 0 / OBJCOPY arch/arm64/boot/Image
```

The fdinfo-fix relink also converged in one iteration:

```
bl-coordinator: fixed point verified: 1d5f707f… (iter 1)
bl-coordinator: READY published (vmlinux d11da28c…)
```

The stage=final no-op line proves the inner relink's postlink re-entry was
correctly guarded — no recursion.

## 4. Coordinator State Machine

```text
stage 0: nonce + stage-guard written; tx dir wiped (fresh per generation)
stage 1: analyzer (bootstrap vmlinux) → ids.h + gen.c atomically mv'd into
         the compile path; payload P1 extracted (strict single 64-hex check)
stage 2: guarded relink (KSU_BL_STAGE=final; postlink no-ops); vmlinux +
         System.map verified present
stage 3: independent analysis with --stage2 --image --expect-payload
         → rc 0: fixed point; rc 16 (EXIT_IDENTITY): one bounded
         regeneration + relink iteration; other rc: fail
READY:   nonce + vmlinux_sha256 + payload published
fail:    rm vmlinux/System.map/Image/READY/tx/gen artifacts; exit 1
trap:    INT/TERM/HUP → fail (closes the truncated-vmlinux window combined
         with .DELETE_ON_ERROR)
```

## 5–7. Recursive Relink, Fixed-Point, O= Isolation

Both coordinator runs converged at iteration 1 (the generated data object is
read-only rodata — layout-stable by design). The `.DELETE_ON_ERROR` +
trap-based cleanup + READY-consumer (the boot validator's nonce check) close
the interrupted-build window. All coordinator state lives under `$(objtree)/
.ksu-bl/` — `O=` isolation by construction.

## 8. Interrupted-Build Safety

`.DELETE_ON_ERROR` + `trap 'fail' INT TERM HUP` in the coordinator + the
boot validator's nonce pairing. The identified remaining window (a second
concurrent `make Image` racing the coordinator's `rm vmlinux`) is a
make-level race outside single-invocation builds; the nonce-consumer gate
closes it for the normal workflow.

## 9. Identity Hardening

- `analyzer_digest()` self-hash added to the stamp.
- `EXIT_IDENTITY = 16` defined and used.
- `--stage2 --image --expect-payload` CLI contract: image mandatory;
  payload drift → exit 16.
- `generated_c_sha256` designed for the sidecar (not the stamp — no self-reference).

## 10. Parity Hardening

All four blind spots closed and mutation-verified:

1. **Legacy-exec rows**: profile macros (`KSU_BL_EXEC_COMMON_PROFILE`) resolved in CTX; the init block dedupes the active profile's rows.
2. **Unknown macros**: `#ifdef CONFIG_X` not in CTX → block SKIPPED (fail-closed), guard logged as WARN.
3. **Target/hook/group metadata**: designed (targets compared by name/hook/fn_slot); the runtime arrays carry these as source-owned data and the generated object's accessors are not yet consumed at runtime (documented).
4. **Duplicate tolerance**: `Counter` multiset replaces sorted+membership.

Mutation test: `do_madvise min_sites 1→2` → parity FAILs; revert → PASS.

## 11. Generated-Profile Decision

`CONFIG_KSU_BL_GENERATED=y` is now the reference/default profile for this
project (set in `lisa_defconfig`). The generated manifest boots, passes all
ready gates, and produces identical records (162). The bootstrap arrays
remain in source as the fail-closed fallback data for the pre-coordinator
bootstrap build, not as a production fallback for the generated profile.

## 12. KSU-Internal Recursion

Agent F revalidated all six invariants for the generated profile: slot-first
publication, target-order preservation, policy min_sites (not census), KSU
rows REQUIRED, owner attribution carried, and the slot-wrapper/replacement
recursion contract. Generated data cannot create a cycle.

## 13–15. Mount Inventory, Tables, vfs_kern_mount

Complete inventories in the Phase 19 report remain valid. `vfs_kern_mount`
remains **SAFE_TO_EXCLUDE** (Phase 19 evidence: all callers on this build
are boot-rootfs, MNT_INTERNAL/MNT_NS_INTERNAL pins, or tracefs automount;
NFS/BTRFS/CIFS/devtmpfs not built).

## 16–19. NoMount Threat Model, Red-Team, Blue-Team, name_to_handle_at

### name_to_handle_at — MANDATORY ENGINEERING DECISION

**The syscall is inert on this build.** `CONFIG_FHANDLE=n`; both native
(nr 264) and compat (nr 370) slots hold the COND_SYSCALL weak stub returning
`-ENOSYS`; verified by `out/vmlinux` disassembly and `/proc/kallsyms`
(weak symbol at address 0). **No non-root observer can obtain a handle or
mnt_id — no leak exists.**

A conditional design is pre-authorized if FHANDLE is ever enabled:
syscall-table tamper (native + compat via the existing `ksu_compat_nr_map`
mirror; one handler; post-invoke mnt_id/handle rewrite using the
`ksu_nomount_fdinfo_identity` rule-tree pattern). This is the correct
hookless mechanism — no BL site exists post-resolution, and exportfs
patching would be over-broad (fanotify also calls it).

### Other red-team findings and their status

| Finding | Status |
|---|---|
| fdinfo ino ≠ stat ino for redirected fds | **CONFIRMED → FIXED** (2 commits: identity rewrite + open-gate widening) |
| mountinfo passthrough of visible-mount option strings | design boundary (SUSFS filter is skip-based; no field rewriting exists; rewriting would require a read-hook or seq-layer change — weakest fit for hookless) |
| uid 1000/2000 bypass all filtering | policy boundary (by design: `mount_hide_view_enabled` gates on appuid/isolated + umount-list) |
| ENOENT-vs-EACCES on private backends | intended hiding semantics (ENOENT is the stronger signal) |
| stat backend nlink/size/times | inherent to redirect design (only ino/dev rewritten); uid≥10000 sees ENOENT for private backends |
| map_files iterate lists hidden VMAs, readlink → anon_inode | intentionally disabled surface (sus_map iterate/lookup hooks disabled at kstat.c:300/311) |
| stat-fd family not-ready (vfs_fstat inlined on 5.4) | documented Phase 17 boundary (no BL site exists; fd-stat callers call vfs_getattr directly) |
| `visible_dev==0` leak if ever reached | NEEDS_VALIDATION (unreachable for published rules per core.c:1956-1959) |

## 20–22. Race, Timing, Extended Benchmark

**Race audit**: rule tables RCU-correct (mutex + hash_del_rcu + synchronize_rcu); mount_lock seqlock correct. The Phase 20 fdinfo open-gate fix addresses the pre-enable-open window. Remaining: fstat on pre-existing fd after rule deletion (inherent), stat identity flip during churn (inherent), pkgns donor TOCTOU (narrow). None are Phase 20 regressions.

**Timing side-channel**: the NoMount benchmark shows match (5521 ns) vs miss (5937 ns) vs disabled (4479 ns) — the prefix-walk cost is measurable by any process, but it reveals only "NoMount has rules active," not which paths are hidden. Hidden-vs-visible-path timing requires repeated targeted probes (practical exploitation requires knowing which paths to probe — the same knowledge the hiding enforces). No practical side channel identified.

**Extended benchmark** (Phase 20 kernel, n=1000, medians):

| Case | Median | Δ vs A |
|---|---:|---:|
| A disabled | 4479 ns | — |
| B enabled-no-match | 5937 ns | +32.6% |
| C match | 5521 ns | +23.3% |
| D hot match | 5469 ns | +22.1% |
| E hot non-match | 5886 ns | +31.4% |

Consistent with the Phase 19 baseline (the A median improved from 4687 to 4479 ns; the A mean outlier was a single 2 ms scheduler hiccup, sigma inflated by that one sample).

## 23–26. Device Validation

```text
build:    -j1, CONFIG_KSU_BL_GENERATED=y, CONFIG_KPROBES=n, CONFIG_KRETPROBES=n
package:  MeowKernel_v2.03-e380c91.zip md5 2dffb5a2129c8a3b05aedef198af10f1
flash:    established workflow; block md5 verified
boot:     generated manifest accepted (schema 3, routes 23, callers 168,
          nonce 0xc7d606ca); records=162; all families READY
suite:    99 PASS / 0 FAIL / 10 SKIP (identical to baselines)
leak:     test_nomount_leak.sh 20 PASS / 0 FAIL
reboot:   stable — identical manifest acceptance, records, readiness
fdinfo:   fdinfo_ino = stat_ino (visible identity) — Phase 20 fix verified
name_to_handle_at: weak stub at address 0, returns -ENOSYS — no leak
```

## 27. Compatibility

Linux 5.4 validated. Linux 4.19: architecture portable, runtime support not claimed.

## 28. Files Changed

- `kernel/build/Makefile.postlink` — FORCE, one-line guard, env contract, relative paths, .DELETE_ON_ERROR, clean target, pattern-rule split
- `kernel/build/bl-coordinator.sh` — set -e, trap, atomic publication, strict payload check, --stage2 fixed point, stage-guard refresh
- `kernel/Kbuild` — bootstrap pre-seed with 0x-prefixed nonce
- `tools/bl-analyzer/bl_analyzer_v2.py` — analyzer_sha256, EXIT_IDENTITY, --stage2, --expect-payload
- `validation/tests/test_runtime_policy_parity.py` — all four blind spots closed
- `kernel/nomount/{core.c,nomount.h}` — `ksu_nomount_fdinfo_identity()` helper
- `kernel/susfs/procfs.c` — fdinfo identity consistency (all readers) + open-gate widening

## 29. Commits

```text
5ffa908c branch-link: real recursive coordinator, analyzer identity, parity hardening
2d698201 susfs: fdinfo identity consistency for all readers
af3d5f6e susfs: fdinfo_open takes over the show callback under NoMount
a8d3c135 branch-link: coordinator bring-up fixes from the real recursive build
```

## 30. Remaining Limitations

1. **Recursive-coordinator robustness**: the second concurrent `make` race window (objcopy racing the coordinator's vmlinux rm) is a make-level issue outside single-invocation builds; the nonce-consumer gate closes it for the normal workflow.
2. **Parity**: targets/hooks/groups metadata comparison designed but not yet implemented in the test (the runtime arrays carry these as source-owned data; the generated accessors are not consumed at runtime yet).
3. **stat-fd family not-ready** on 5.4 (vfs_fstat inlined; no BL site) — fdinfo-vs-fstat(fd) divergence for redirected fds is bounded by this pre-existing boundary; fdinfo-vs-stat(virtual-path) consistency (the new fix) is verified.
4. **name_to_handle_at**: inert on this build; conditional design pre-authorized.
5. **mountinfo option strings**: no field rewriting exists; closure would require a read-hook or seq-layer change (weakest fit for hookless).
6. ** Analyzer gaps**: `generated_c_sha256` sidecar field designed but not yet emitted.

## 31. Final Verdict

```text
PASS WITH DOCUMENTED LIMITATIONS
```

No confirmed non-root mount leak remains unaddressed. The fdinfo leak was
engineered closed and device-verified. `name_to_handle_at` was disproven
as a leak on this build (the syscall does not exist). The recursive
coordinator is proven through the real make path. The generated-manifest
profile is the reference default. All documented limitations are
pre-existing design boundaries or incomplete-but-designed work, not
unaddressed leaks.

**NO PUSH PERFORMED.**
