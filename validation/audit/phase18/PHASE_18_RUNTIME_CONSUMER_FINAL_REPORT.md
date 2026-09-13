# PHASE 18 — HARDEN RUNTIME CONSUMER & RESOLVE CENSUS GAPS

**Branch:** `susfs+nomount-hookless` · base `7ccd0f68`
**Verdict:** **PASS WITH DOCUMENTED LIMITATIONS**
**Kernel:** `5.4.302-MeowKernel-v2.03-e380c91` (built `-j1`, flashed, device-validated)
**Push:** none performed

---

## 1. Verdict

**PASS WITH DOCUMENTED LIMITATIONS.**

Implemented and device-validated:

1. **Runtime slot-rollback fix** in `ksu_bl_record_patch_routes()` — the
   pre-existing fn_slot rollback bug, confirmed by delegated audit.
2. **Explicit decisions on all six Phase 17 acknowledged gaps** — six ADOPTED,
   one (`vfs_kern_mount`) EXPLICITLY OUT OF PROFILE. No indefinite
   `acknowledged` state remains.
3. **Capacity**: `KSU_BL_MAX_RECORDS` 160 → 176, policy `MAX_RECORDS` in
   lockstep.
4. **Permanent runtime↔policy parity test** — file-wide-preprocessor-aware
   parser proving runtime arrays == policy rows with zero drift.
5. **Full kernel build (-j1), package, flash of the fresh image, and the
   established device validation suite: 99 PASS / 0 FAIL / 10 SKIP**, plus
   reboot stability.

Limitations: the generated-data *runtime* consumer switch (replacing the C
arrays with a generated data object at compile time) is deliberately deferred
to Phase 19; this phase proves semantic equivalence offline and on-device
instead. The two-stage Kbuild coordinator remains future work.

## 2. Delegated Investigations

| Agent | Conclusion |
|---|---|
| A — Slot-rollback bug | Real. `ksu_bl_record_patch_routes()` binds the candidate fn_slot before patching; a positive-but-sub-`min_sites` candidate leaves orphan records patched to a non-preferred wrapper with the slot still bound; a failed route leaves the last candidate's slot bound forever. **Dead on the 5.4 lisa profile** (no route has 2+ enabled targets AND a `min_sites>1` caller), but latent for other shapes. Minimal fix identified with exact insertion points. |
| B — Consumer contract | Policy↔runtime is a 1:1 zero-loss mapping across all 23 routes (field-for-field: classification, min_sites, width, conditions, groups). Minimal consumer change is data substitution; engines unchanged. |
| C — Generated representation | Phase 17 C rows are struct-exact and suitable as a controlled consumer input; width elision (0 ≡ 1024) is lossless; `owner`/`acknowledged` are audit-only fields. Flagged a possible width-reconciliation issue which this phase **disproved by direct binary measurement** (all disputed sites < 0x400; no in-tree row fails on lisa). |
| D — Six gaps | ADOPT gaps 1–6 (old symbol-scoped probes covered all of them; existing wrappers semantically correct; no new wrappers needed). OUT_OF_PROFILE gap 7 (`vfs_kern_mount`): no observable benefit, LTO-fragile readiness dependency for the whole atomic mount trio. |
| E — Record budget | 160 was sufficient for the reference image (155) but had no margin: adoption → 161, worst-case optionals ≈ 160, multi-site LTO growth +6–10. **Recommend 176** (adopted); +640 B `.bss`. Route-specific budgets rejected (breaks global rollback pool). |
| F — Adversarial consumer review | Validation checklist for generated data (schema/revision/uniqueness/bounds/budget/grouping) split into compile-time vs boot-time checks; per-site vs per-caller mismatch flagged — the generated rows must carry the **policy** `min_sites`, not census counts. Adopted into the parity test design. |
| G — 4.19 compatibility | Consumer architecture is common across 4.19/5.4: positional initializers, `READ_ONCE`/`WRITE_ONCE`, `stop_machine`, and nofault reads (existing compat shim) all have 4.19 equivalents. The slot fix uses no 5.x-only API. **No runtime support claimed** — static analysis only. |
| H — Regression audit | Zero drift from Phase 12/13 historical expectations: all families, classifications, widths, arming guards, and record accounting intact. Phase 17/18 code had not touched the runtime. Dead Phase 13 discovery code confirmed uninvoked. |

## 3. Six-Gap Decisions

| # | Gap | Decision | Justification |
|---|---|---|---|
| 1 | `audit_log_d_path → d_path` | **ADOPT** (REQUIRED, `CONFIG_AUDIT`) | The old d_path kretprobe was symbol-scoped and fired here; the wrapper's bypass/task gates keep audit contexts unmodified. |
| 2 | `__arm64_sys_stat64 → vfs_statx` | **ADOPT** (REQUIRED) | Live site at +0x54 (Phase 17 census + on-device patch log); old `vfs_getattr_nosec` kretprobe covered it; wrapper semantics identical. The Phase 12-era comment claiming no such sites was factually wrong and is corrected. |
| 3 | `__arm64_sys_lstat64 → vfs_statx` | **ADOPT** (REQUIRED) | Same as #2. |
| 4 | `__arm64_compat_sys_newstat → vfs_statx` | **ADOPT** (REQUIRED, `CONFIG_COMPAT`) | Same as #2. |
| 5 | `__arm64_compat_sys_newlstat → vfs_statx` | **ADOPT** (REQUIRED, `CONFIG_COMPAT`) | Same as #2. |
| 6 | `do_open_execat` + `file_open_name → do_filp_open` | **ADOPT** (REQUIRED, both openat2 profiles) | Live sites (+0x7c / +0xf8); old symbol-scoped probe covered them; execve pathname entry and kernel named-open flow through the same redirect wrapper. |
| 7 | `vfs_kern_mount → vfs_create_mount` | **EXPLICITLY OUT OF PROFILE** (UNSUPPORTED row + documented rationale) | Internal multi-mount helper; adding it would gate the whole atomic mount trio's readiness on an LTO-fragile symbol; its `fc_mount`-like callers are already covered by the `fc_mount` row. Known, documented behavior change vs the pre-branch-link probe profile. The row is present in both runtime and policy so the audit sees an explicit decision, never an unaccounted site. |

Nothing remains in the indefinite `acknowledged=True` state; the stat-fd and
exec routes retain `acknowledge_unlisted` only for cross-route physical-target
overlaps (`exportfs_get_name` belongs to getattr-interior; `do_execve`/
`do_execve_file` are wrapper-internal BL paths), which are structural, not
coverage gaps.

## 4. Runtime Rollback Fix

**Bug** (pre-existing): in `ksu_bl_record_patch_routes()` the candidate
target's fn_slot was published before any text patch (required by the
stop_machine protocol), but neither candidate rejection nor route rollback
undid that binding. Consequences: orphan text records patched to a
non-preferred wrapper with a stale slot; on total route failure the last
candidate's slot stayed bound forever.

**Fix** (smallest possible, inside one function):

1. Save the slot's previous value (`READ_ONCE`) before each candidate bind,
   in a fixed `KSU_BL_MAX_ROUTE_TARGETS` (4) stack.
2. On candidate rejection: **restore text records first** (`cand_first`
   marker), then restore the slot (`WRITE_ONCE`) — reverse of install order,
   so no live site observes a stale/NULL slot while patched.
3. On route failure (`failed:`): after the existing text rollback, restore
   every touched slot — **gated on `ksu_bl_records_all_restored()`**, so a
   CONFLICT-stranded site keeps its valid original binding (mirrors the
   existing open-scope/dpath cleanup convention).

**Concurrency safety**: unchanged protocol — slot is still bound before the
first text patch; restores happen after the corresponding text restores;
plain `READ_ONCE`/`WRITE_ONCE` suffices because installs run under
`ksu_bl_lock`; each text restore goes through the existing
`ksu_patch_text_compare()`/stop_machine path. Happy path is bit-identical
(all restore branches are untaken on success).

**Regression test**: on-device verification — the fresh kernel installs
identical readiness and records (162) with `conflicts: 0`,
`restores/rollbacks: 0`; the permanent parity test locks the data model; the
failure-path behavior is covered by the existing family-rollback suite
(lifecycle test: "no branch-link restore conflicts" PASS).

## 5. Runtime Consumer

**Old architecture**: hand-maintained `static const` arrays per family inside
`branch_link_hook.c` (source of truth duplicated between runtime C and
`bl_policy.py`).

**New architecture (this phase)**: the policy file remains the single semantic
authority; the runtime arrays are now *proven equivalent* to it by a permanent
parity test, and the adopted/out-of-profile decisions are expressed in both
places atomically. Generated absolute addresses are not consumed anywhere;
the runtime's live verification (`BL opcode + decoded target + range +
compare-and-patch + rollback`) remains the only patch authority.

**Generated data contract** (validated for Phase 19): C rows matching
`struct ksu_bl_manifest_caller` exactly; classification map 1:1; width
elision `0 ≡ KSU_BL_SCAN_WIDTH` lossless; policy `min_sites` authoritative
(census counts are build-machine observations, never runtime invariants);
JSON stamp fields split into runtime-verifiable (`vmlinux_build_id`,
schema/policy revision) vs loader-verifiable (full digests); `payload_sha256`
stays build-time only (no self-referential in-image hashes).

**Fallback behavior**: no fallback path was created. There is no
"generated missing → stale manual array" mode; the arrays in tree are the
runtime data, and the parity test is the drift gate until the Phase 19 data
object replaces them.

## 6. Tests (exact results)

| Suite | Result |
|---|---|
| Analyzer suite (`run_bl_analyzer_v2_tests.sh`) | **15 PASS / 0 FAIL** |
| ELF fixtures (`bl_analyzer_v2_fixtures.py`) | **7 PASS / 0 FAIL** |
| Runtime↔policy parity (`test_runtime_policy_parity.py`, NEW) | **PASS** — 13 blocks, all routes, zero drift under the reference lisa profile (handles wrapped rows, `#if`/`#ifdef`/`#else` nesting incl. `<`/`>=` kernel-version guards, and the `mnt_clone_internal` version ternary) |
| Fresh-build analyzer run | exit 0 — 22 routes, **162 committed sites**, `vfs_kern_mount` logged as an explicit documented exclusion |
| Census delta audit (Phase 17 vs Phase 18 manifests) | Only the four adoption routes changed; the rollback fix produced **zero semantic drift** |
| On-device suite | **99 PASS / 0 FAIL / 10 SKIP** (inventory 6, avc 12, compat-table 8, lifetime 17, race 5, faccessat 5, readlink 6, stat/statfs 10, open 8, exec 9, mount 4, lifecycle 6, sucompat 3) |
| Reboot stability | Second boot identical: `records=162`, all families READY, `conflicts: 0` |

Device suite notes: the `readlink` and `stat/statfs` shell suites abort under
`/system/bin/sh` (mksh does not support fd numbers > 9 used by their
`exec 99<`/`exec 98<` redirections) — a pre-existing test-environment quirk,
not a kernel issue; both suites run clean under `busybox sh` (6+10 PASS).
The SKIPs are pre-existing environment constraints (SUSFS CLI, module
unload, C harnesses) identical to the historical profile.

## 7. Build

```text
kernel release:  5.4.302-MeowKernel-v2.03-e380c91
config:          CONFIG_KSU=y  CONFIG_KSU_HOOK_CORE=y  CONFIG_KSU_TAMPER_SYSCALL_TABLE=y
                 CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y  CONFIG_KSU_HOOKLESS_SUSFS=y
                 CONFIG_KSU_HOOKLESS_NOMOUNT=y  CONFIG_AUDIT=y
                 # CONFIG_KPROBES is not set   # CONFIG_KRETPROBES is not set
compiler:        Clang/LLVM (clang 21.1.8 toolchain, LLVM=1 LLVM_IAS=1)
build:           make O=out ... -j1   (defconfig + full build + ak3 package)
package:         /home/meow/KernelReleases/MeowKernel_v2.03-e380c91.zip
                 md5 52c6ed73ff9ce71ab56551eec3e26dde
generated-data:  validation/audit/phase18/fresh_build_manifest.json
                 (payload 7727a120c0d59204, full vmlinux/Image/System.map/
                  config digests + build-id, computed from the exact flashed build)
```

## 8. Device

```text
flash method:    established workflow — magiskboot unpack of the rescue
                 boot image (copy, original preserved), kernel swap, repack,
                 push (md5 verified both sides), dd to active boot_b
                 /dev/block/sde35 (md5 re-verified from the block device),
                 reboot
kernel string:   5.4.302-MeowKernel-v2.03-e380c91 (verified on device)
boot:            ~35 s to adb; no kernel panic/oops
boot log:        faccess 2/2 · readlink 2 · permission 35/35 (46 sites) ·
                 dpath 20/20 (21 sites incl. audit_log_d_path) · avc 7/7 ·
                 getname-flags 14/14 (22) · getname-kernel 14/14 (15) ·
                 iterate 9/9 (10) · stat-path 7/7 (incl. adopted old-stat) ·
                 open-scope 4/4 · do_filp_open 3/3 (4 sites incl. adopted
                 helpers) · getattr-interior 1/1 · mount 4+4+3 · exec ready ·
                 records=162 · conflicts: 0
regressions:     none (suite 99/0; conformance with historical baseline)
```

## 9. Performance

The runtime consumer change touches initialization/transaction paths only;
the hot path (wrapper slot reads) is unchanged, so no new benchmark was run.
The Phase 12 measurement (`sucompat=1 mean ≈ 13666.4 ns`, `sucompat=0 mean ≈
13654.8 ns`, mean overhead ≈ +0.089%, median ≈ +0.048%) remains the valid
baseline. No performance claim is made or implied beyond "hot path
unchanged".

## 10. Compatibility

- **Linux 5.4 (lisa)**: fully validated — offline parity + fresh-build
  analyzer + device suite + reboot stability (this phase).
- **Linux 4.19**: consumer architecture analyzed as C-level portable
  (Agent G); the slot fix uses no 5.x-only API. **Not runtime tested; no
  support claimed.**
- **Two-stage Kbuild / generated-data-at-compile-time**: not implemented
  (Phase 19 scope).

## 11. Git

```text
a8386aa7 branch-link: harden runtime consumer and resolve census gaps
7ccd0f68 gitignore: exclude phase17 test residue          (Phase 17)
```

Changed files in `a8386aa7`:
- `kernel/hook/arm64/branch_link_hook.c` (slot-rollback fix, gap rows,
  capacity, out-of-profile documentation)
- `tools/bl-analyzer/bl_policy.py` (gap decisions, `explicitly_excluded`,
  `MAX_RECORDS=176`)
- `tools/bl-analyzer/bl_analyzer_v2.py` (out-of-profile census handling)
- `validation/tests/test_runtime_policy_parity.py` (new permanent test)
- `validation/audit/phase18/` (fresh-build manifest/rows/log)

Worktree: **CLEAN** (flash/boot image work products kept under
`validation/audit/phase18/`, ignored). **NO PUSH PERFORMED.**

## 12. Remaining Work (before the Phase 19 Kbuild coordinator)

1. **Runtime data-object switch**: replace the in-tree arrays with the
   Phase-17-format generated data object consumed through a stable schema +
   boot-time validator (schema/revision/uniqueness/bounds/budget/build-id),
   with the arrays retired to a development-only explicit mode — never a
   silent fallback.
2. **KSU-internal recursion proof**: per-wrapper source invariant that no
   wrapper can BL directly to its own semantic target through a patched site
   (currently satisfied by fn-slot indirection; must be stated as policy).
3. **Decision records**: encode the adopted/out-of-profile decisions as
   machine-readable policy annotations (done: `note` fields + explicit rows)
   and keep them synchronized by the parity test (done).
4. **Guarded two-stage coordinator**: bootstrap manifest-independent data
   object, transaction nonce, `O=` isolation, atomic stamp, final-image
   re-analysis, bounded fixed-point comparison — per the Phase 16 design and
   the Phase 15/16 blocker record.
5. **Performance re-measurement** only if the Phase 19 switch changes the
   hot path (it should not).
