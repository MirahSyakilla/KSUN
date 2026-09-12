# PHASE 17 — BL MANIFEST/DATA-MODEL CORRECTION & SAFE FOUNDATION

**Branch:** `susfs+nomount-hookless` · base `0f9dfd9e`
**Verdict:** **PASS WITH DOCUMENTED LIMITATIONS**
**Push:** none performed · **Flash:** none performed · **Kernel build:** none performed
**Report:** `validation/audit/phase17/PHASE_17_ANALYZER_V2_FINAL_REPORT.md`

---

## 1. Verdict

**PASS WITH DOCUMENTED LIMITATIONS.**

Implemented and validated: the corrected fail-closed analyzer (v2), the complete
source-owned policy model, the offline positive/negative test suite, and full
golden-image validation of the exact lisa build. The two-stage build and runtime
consumer switch remain deliberately unimplemented per the Phase 15/16 blocker
record and this phase's own instruction ("Do NOT blindly implement the two-stage
build yet"). No kprobe/kretprobe reintroduction, no vendor-source modification,
no `/tmp` usage, no push.

## 2. Delegated Investigations

| Agent | Scope | Key conclusions |
|---|---|---|
| A — Runtime contract | `branch_link_hook.c` manifest/routes/exec drivers | One row per caller; `min_sites` per caller; width `u16`, `0`=default; classification REQUIRED/OPTIONAL/UNSUPPORTED semantics; rollback is record-range based; canonical vs real-body lookup split; record cap 160; readiness flags. |
| B — Policy design | format choice + full transcription | Python dataclasses selected (typed, comments, conditionals, zero parser); full policy content transcribed from every runtime array; explicit `owner=` KSU policy (prefix matching forbidden). |
| C — Failure matrix | v2 exit codes + identity | Byte-classes: 32 input / 48 symbol / 64 drift / 80 manifest / 96 internal; any nonzero suppresses consumable output; identity = full-file SHA-256 + build-id + config; self-reference solved by keeping final digests in the external stamp. |
| D — ELF validation | header/section/symbol spec | P0: ELF64/LSB/AArch64 gate, ET_REL rejection, containment via `st_size`, System.map exact binding, fail-closed exits. |
| Review 1 — adversarial | post-implementation | Found H1–H4, M1–M8, L1–L8; all HIGH/MEDIUM fixed and re-verified; LOWs fixed or documented. |
| Review 2 — policy fidelity | runtime↔policy diff | **PASS: zero mismatches** across all runtime rows; KSU-internal explicit; acknowledged gaps verified against live vmlinux census. |

## 3. Architecture Decision

- **Source policy** (`tools/bl-analyzer/bl_policy.py`): authoritative semantic
  policy — route IDs, targets, wrapper bindings, caller rows with
  classification/`min_sites`/width/owner/conditions, acknowledged gaps,
  `MAX_RECORDS`, `SCAN_WIDTH`, section allowlist. 167 rows covering all 22
  direct-BL routes.
- **Generated binary facts**: analyzer census — site VAs, raw instruction words,
  caller attribution (containment-checked), per-caller aggregation, full identity.
- **Analyzer v2** (`tools/bl-analyzer/bl_analyzer_v2.py`): policy-joined,
  fail-closed; outputs JSON (stamp + census) and C rows (audit artifact) written
  atomically only on success.
- **Build integration boundary**: unchanged this phase. The v2 analyzer is a
  prerequisite-complete tool for the future two-stage design recorded in
  Phases 15/16.

## 4. Implementation

| File | Purpose |
|---|---|
| `tools/bl-analyzer/bl_policy.py` | NEW: source-owned policy (single source of semantic truth). |
| `tools/bl-analyzer/bl_analyzer_v2.py` | NEW: fail-closed analyzer v2. |
| `validation/tests/run_bl_analyzer_v2_tests.sh` | NEW: 15-check suite (positive, determinism, stale handling, negative inputs, usage). |
| `validation/tests/bl_analyzer_v2_fixtures.py` | NEW: 7 synthetic-ELF assertions. |
| `validation/audit/phase17/build_fixtures.py` | NEW: fixture builder (uses `.size` directives so `nm -S` yields function sizes). |
| `validation/audit/phase17/lisa_manifest.{json}`, `lisa_manifest_rows.h`, `lisa_run.log` | Golden validation artifacts for the exact current lisa build. |
| `.gitignore` | `__pycache__/` added. |

No runtime, Kbuild, vendor, or `bl_discover.py` (Phase 14 historical artifact)
changes.

## 5. Analyzer Correctness (test results)

**Suite (`run_bl_analyzer_v2_tests.sh`): 15 PASS / 0 FAIL**

```
PASS fixture_assertions        PASS neg_vmlinux_missing
PASS pos_lisa_full             PASS neg_sysmap_missing
PASS determinism               PASS neg_sysmap_empty
PASS stale_reject (exit 32)    PASS neg_config_missing
PASS stale_not_clobbered       PASS neg_x86_image
                               PASS neg_et_rel
                               PASS neg_output_alias
                               PASS neg_sysmap_unrelated
                               PASS neg_no_args / neg_bad_flag (exit 2)
```

**Fixtures (`bl_analyzer_v2_fixtures.py`): 7 PASS / 0 FAIL**

| Fixture | Proves |
|---|---|
| `valid.elf` | single direct BL discovered with correct caller |
| `two.elf` | 2 BLs in one caller aggregate to ONE row, count 2 |
| `pad.elf` | BL outside caller size rejected (no phantom caller) |
| `notarget.elf` | missing target → zero sites → policy fails closed |
| `recurse.elf` | target self-call attributed; explicit policy exclusion required |
| `blronly.elf` | BLR indirect yields zero direct sites (never patched) |
| `veneer.elf` | no direct caller site through a stub |

**Golden image validation (exact current lisa build):**

```
22 routes, 155 committed sites, payload aeab3fa8…
faccessat 2 · readlink 2 · permission 46 · dpath 21 · avc 7 ·
getname_flags 22 · getname_kernel 15 · iterate 10 · stat-path 7 ·
stat-fd 0 · statfs-path 3 · statfs-fd 3 · open-scope 4 · filp_open 2 ·
getattr-interior 1 · create 5 · clone 4 · cleanup 3 ·
execve 1 · execveat 1 · compat_execve 1 · compat_execveat 1
projected budget if acknowledged gaps adopted: 161/160
```

The 155 committed-site total matches the historically validated runtime
155-record (148 non-AVC + 7 AVC) profile. The committed-site count deliberately
excludes the acknowledged census gaps; the projected budget documents that
adopting all six acknowledged gaps would require raising `KSU_BL_MAX_RECORDS`
(≥176 recommended).

## 6. Build Correctness

Not implemented — per instruction and per the Phase 15/16 blocker record
(circular final-image dependency; no guarded coordinator exists). The v2
analyzer is now prerequisite-complete for that design: fail-closed exits,
policy join, identity stamp, deterministic outputs.

## 7. Runtime Validation

Not performed — no kernel was built or flashed this phase (no runtime code
changed). Historical 80/0 remains Phase 12 evidence. Runtime hot path is
untouched; no new benchmark claimed.

## 8. Security / Fail-Closed Review

- ET_REL, wrong-arch, non-ELF inputs → exit 32, nothing written.
- Missing/empty/System.map-target mismatch → exit 32.
- Missing/unreadable UAPI headers → `SRCTREE_HEADERS_MISSING` (no silent
  `__NR_*` disabling of required callers).
- Policy condition errors (`!(`-style, undefined CONFIG) → exit 80, not 96.
- Output paths colliding with inputs (vmlinux/sysmap/config) or each other →
  exit 32.
- Any drift/policy failure → nonzero; existing stamped outputs are never
  clobbered by failing runs (verified: `stale_not_clobbered`).
- Identity stamp: full-file SHA-256 for vmlinux/Image/System.map + config +
  build-id + policy digest + schema/policy revisions.
- Deterministic outputs: byte-identical JSON across runs (no wall clock).

Post-implementation adversarial review verified H1–H4/M1–M8 fixes as real;
remaining LOW findings fixed or documented (dead code removed, projected
budget counts sites, `report-on-fail` alias-guarded).

## 9. Compatibility

- **Linux 5.4**: golden-validated offline (this phase). Build integration and
  runtime consumer switch: **not** implemented — manual runtime arrays remain
  the production mechanism.
- **Linux 4.19**: analyzed only (Phase 16 record stands). No runtime/build
  validation claimed. The analyzer's `kver` conditions (`KV(5,0,0)`, `KV(5,10,0)`)
  now evaluate from the actual target version instead of a hardcoded 5.4.
- AArch32/compat: policy rows preserve runtime `CONFIG_COMPAT` guards exactly
  (independently verified row-by-row).

## 10. Performance

No runtime change; hot path untouched. No new benchmark.

## 11. Git State

See section below (final commit listing). Worktree clean. **No push.**

## 12. Remaining Work

1. Runtime consumer switch: replace hand-maintained arrays with generated
   data object (Phase 16 design), including `KSU_BL_MAX_RECORDS` capacity
   decision (155 today; 161+ if gaps adopted → recommend ≥176).
2. Explicit product decision on the six acknowledged census gaps
   (`audit_log_d_path`, stat64/lstat64/newstat/newlstat,
   `do_open_execat`/`file_open_name`, `vfs_kern_mount`): adopt into runtime
   arrays (with capacity bump) or declare them out of profile in policy.
3. Guarded two-stage Kbuild coordinator (Phase 16 design) — only after 1–2.
4. Device runtime validation after any runtime-consuming integration.
5. Documentation refresh only when automatic generation is actually real.

---

## Git (filled at commit)

```text
<HEAD recorded in final verification below>
```

**NO PUSH PERFORMED.**
