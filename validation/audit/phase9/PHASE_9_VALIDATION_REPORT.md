# PHASE 9 — VALIDATION GAP CLOSURE & PORTABILITY REPORT

**Project:** KernelSU-Next `susfs+nomount-hookless` · Xiaomi lisa · ARM64 · Linux 5.4.302
**Date:** 2026-09-12
**Verdict:** **PASS — ALL TARGETED VALIDATION CLOSED** (with integration limitations documented)
**Push status:** **NO PUSH PERFORMED**

---

## A. Executive summary

Phase 9 closed every validation gap that Phase 6/7 flagged as open: three new permanent tests (compat-table invariants, permission one-shot lifetime, signal/namespace races — **+30 checks**, suite now **79 PASS / 0 FAIL**), a decisive stat-fd investigation (conclusion: **no missing semantics; not a regression; documentation fixed instead of code**), a real cross-kernel portability measurement on a genuine 5.15 GKI Image (all hookless families discoverable), an AVC/`CONFIG_AUDIT` investigation that also caught and fixed a misleading boot log, a prop-hygiene `EACCES` root-cause (pre-existing, SELinux-denied usermodehelper exec, near-no-op), and camera-warning attribution (unrelated vendor noise). One small code change (extras.c log accuracy) — no architectural changes. Zero-probe state unchanged.

## B. Starting state

- Branch `susfs+nomount-hookless`, HEAD `257726f5`, clean tree, 20 commits ahead of remote (17 after Phase 8 + Phase 7 fix commit; final count after Phase 9: 21).
- Config as expected (verified): `KSU=y`, `KSU_HOOK_CORE=y`, `TAMPER=y`, `BRANCH_LINK=y`, `HOOKLESS_SUSFS=y`, `HOOKLESS_NOMOUNT=y`, `KPROBES=n`, `KRETPROBES=n`.
- Shipped hook mode: **`SyscallTable+BranchLink`** (verified via compiled `vmlinux` string set).
- Previous limitations under reassessment: stat-fd, AVC/AUDIT, ovl lifetime test, signal/namespace test, compat invariant test, cross-kernel portability, camera warnings, prop-hygiene EACCES.

## C. stat-fd investigation

**Old behavior:** kretprobe symbol-scoped on `vfs_getattr_nosec` with handler applying SUSFS kstat + NoMount fd layers.

**This build's reality (Image disassembly, exact):**
- `vfs_fstat()` is **fully inlined** into the fd-stat syscall wrappers. `__arm64_sys_newfstat` = `bl __fdget_raw` (+0x50) then `bl vfs_getattr` (+0x70) then `bl cp_new_stat` (+0x90); same shape for `__arm64_sys_fstat64` (+0x70) and `__arm64_compat_sys_newfstat` (+0x70).
- There is **no** `vfs_fstat` symbol and **no** BL to `vfs_getattr_nosec` anywhere on the fd-stat path (the nosec body is inlined into `vfs_getattr`; `vfs_getattr_nosec` has exactly 1 BL caller: `exportfs_get_name`).
- The existing stat-fd manifest routes (targets `vfs_fstat` and `vfs_getattr_nosec` via `ksu_bl_record_patch_routes`) therefore correctly find 0 sites → `stat-fd=0` → **fail-closed**, exactly as designed.

**Decisive semantic fact:** the old kretprobe was symbol-scoped on `vfs_getattr_nosec`. Since this build's fd-stat path never *enters* that function (body inlined into `vfs_getattr`), **the old kretprobe never fired for fstat/newfstat/fstat64 either.** `stat-fd=0` therefore represents **exact parity with the pre-migration kernel**, not a lost capability.

**User-visible coverage today:** path-based stat (`newfstatat`, `stat`, `statx` on paths) is covered by the stat-path family + `ksu_bl_handle_stat_result`/`ksu_susfs_handle_stat_result` kstat-identity matching + NoMount getname scopes; fd-derived `fstat`/`fstatx` on a redirected backend file returns data fetched via the fd's path — metadata spoofing for that fd was never functional under the old kretprobe in this build, so nothing regressed.

**Alternative boundary identified (documented, deliberately NOT implemented):** a third stat-fd route targeting `vfs_getattr` with a call-then-apply wrapper would work (19 reachable BL sites) but would additionally intercept ovl/fuse/exportfs internal `vfs_getattr` callers — an interception expansion beyond the old kretprobe's reach, with zero user-visible gain on this build.

**Final classification: `ALREADY COVERED SEMANTICALLY`** (stat family) / fd-stat: **NO SAFE *NEEDED* BOUNDARY — parity-neutral, no hook added.** Documentation updated; `stat-fd=0` is honest and correct.

## D. Compat syscall-table invariant (NEW permanent test)

`validation/tests/test_compat_table_invariant.sh` (8 checks), wired into the suite runner:

| Check | Result |
|---|---|
| tamper dispatcher enabled (boot log) | PASS |
| hook registrations present, **no duplicate nr** (48/79/142/147/160/221) | PASS |
| `compat reboot slot 88 mirrors native 142` identity line | PASS |
| `compat syscall 88 hooked` (mirror actually installed) | PASS |
| zero `hook failed` lines (no failed mirror patch) | PASS |
| 32-bit task syscalls functional (compat tester) | PASS |
| native routing functional (toybox exec through tampered execve slot) | PASS |

Design notes: on-device kernel-side table bytes are not exposed to userspace, so the invariant is verified through the registration/mirror log contract (which Phase 7 made fail-safe: identity check + explicit mismatch logging) plus dual-ABI behavioral probes. Slot enumeration evidence: registered set is exactly the TAMPER-routed numbers; the only compat-mapped slot is 88→142.

## E. OverlayFS / permission one-shot lifetime (NEW permanent test)

`validation/tests/test_permission_lifetime.sh` (17 checks). A scratch overlayfs upper is **not supported** on this device (`overlayfs: filesystem on '...' not supported` — f2fs+dm-crypt+inlinecrypt upper rejected by 5.4 ovl), so a raw ovl mount test is not practical; however the `permission_consumed` state machine being tested lives in the NoMount access-scope engine and is fully exercisable through the real rule API with a DAC-denied (root:root 0600) backend:

| Check (×3 rounds) | Result |
|---|---|
| rule add; first redirected open (scope created, consumed, DAC force-allow applied) | PASS ×3 |
| second independent open (fresh scope — proves consumption doesn't leak) | PASS ×3 |
| repeated open | PASS ×3 |
| visible inode identity stable across repeated access | PASS ×3 |
| rule delete restores stock content | PASS ×3 |
| concurrent scope isolation: 4 workers × 30 opens, zero cross-task leakage | PASS |
| no kernel BUG/OOPS during test | PASS |

**17 PASS / 0 FAIL.** The ovl-nesting case (`ovl_permission → inode_permission(realinode)`) shares this same `permission_consumed` engine; the red-team analysis plus this test close the identified gap at the correct level.

## F. Signal/namespace race (NEW permanent test)

`validation/tests/test_signal_namespace_race.sh` (5 checks, bounded):

| Scenario | Result |
|---|---|
| S1: 60 rounds fork/exec storm + concurrent path lookups (getname scope task_work vs exec teardown) | PASS |
| S2: 40 rounds SIGKILL storm during redirected lookups (PF_EXITING gating, task_work vs do_exit) | PASS |
| S3: 40 bind-mount/mountinfo churn ops + 120 concurrent redirected lookups (mntns/path lifetime) | PASS |
| S4: 25 rule add/del cycles racing lookups (stale-redirect detection; redirect intact after churn) | PASS |
| kernel BUG/OOPS delta across all scenarios | 0 |

No stale task state, no cross-process leakage, no missed cleanup, redirect/hide semantics correct through all transitions.

## G. Cross-kernel Branch Link portability

Method: real built Images where locally available; static source analysis otherwise. The lisa manifest was never assumed portable — the question was whether the *scanner semantics* (BL discovery, symbol resolution, next-symbol/size boundary detection, ±128 MiB reach, fail-closed manifest validation) function per target.

| Kernel | Build | Scanner | Required families | Manifest | Runtime | Verdict |
|---|---|---|---|---|---|---|
| **5.4** (lisa) | ✅ shipped | ✅ | ✅ | ✅ 148 records | **validated** | **VALIDATED** |
| **5.15.189** (android13 GKI, local tree, real Image+System.map) | pre-built (KSU not integrated) | ✅ **statically exercised on the actual Image** | ✅ all families discoverable | sites found: getattr_nosec **21**/17 callers, d_path **28**/24, getname_flags **40**/30, getname_kernel **22**/20, iterate_dir **11**/10, inode_permission **55**/47, vfs_statx **12**/12 (mostly default-reachable; width overrides available) | not run | **PORTABLE (static)** — notably `vfs_getattr_nosec` is standalone with 21 sites on 5.15 (opposite of lisa's inlined shape), and the fd-stat wrappers keep their nosec call, so even stat-fd resolves there |
| **6.1** | no local tree | source-level: same-generation VFS as 5.15/6.6 | — | — | — | **UNVALIDATED** |
| **6.6.118** (mt6991 workspace) | source not a kernel tree (exploit workspace) | not analyzable | — | — | — | **UNVALIDATED** |
| **6.12.30** (aosp, local source) | no built Image (bazel) | ✅ static source check: `vfs_getattr`, `inode_permission`, `iterate_dir`, `d_path`, `getname_flags` all present (getname_flags lost `int *empty` arg — manifest ABI already parameterizes wrappers per family) | ✅ boundaries exist | — | — | **PORTABLE WITH VERSION-SPECIFIC SHIMS** (scanner + wrapper ABIs adapt; not built/run) |
| **4.19 / 4.9** | not built | branch-link mechanics (BL patch, boundaries, rollback) are version-agnostic; API gaps (`vfs_create_mount` etc.) are *SUSFS runtime* issues, **not** scanner issues | — | — | — | **REQUIRES BACKPORT (APIs) — architecture conceptually portable** |

Distinction preserved throughout: **kernel API compatibility ≠ Branch Link architecture compatibility**. Manifests are target-build-specific *by design*; discovery/validation/patching/rollback/lifecycle are the portable parts, and the 5.15 measurement demonstrates the discovery half on a genuinely different kernel generation.

## H. CONFIG_AUDIT / AVC

- The only AVC-spoof interception in-tree was the `slow_avc_audit` **kprobe** (`extras.c`), gated `CONFIG_KPROBES` and requiring the `slow_avc_audit` symbol (`CONFIG_AUDIT=y`).
- On the shipped build (`KPROBES=n`, `AUDIT=n`) the mechanism is compiled out. **Investigation also caught a real logging bug**: on `KPROBES=n` the enable path fell through to `slow_avc_audit spoofing enabled!` with no mechanism behind it — **fixed** (now reports `slow_avc_audit interception not built (CONFIG_KPROBES=n): spoofing disabled`); verified on the flashed build.
- `CONFIG_AUDIT=y` alone restores the *symbol*, not hookless enforcement; the feature would additionally need `CONFIG_KPROBES=y` (violating zero-probe) — **unless** implemented hooklessly: `slow_avc_audit()` is `noinline` with a **single compiled call site** (`avc.c:429`), so with `AUDIT=y` a clean single-site BL rewrite (wrapper rewrites the `tsid` argument, calls the original) is the natural route.
- Final classification: **IMPLEMENTABLE VIA EXISTING HOOKLESS INFRASTRUCTURE, but only on `CONFIG_AUDIT=y` builds — deliberately NOT implemented now** (speculative; lisa is `AUDIT=n` where there is no AVC path to spoof). README now states this precisely. The addendum's premise that spoofing is "active" on the zero-probe build was a **misleading log artifact**, now corrected at the source.

## I. Zero-probe verification (final)

- `.config`: `KPROBES=n`, `KRETPROBES=n` (grep count of `=y` forms: 0).
- `System.map`: 0 probe symbols.
- Source audit: all `register_kprobe/kretprobe` sites inside `#ifdef CONFIG_KPROBES/KRETPROBES` guards.
- Generic `KPROBES=y` matrix sanity: hookless selection unchanged; shipped config restored.
- Boot: four probe-free boots this phase; `records=148` every time.

## J. Test-suite status

| Test | Before Phase 9 | After Phase 9 | Status |
|---|---|---|---|
| Full deterministic suite | 49 PASS / 0 FAIL | **79 PASS / 0 FAIL** | expanded |
| BL edge tester | 9/9 | 9/9 | existing |
| AArch32 compat tester | pass | pass | existing |
| NoMount selftest | 41 PASS | 41 PASS | existing |
| App-UID open_redirect | pass | pass (`SWAPPED_V203`/`SWAPPED_CLEAN`) | existing |
| **compat-table invariant** | **gap** | **8 PASS / 0 FAIL** | **NEW** |
| **permission one-shot lifetime** | **gap** | **17 PASS / 0 FAIL** | **NEW** |
| **signal/namespace race** | **gap** | **5 PASS / 0 FAIL** | **NEW** |
| su/ksud, reboot, dmesg, hook-mode | pass | pass | existing |

## K. Limitation reclassification

| Item | Previous classification | New classification | Reason |
|---|---|---|---|
| stat-fd not-ready | Known limitation (implied missing capability) | **Target/kernel-integration property; semantics covered; parity-neutral** | nosec inlined into getattr in this build; old kretprobe never fired on fd-stat path; on 5.15-style builds the family resolves |
| AVC spoofing "unsupported" | Known limitation | **Kernel-integration requirement**: implementable hooklessly as a single-site BL rewrite **only with `CONFIG_AUDIT=y`**; absent-by-design on `AUDIT=n`; misleading log fixed | single call site at `avc.c:429` identified; not implemented (speculative) |
| Missing compat invariant test | Test gap | **Closed** | new permanent test, 8/8 |
| Missing ovl lifetime test | Test gap | **Closed** (at the correct level: rule-engine lifetime; raw ovl upper unsupported on this device) | new permanent test, 17/17 |
| Missing signal/namespace race test | Test gap | **Closed** | new permanent test, 5/5 |
| "Branch Link is lisa-specific" | Mischaracterized limitation | **Target-specific manifests by design; scanner is portable** | real 5.15 GKI Image: all families discoverable |
| camera warnings (mclk2/-110/regulator) | Unclassified | **Unrelated vendor warnings** (Qualcomm camss sensor power-down; traces contain no KSU symbols; timing matches camera HAL init, not KSU) | dmesg attribution |
| prop-hygiene `-13` | Unclassified / "open issue" | **Pre-existing, expected-on-enforcing-Android, functionally near-no-op** | root-caused: `call_usermodehelper` exec of `/system/bin/sh` from the UMH kworker denied by SELinux (`EACCES`), retried 6×, and no baseline file has ever existed so there is nothing to restore; code introduced pre-Phase-1 (`77fa465c`, July 2026); untouched by any migration phase; no AVC suppression or fail-open applied |

## L. Documentation changes

`docs/README.md`:
- `avc_log_spoofing` feature entry qualified: `CONFIG_AUDIT=y`-only, implemented as a single-site branch-link rewrite of the compiled `slow_avc_audit()` call; absent-by-design on common `CONFIG_AUDIT=n`.
- New "Branch Link portability and manifests" subsection: manifests are target-build-specific **by design**; portability lives in discovery/validation/patching/rollback; 5.15 static result cited; `stat-fd` no-patch-point status explained (parity-neutral, not a missing feature).

Translations **not** modified: the English README's technical conclusions on compatibility/config are unchanged in substance; translation churn was avoided per the phase rules. (The Phase 8 translations already carry the defconfig/KPROBES/portability-critical content.)

## M. Git changes (Phase 9)

| Hash | Subject | Files |
|---|---|---|
| `6cd73b6c` | tests: close hookless validation gaps; correct avc-spoof reporting | `kernel/extras.c`, 3 new tests, suite runner, `docs/README.md` |

## N. Runtime evidence

- Kernel: `5.4.302-MeowKernel-v2.03-e380c91`, Image md5 `2c5bd8d5…` (post-extras-fix build), boot image `0894e9d0…` verified.
- Boot ×2 clean; `records=148`; `compat syscall 88 hooked`; corrected AVC log line present; 0 BUG/OOPS.
- Expanded suite: **79 PASS / 0 FAIL** (log `bl-test-results-20260912-021306.log`).
- Individual: compat-table 8/0, lifetime 17/0, race 5/0.
- su/ksud/app-UID/selftest all pass post-reboot.

## O. Known remaining limitations

Only genuine ones retained:
1. AVC-log spoofing requires a `CONFIG_AUDIT=y` build + a (small, unimplemented) BL rewrite — absent-by-design on `AUDIT=n`.
2. stat-fd family inactive on inlined-helper builds like lisa 5.4 (semantics covered elsewhere; resolves on 5.15-style builds).
3. Cross-kernel runtime validation (5.15/6.x) still requires someone to integrate KSU into those trees and run the device/build loop — the discovery half is proven, the end-to-end half is not.
4. 4.19 needs `vfs_create_mount()`-era API resolution; 4.9 experimental; 3.10/3.18 unsupported.
5. Target-specific manifests are required per build (by design; fail-closed).

## P. Final recommendation

```text
PASS — ALL TARGETED VALIDATION CLOSED
```
(with integration requirements — not architectural defects — documented in §O)

---

## Latest Runtime Log Follow-Up (addendum)

### prop-hygiene `EACCES`
Root-caused: `ksu_susfs_run_prop_hygiene_restore()` uses `call_usermodehelper(UMH_WAIT_PROC)` to run `/system/bin/sh -c '<resetprop script>'`. On this enforcing-Android build the UMH kworker's exec of `/system/bin/sh` is denied by SELinux → `do_execve` returns `-EACCES`, which `call_usermodehelper` propagates → 6 retries → final failure. Additionally, no `prop_hygiene_baseline` file has ever existed on this device (the script's guard would `exit 1` anyway), so the restore is a functional no-op even if exec succeeded. The code was introduced in pre-Phase-1 groundwork (`77fa465c`, 2026-07-09) and the failure mode is untouched by Phases 1–9 (no BL family patches the usermodehelper exec decision; the getname wrapper on `call_usermodehelper_exec_async` only runs NoMount path policy, which `/system/bin/sh` does not match, and cannot produce EACCES). **Classification: pre-existing + expected behavior on enforcing Android; functionally near-no-op; treated as an open (non-blocking) issue** — no suppression, no retry increase, no fail-open applied.

### AVC / slow_avc_audit
The addendum's log line (`slow_avc_audit spoofing enabled!`) was a **misleading artifact**: on `KPROBES=n` the enable path compiled past the (absent) kprobe block and printed "enabled" with no mechanism behind it. Fixed to report accurately; the feature genuinely requires `CONFIG_AUDIT=y`, and even then a hookless implementation (single-site BL rewrite at `avc.c:429`) would be needed — documented as implementable-but-unimplemented. **The zero-probe build has no AVC spoofing, and now says so honestly.**

### stat-fd
See §C: **semantics already covered / parity-neutral**; `stat-fd=0` is honest, documentation updated instead of adding an unnecessary hook.

### Camera warnings
`cam_cc_mclk2_clk already disabled/unprepared` (t≈16 s) and camera `-110` I2C timeouts originate in Qualcomm camss sensor power-down code (`cam_sensor_util_power_down → clk_core_disable`); no KSU symbol appears in any trace, the timing tracks camera HAL/sensor init rather than KSU activity, and identical warnings appear in pre-Phase-9 dmesg. **Classification: unrelated vendor warnings; no Qualcomm code touched.**
