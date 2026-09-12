# PHASE 15 - FULLY AUTOMATIC BUILD-INTEGRATED BL MANIFEST GENERATION

## Status

**BLOCKED - no unsafe implementation was committed.**

This report records the Phase 15 investigation and the exact reason implementation
was stopped. The requested final state requires generated caller metadata to be
compiled into built-in KSU code. In the current Linux 5.4/vendor topology, that
would create a circular build dependency. The existing Phase 14 analyzer also
cannot be promoted to a build gate or runtime manifest consumer without first
fixing several fail-open and coverage defects.

No production Kbuild, runtime, vendor functional source, or manifest consumer was
modified. No kernel build, package, flash, or push was performed for Phase 15.

## Executive Summary

The current build is an in-tree built-in KSU integration:

```text
CONFIG_KSU=y
drivers/kernelsu -> KernelSU-Next/kernel
KernelSU built-in.a
        -> vmlinux.o
        -> final vmlinux
        -> System.map
```

`branch_link_hook.o` is compiled while the built-in archives are assembled, long
before the final `vmlinux` and `System.map` exist. A generated header consumed by
`branch_link_hook.o` therefore cannot be generated from that same final image in
the ordinary Kbuild DAG:

```text
branch_link_hook.o
    -> generated_manifest.h
    -> analyzer(vmlinux, System.map)
    -> final vmlinux
    -> built-in.a
    -> branch_link_hook.o
```

This is a real cycle, not an ordering detail that can be fixed with an additional
ordinary prerequisite.

The only architecture proven safe within the existing Kbuild boundary is a
post-link analyzer sidecar or validation target. That architecture would be
suitable as a mandatory gate only after the analyzer is corrected, made
fail-closed, and integrated. It can validate an already-built image, but it
cannot compile the generated manifest into the built-in KSU object in the same
invocation. An actual compile-in solution requires
an explicitly controlled outer two-pass build driver or a separate discovery link,
neither of which is currently part of the repository or safely expressible as a
normal single-pass Kbuild dependency.

The Phase 14 analyzer is also not ready for either role. Independent audits found
that it:

- is not invoked by Kbuild or any normal kernel build target;
- emits initializer fragments rather than a usable family-specific header;
- emits duplicate rows for callers with multiple sites;
- drops required KSU-internal callers;
- models only three families while the runtime has substantially more routes;
- requires `--sysmap` syntactically but never reads it;
- hashes only the first 16 MiB of vmlinux and does not bind the final Image;
- reports required drift while returning exit status 0;
- does not validate function containment or symbol roles robustly, and does not
  handle aliases or complete executable-section coverage.

The analyzer was run independently with a nonexistent System.map and with a
known d_path coverage failure. It returned status 0 in both cases. That makes it
unsafe as a mandatory build gate until corrected.

## Delegated Investigations

Five required investigations and an additional binary-analysis review were
delegated to independent agents during this session. Their returned findings
were compared against the repository; none edited repository files. The agent
responses are session evidence rather than repository artifacts.

| Investigation | Conclusion |
|---|---|
| KSU/Kbuild integration | KSU is built-in before final vmlinux/System.map; a final-image generated header creates a cycle; post-link validation is acyclic; compiled-in data requires an explicit two-pass driver. |
| Phase 14 analyzer audit | Analyzer is not integrated, not fail-closed, emits invalid/ambiguous runtime data, ignores System.map, and has incorrect deduplication and family coverage. |
| Runtime manifest architecture | Runtime still consumes hand-maintained arrays in `branch_link_hook.c`; generated artifacts are not included; rows must be caller-oriented and target/route-specific. |
| Linux 4.19/5.4 compatibility | Old Kbuild supports post-link mechanisms but cannot break the same-build cycle; raw Image-only analysis is not supported by the current tool; O= and symlinked source paths require object-tree outputs. |
| Adversarial build/race/security review | Stale manifests, shared source-tree outputs, duplicate writers, malformed metadata, failure masking, and recursive build races are all possible with a naive integration. |
| Independent binary-analysis review | ARM64 direct-BL arithmetic is correct, but section coverage, mapping symbols, aliases, function boundaries, BLR/veneer handling, and target identity are insufficient for a fail-closed build gate. |

### Reconciliation

The reviews agreed on the central dependency conclusion. There was no safety-
critical disagreement requiring a design choice between conflicting claims.

The important distinction is:

```text
post-link analyzer target
    safe and acyclic, but validation-only

generated header consumed by built-in KSU
    requires explicit multi-stage orchestration
```

The Phase 14 report claimed the generated header was already consumable without
runtime integration. Direct inspection disproved that claim: no source file
includes it, the runtime arrays remain in `branch_link_hook.c`, and the output is
not a complete declaration.

## Actual Build Topology

### KSU integration

The setup script creates a relative `drivers/kernelsu` symlink to the KSU kernel
directory and appends the normal driver Kbuild/Kconfig entries:

- `KernelSU-Next/kernel/setup.sh:87-92`
- `/home/meow/lisa_kernel/drivers/Makefile:189`
- `/home/meow/lisa_kernel/drivers/Kconfig:233`

Kbuild prefers `Kbuild` over `Makefile` when descending into the directory:

- `/home/meow/lisa_kernel/scripts/Makefile.build:39-42`
- `KernelSU-Next/kernel/Kbuild:330`

The active configuration has `CONFIG_KSU=y`, so the KSU archive is linked into
the kernel rather than built as a module. Hookless SUSFS also rejects module mode
in `KernelSU-Next/kernel/Kconfig:95-97`.

`branch_link_hook.o` is included by:

- `KernelSU-Next/kernel/Kbuild:55-59`

The current hand-maintained manifest arrays are in:

- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:943`
- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:1093`
- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:1200`
- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:1261`
- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:1298`
- `KernelSU-Next/kernel/hook/arm64/branch_link_hook.c:1335`
- route arrays later in the same file

No source file includes `tools/bl-analyzer/generated_manifest.h` or its JSON
output.

### Link ordering

The top-level Makefile assembles the vmlinux dependency set at:

- `/home/meow/lisa_kernel/Makefile:1203-1212`

The final vmlinux target is linked at:

- `/home/meow/lisa_kernel/Makefile:1241-1246`

The link script performs these stages:

1. Compiles final init objects.
2. Links `vmlinux.o`.
3. Runs modpost.
4. Performs kallsyms intermediate links.
5. Links final `vmlinux` at `scripts/link-vmlinux.sh:438`.
6. Generates `System.map` at `scripts/link-vmlinux.sh:451-452`.

The KSU objects are therefore complete before step 5. A stale vmlinux already
present in the output directory is not a valid input for the current source,
configuration, or compiler state.

### Dependency graph

The requested compile-in relationship would be:

```text
generated_manifest.h
    -> branch_link_hook.o
    -> drivers/kernelsu/built-in.a
    -> vmlinux.o
    -> vmlinux
    -> System.map
    -> bl_discover.py
    -> generated_manifest.h
```

Adding `vmlinux` as a prerequisite of the generated header produces a Make cycle.
Generating the header in a post-link recipe does not repair the first image: the
first link already used the old or missing header, and Make does not generally
re-evaluate the completed `vmlinux` target after its recipe changes an input.

## Architecture Decision

### Chosen safe boundary

No compile-in architecture was selected for implementation because the current
repository lacks a safe, tested outer orchestration layer. The safe boundary is:

```text
normal kernel build
    -> final vmlinux + System.map + Image
    -> offline analyzer
    -> validation artifact under the active O= tree
```

This is suitable for a mandatory post-link validation gate. It is not sufficient
for the user's required generated header to be compiled into built-in KSU.

### Option A: two-pass build

Conceptually possible:

```text
Pass 1: build with a bootstrap policy/data object
    -> discovery vmlinux/System.map
    -> analyzer
    -> generated manifest

Pass 2: rebuild KSU using generated manifest
    -> final vmlinux/System.map/Image
    -> analyze final image again
    -> require stable/final metadata
```

This cannot be implemented as an ordinary prerequisite in the current Makefile.
It needs an explicit guarded recursive build driver, isolated object/output
directories or a carefully defined bootstrap header, atomic generated outputs,
fixed-point detection, and a final verification pass. The current runtime data
model is not yet ready for this because it has multiple route-specific arrays,
shared targets, KSU-internal exceptions, and ABI-dependent alternatives.

Without those controls, a recursive post-link call would risk:

- infinite recursion through `ARCH_POSTLINK`;
- final-image changes invalidating the generated header again;
- two concurrent output writers;
- stale generated data being accepted on the next invocation;
- an old bootstrap manifest remaining in the final image;
- different KMI or `O=` builds sharing one source-tree header.

### Option B: intermediate ELF

The current `.tmp_vmlinux.kallsyms2` is an analyzable intermediate executable in
this particular build, but it is created after KSU objects have already compiled.
It therefore does not make a generated header available to the first KSU compile.

`vmlinux.o` is an `ET_REL` relocatable object with section-relative addresses and
relocations. It is not safe input to the current analyzer. Supporting it would
require applying AArch64 `R_AARCH64_CALL26`/`JUMP26` relocations across executable
sections and handling linker veneers. That would add a second binary-analysis
implementation before the final-image analyzer is correct.

### Option C: separate discovery build

A dedicated discovery link could be made to compile KSU without generated data,
link a discovery executable, analyze it, and then perform the final build. This is
functionally another two-pass build. It is potentially cleaner than mutating the
normal link recipe, but still needs an explicit driver and isolated outputs. It
does not exist in the current Kbuild and was not implemented because the policy
and generated-data model first need to be corrected.

## Phase 14 Analyzer Audit

### Current interface

The actual CLI is:

```text
python3 tools/bl-analyzer/bl_discover.py \
  --vmlinux VMLINUX \
  --sysmap SYSMAP \
  [--output-c HEADER] \
  [--output-json JSON]
```

The module docstring advertises `--output` and `--json`, but the parser accepts
only `--output-c` and `--output-json` at `tools/bl-analyzer/bl_discover.py:299-305`.

The analyzer reads symbols from `nm` and `.text` from `readelf`:

- `tools/bl-analyzer/bl_discover.py:90-115`
- `tools/bl-analyzer/bl_discover.py:117-141`

The required `--sysmap` argument is never opened, parsed, hashed, or compared.

### Current output

The C output is only initializer fragments:

- `tools/bl-analyzer/bl_discover.py:335-346`

It has no:

- include guard;
- complete declaration;
- family-specific array boundary;
- target-to-wrapper association;
- schema version;
- machine-readable image identity;
- source-policy version;
- generated-data validation function.

It is not a drop-in replacement for the private runtime structure declared at
`branch_link_hook.c:109-118`.

The JSON output is an array of only the three modeled families and is written at:

- `tools/bl-analyzer/bl_discover.py:348-367`

### Confirmed output defects

1. **Duplicate caller rows**

   The loop at `bl_discover.py:221-231` appends every site even when a caller has
   already been seen. Current output repeats callers such as `do_faccessat`,
   `ksys_chdir`, `vfs_rename`, and `link_path_walk`. The runtime processes each
   row independently; the second row then sees already-patched sites and can
   fail the required transaction.

2. **KSU-internal coverage loss**

   The analyzer rejects every selected caller beginning with `ksu_` at
   `bl_discover.py:205-208`. The runtime deliberately requires KSU-internal
   d_path and getname-kernel callers at `branch_link_hook.c:1114-1124` and
   `branch_link_hook.c:1310-1313`. A universal prefix exclusion cannot preserve
   current coverage.

3. **Incomplete family model**

   `FAMILIES` at `bl_discover.py:268-293` contains only:

   - `slow_avc_audit`;
   - `inode_permission`;
   - `d_path`.

   The runtime has additional getname, iterate, faccess, readlink, stat, statfs,
   open, getattr, mount, and exec routes with different target/wrapper policies.

4. **Required drift returns success**

   Drift is assigned at `bl_discover.py:237-244`, but no drift is converted into a
   nonzero process exit. `main()` reaches the successful completion path at
   `bl_discover.py:369-372` regardless of required failure.

5. **System.map is ignored**

   Supplying a missing or unrelated System.map produces the same analysis result
   as supplying the matching map. This is incompatible with an exact binary-pair
   identity requirement.

6. **Incomplete identity hash**

   The tool hashes only one 16 MiB prefix of vmlinux at `bl_discover.py:307-310`.
   The value is stored only as a C comment. It is not the final raw Image hash,
   is absent from JSON, and is not checked by the compiler or runtime.

7. **Function-boundary validation is absent**

   `lookup()` uses only the nearest preceding accepted symbol at `bl_discover.py:78-82`.
   It does not prove `caller.addr <= site < caller.addr + caller.size`. The
   calculated positive-size address list at `bl_discover.py:187-188` is unused.

8. **Mapping symbols and aliases are accepted**

   The parser accepts zero-size three-field text symbols at `bl_discover.py:108-113`
   and accepts weak symbols. Current ELF files contain large numbers of `$x.*`
   mapping symbols and duplicate-address aliases. These are not reliable runtime
   caller names.

9. **Section coverage is incomplete**

   Only the exact `.text` section is scanned. `.init.text`, `.exit.text`,
   `.altinstr_replacement`, and other executable sections are not modeled. If
   init text is intentionally excluded, that must be an explicit family policy;
   it cannot be described as full `ALL_DIRECT_CALLERS` coverage.

10. **Raw Image input is not supported**

    The report claims a matching Image/System.map pair can be used, but the
    implementation invokes `nm` on the `--vmlinux` path. A raw Image is not an
    ELF and is rejected by the current parser.

11. **No baseline or exact drift comparison**

    `DRIFT_RELOCATED`, `DRIFT_NEW_VALID_SITE`, `DRIFT_AMBIGUOUS`, and related
    states are described in the report but are not produced by the code. There
    is no prior site-set comparison and `min_sites` is a manually chosen count.

12. **Malformed output is possible**

    Symbol names are interpolated into C strings without escaping. Widths are
    not checked against the runtime `u16` field. C and JSON are written
    separately and non-atomically.

### Direct verification

Running the current analyzer against the actual lisa vmlinux with a nonexistent
System.map produced:

```text
avc:        7 sites, DRIFT_NONE
permission: 46 sites, DRIFT_NONE
dpath:      11 sites, DRIFT_REMOVED_SITE
analyzer_exit=0
```

This confirms that required drift is currently fail-open at the tool boundary.

## Runtime Manifest Architecture

The runtime structure is:

```c
struct ksu_bl_manifest_caller {
        const char *name;
        u8 classification;
        unsigned int min_sites;
        u16 width;
};
```

See `branch_link_hook.c:109-118`.

`ksu_bl_record_patch_manifest()` treats each row as one caller contract:

- unsupported rows are logged and skipped;
- required rows contribute to `required_total`;
- the caller is resolved by name at runtime;
- all matching sites in that caller are patched;
- the returned count must satisfy that row's `min_sites`;
- every required row must commit;
- failure restores records from the start of that manifest.

See `branch_link_hook.c:804-877`.

This means a generated manifest must be **one row per caller**, not one row per
physical site. The generated data must preserve classifications and route context.
It cannot merge all targets into one array because the runtime target and wrapper
are passed separately to each family or route.

### Source policy

The following remain source-owned semantic policy:

- target/wrapper ABI relationship;
- required, optional, and unsupported status;
- route target alternatives;
- shared function-pointer slot ownership;
- KSU-internal recursion rules;
- syscall ABI and compat selection;
- route grouping and atomic retirement;
- family-level safety floors.

### Build-generated data

The following can be derived from the exact linked binary:

- caller symbol address/name after canonical symbol filtering;
- direct BL site address and offset;
- exact original instruction word;
- target address;
- proven caller function extent;
- safe scan width;
- complete-image and matching-map identity;
- discovered site/caller counts;
- accepted and rejected candidate diagnostics.

The present runtime still has manual caller arrays at multiple locations. The
Phase 14 generated artifacts do not replace them and would reduce coverage if
used as a replacement.

### KSU-internal policy

KSU-internal inclusion cannot be decided by a global name prefix. Current policy
intentionally includes internal callers for d_path and getname-kernel because the
retired symbol-scoped probes covered them. Other route wrappers have different
recursion and scope requirements. The generator needs explicit source policy for
these cases, not a universal `ksu_` exclusion or inclusion rule.

## Stale-Manifest Protection

The requested stale protection is not implemented.

Current behavior:

- generated C contains a prefix-only vmlinux hash comment;
- JSON contains no image hash;
- the final Image is never hashed or compared;
- System.map is never read;
- `.config`, compiler, linker, analyzer version, source policy, and schema are
  not bound;
- the runtime never validates generated metadata identity;
- stale generated files are not deleted when analysis fails;
- analyzer failure may still return status 0.

The correct future design must bind at least:

```text
full vmlinux digest
full raw Image digest
full System.map digest
configuration digest
tool/schema/policy version
kernel build identity / build ID where available
```

The identity record must be produced atomically with the generated manifest and
must be checked before a generated header becomes compile input. A hash embedded
inside the header that changes the final linked image is self-referential and
cannot be used naively in a two-pass fixed-point build. Identity should therefore
be kept in a separate validated sidecar, or the exact compile-input hash must be
defined so it excludes self-generated content.

## Build-Integration Test Matrix

No Phase 15 implementation tests were run because the dependency and generator
contracts are not safe yet. The required outcomes are recorded below.

| Test | Status | Reason |
|---|---|---|
| Clean build | **BLOCKED** | No automatic analyzer target exists; generated header is not a Kbuild input. |
| Incremental build | **BLOCKED** | No dependency graph or artifact stamp exists; stale acceptance is possible. |
| Layout drift | **STATIC EVIDENCE ONLY** | Phase 14 analyzer can observe address changes for tested direct BL sites, but cannot feed the runtime safely. |
| New caller | **STATIC EVIDENCE ONLY** | Direct full-text scan can find a new caller, but generated output is not integrated and no controlled source test exists. |
| Removed required site | **FAIL** | Current analyzer reports drift but exits 0. |
| Stale artifact | **FAIL** | Hash is prefix-only, not tied to Image/System.map/config, and is not enforced. |
| Analyzer failure | **FAIL** | Missing System.map is ignored; malformed inputs can produce raw tracebacks or inconsistent output. |
| Generated corruption | **NOT RUN** | No consumer or validation stamp exists. |
| Parallel build | **BLOCKED** | No generated target or atomic output transaction exists. |
| Two O= trees | **UNSAFE** | Current generated files are under the source tree and would be shared. |
| Runtime regression | **NOT RUN** | No Phase 15 kernel was built or flashed. |
| Performance | **UNCHANGED** | No runtime code was modified; Phase 12 baseline remains the only measured result. |

Before implementation, these tests must be made real rather than represented by
report text. Each failure must cause a nonzero build result.

## Linux 4.19 / 5.4 Compatibility

### Linux 5.4

The current vendor tree is Linux 5.4.302. It supports the generic `ARCH_POSTLINK`
variable in the top-level Makefile at `/home/meow/lisa_kernel/Makefile:1238`, but
there is no ARM64 post-link file in the current tree. A post-link analyzer can be
added as a validation artifact, but it cannot make a final-image header available
to objects already compiled into that image.

The output tree must be used for generated data. `O=` is resolved through the
top-level Makefile, while the KSU symlink resolves source paths through
`KSU_KERNEL_DIR` in `kernel/Kbuild:322-328`. Writing a manifest under the KSU
source checkout would make different output directories or KMI builds share one
file.

### Linux 4.19

The available local 4.19 tree also has the generic post-link variable, but no
ARM64 post-link implementation was found. The same dependency result applies:
ordinary Kbuild can express an acyclic post-link sidecar, not a header whose
producer depends on the same final vmlinux that consumes it.

The canonical compatibility table in `docs/README.md:194-203` labels 4.19 as
untested, while older focused documents still describe 4.19 as a primary or
supported target. That documentation inconsistency is itself unresolved and
must be corrected before making a 4.19 support claim. Python portability alone
is not evidence of 4.19 Kbuild or runtime compatibility.

### Android/vendor/GKI

The vendor setup uses recursive Make and a symlinked in-tree KSU directory. Newer
GKI layouts also differ in symbol aliases, executable sections, inlining, target
ABIs, and route shapes. A generator must be invoked with the selected `NM`,
`READELF`, `OBJCOPY`, and related Kbuild tools, not assume bare host `nm` and
`readelf`.

The current `docs/README.md:205-221` also describes boot-time Image/System.map
discovery and validation, while the actual runtime still uses hand-maintained
arrays and the Phase 14 generated files have no source consumer. That wording is
stale relative to the current implementation and must not be used as evidence
that automatic build integration already exists.

## Security and Correctness Review

The following fail-open paths were identified:

- required analyzer drift returns status 0;
- ignored System.map allows unverified input pairing;
- prefix-only hash does not identify the final Image;
- generated C is not structurally validated;
- duplicate rows can cause a runtime transaction failure;
- aggregate `min_sites` can hide loss of a particular required caller;
- KSU-internal exclusion loses validated coverage;
- mapping symbols can become unusable runtime caller names;
- no exact executable-section or function-containment proof exists;
- no baseline distinguishes relocation, addition, and removal;
- no atomic C/JSON/stamp transaction exists;
- source-tree output can be shared by separate `O=` builds;
- existing runtime fallback/readiness behavior does not constitute a build-time
  proof of generated metadata validity.

The existing runtime BL verifier remains the correct safety authority for actual
text modification:

- direct BL opcode validation;
- exact decoded target validation;
- branch-range validation;
- compare-and-patch through `ksu_patch_text_compare()`;
- record tracking and rollback;
- family readiness gates.

Phase 15 must preserve that authority. It must not replace it with generated
absolute addresses or trust raw analyzer output without runtime verification.

## Files Examined

- `tools/bl-analyzer/bl_discover.py`
- `tools/bl-analyzer/generated_manifest.h`
- `tools/bl-analyzer/generated_manifest.json`
- `kernel/Kbuild`
- `kernel/Makefile`
- `kernel/setup.sh`
- `kernel/hook/arm64/branch_link_hook.c`
- `kernel/infra/symbol_resolver.c`
- `kernel/infra/symbol_resolver.h`
- `kernel/Kconfig`
- `docs/README.md`
- `/home/meow/lisa_kernel/Makefile`
- `/home/meow/lisa_kernel/scripts/link-vmlinux.sh`
- `/home/meow/lisa_kernel/arch/arm64/Makefile`
- `/home/meow/lisa_kernel/arch/arm64/boot/Makefile`
- `/home/meow/lisa_kernel/scripts/Makefile.build`
- `/home/meow/lisa_kernel/scripts/Kbuild.include`
- `/home/meow/lisa_kernel/arch/arm64/configs/lisa_defconfig`

## Files Changed

Only this report and the ignore entry for the pre-existing Phase 14 audit
directory were added. No production implementation was changed.

The existing Phase 14 source-tree generated files remain historical evidence and
are not treated as runtime inputs:

- `tools/bl-analyzer/generated_manifest.h`
- `tools/bl-analyzer/generated_manifest.json`

Generated output for any future implementation must live below the active `O=`
object tree and must not be written to `/tmp` or the shared source checkout.

## Git State

Local repository state after recording this blocker:

- branch: `susfs+nomount-hookless`;
- Phase 14 commits remain untouched;
- Phase 15 report committed locally with the accompanying ignore entry;
- Phase 14 audit artifacts ignored but preserved;
- parent vendor repository retains its pre-existing
  `arch/arm64/configs/lisa_defconfig` modification;
- no vendor functional source changes;
- no generated Phase 15 runtime manifest;
- no Phase 15 kernel package or flash artifact;
- no remote push.

## Required Follow-Up Architecture

If Phase 15 is resumed, implementation should proceed in this order:

1. Correct and test the analyzer independently before any Kbuild integration.
2. Define a complete source policy for every route, target alternative, ABI,
   required/optional/unsupported caller class, and approved KSU-internal caller.
3. Generate one complete typed family/route manifest per build, with no duplicate
   caller rows and no generated absolute runtime addresses.
4. Bind the manifest transaction to the full vmlinux, Image, System.map, config,
   policy, schema, and tool identity.
5. Add atomic output and nonzero failure behavior.
6. Prove the analyzer against synthetic malformed, drifted, aliased, sectioned,
   and boundary cases.
7. Decide explicitly whether the project accepts an outer two-pass build driver.
8. If yes, implement guarded isolated two-pass orchestration and a final stable
   re-analysis pass. Do not encode the cycle as ordinary Kbuild prerequisites.
9. Have fresh independent build-system, binary-analysis, security, and
   compatibility reviewers audit the implementation.
10. Only then run the current lisa `-j1` build, package, flash, and runtime suite.

## Required Final Question

**Does a future kernel developer currently need to manually maintain the BL
manifest?**

**Yes, currently.** Phase 15 did not reach the requested automatic end state
because the only existing manifests are still hand-maintained runtime arrays.

The truthful answer can become **No** only after a safe two-pass or equivalent
outer build orchestration is implemented, the generated data replaces all
manual caller/site/width maintenance without losing route policy, and the full
stale/race/failure test matrix passes.

## Final Verdict

```text
BLOCKED
```

This is an intentional stop under the user's stated stop conditions. The unsafe
alternatives would either paper over a circular dependency, accept stale or
malformed metadata, or silently reduce hook coverage.

**NO PUSH PERFORMED.**
