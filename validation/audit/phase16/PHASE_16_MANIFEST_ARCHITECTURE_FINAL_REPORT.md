# PHASE 16 - COMPLETE BL MANIFEST MODEL & SAFE TWO-STAGE BUILD ARCHITECTURE

## Final Status

**BLOCKED - architecture defined, production implementation intentionally not
committed.**

Phase 16 completed the required independent investigations, reconciled their
results against the actual repository and build artifacts, and selected the
architecture that should be used for a future implementation. The phase did not
wire generated metadata into the runtime or Kbuild because the current analyzer
and runtime contract are not yet safe enough to support that change.

This is an intentional stop under the requested stop conditions. A naive generated
header prerequisite would create a real circular dependency. A post-link-only
recipe would be too late for built-in KSU compilation. The current Phase 14
analyzer would also permit required drift, lose required KSU-internal callers,
ignore `System.map`, and generate data that is not structurally compatible with
the runtime manifest consumer.

The complete audit is stored at:

```text
validation/audit/phase16/PHASE_16_MANIFEST_ARCHITECTURE_FINAL_REPORT.md
```

No production Kbuild, runtime, vendor functional source, or generated-manifest
consumer was modified during this phase. No Phase 16 kernel build, package,
flash, or device regression was performed. No push was performed.

## Executive Summary

The requested end state is not achievable by adding one ordinary Kbuild
prerequisite. The active architecture is:

```text
drivers/kernelsu -> KernelSU-Next/kernel
        -> KSU built-in.a
        -> vmlinux.o
        -> final vmlinux
        -> System.map
        -> arch/arm64/boot/Image
```

`branch_link_hook.o` is compiled while the KSU built-in archive is assembled.
The final `vmlinux` and `System.map` do not exist until after that compilation.
Consequently, this requested relationship is circular:

```text
branch_link_hook.o
    -> generated_manifest.h
    -> analyzer(final vmlinux/System.map/Image)
    -> final vmlinux
    -> branch_link_hook.o
```

One viable architecture identified for a future compile-in implementation is:

```text
outer build coordinator
    -> bootstrap KSU manifest-independent object/data
    -> discovery vmlinux + System.map + derived Image
    -> corrected offline analyzer
    -> object-tree generated manifest data
    -> final KSU manifest-data object rebuild
    -> final vmlinux + System.map + Image
    -> independent final-image analyzer
    -> bounded fixed-point and identity verification
    -> package only after final commit marker
```

The generated data should be a separate object-tree artifact. `branch_link_hook.c`
should consume a stable source-owned schema and accessor, while wrappers, target
alternatives, ABI bindings, route grouping, fallback retirement, and semantic
policy remain source-controlled.

The two-stage process must be an explicit outer coordinator. It must not be
encoded as:

```text
generated_manifest.h: vmlinux
vmlinux: generated_manifest.h
```

and it must not recursively invoke the complete Android wrapper twice, because
Android wrappers perform configuration, installation, distribution, and packaging
steps that are not safe to repeat as discovery actions.

## Delegated Investigations

The required independent investigations were delegated before production changes.
Seven primary investigations and four additional design/feasibility reviews were
completed. No delegated agent was authorized to edit production files.

| Agent | Scope | Conclusion |
|---|---|---|
| Agent A | Existing runtime manifest architecture | Runtime still uses hand-maintained arrays. Each row is a caller contract, not a physical site. Route alternatives and transaction groups are source policy. |
| Agent B | Phase 14 analyzer implementation | Analyzer is not a safe build gate: required drift exits 0, System.map is ignored, duplicate rows are emitted, sections and symbol roles are incomplete, and output is not a complete header. |
| Agent C | Complete hook-family discovery | Runtime combines direct BL, syscall-table, function-pointer, ops-table, LSM, source-policy, and fallback mechanisms. They cannot all be reduced to one BL model. |
| Agent D | Kbuild/two-stage architecture | A final-image generated header creates a cycle. A guarded outer two-stage coordinator is the only practical compile-in design; `ARCH_POSTLINK` can coordinate but is not an ordinary header prerequisite. |
| Agent E | Stale-manifest/security model | Full artifact identity must be external to self-referential compiled data. Atomic publication, output-tree isolation, transaction markers, and final-image verification are mandatory. |
| Agent F | Binary-analysis correctness | ARM64 direct-BL arithmetic is correct locally, but mapping symbols, aliases, boundaries, executable sections, BLR, veneers, inlining, and route completeness are not handled safely. |
| Agent G | Linux 4.19/5.4 compatibility | Both Kbuild versions have a post-link mechanism, but neither permits a same-pass final-image header dependency. 5.4 is the validated target; 4.19 remains experimental/untested for this integration. |
| Additional review | Generated runtime model | A generated object can work only as name-based, per-route metadata joined with source policy. Generated absolute addresses and a flat site list are unsafe. |
| Additional review | Selector automation | Binary facts such as caller sites, offsets, and widths can be automated. Requiredness, ABI, target alternatives, ownership, and fallback semantics cannot be inferred reliably from BL instructions. |
| Additional review | Feasibility | Full Phase 16 implementation should stop. A partial analyzer-only effort is possible, but wiring incomplete output into runtime would be unsafe. |
| Additional review | Post-link driver | `ARCH_POSTLINK` is useful as a synchronous coordinator only when guarded and paired with an explicit final-stage re-entry. |

The agent responses are session evidence rather than committed repository
artifacts. Every safety-critical conclusion below was independently checked
against source files or actual build outputs.

## Reconciled Architecture Questions

### 1. What is source policy?

Source policy is the semantic and ABI contract that binary structure cannot prove:

- semantic family and route identity;
- target symbol and wrapper relationship;
- wrapper ABI variant;
- native versus compat selection;
- required, optional, and unsupported classification;
- KSU-internal caller inclusion/exclusion;
- target alternatives and their order;
- route grouping and rollback boundaries;
- original-function slot ownership;
- fallback mechanism and retirement condition;
- executable-section lifecycle policy;
- module versus built-in scope;
- direct-BL versus indirect/ops-table coverage contract;
- family-level safety invariant;
- record-capacity policy;
- tool, schema, and policy revisions.

The source policy must remain trusted source material. It must never be regenerated
from a previous generated manifest or from an aggregate site count.

### 2. What is generated binary metadata?

Generated metadata is the exact build-specific result of analyzing the linked
binary under the source policy:

- canonical caller symbol;
- caller function start and end;
- caller section;
- target symbol and target address for diagnostics;
- physical direct-BL site offsets;
- original instruction words;
- discovered site count;
- safe scan width;
- target alternative selected for a route/caller;
- accepted and rejected candidate diagnostics;
- full artifact identities;
- analyzer, schema, and policy identity.

Runtime names and route IDs may be embedded. Absolute addresses must not be used as
runtime patch authority because KASLR, relocation, linker layout, and separate
builds change them. The existing runtime must continue to resolve names and verify
the live instruction before patching.

### 3. What must remain manually defined?

The future system can remove manual per-kernel caller/site/width maintenance, but
it cannot remove all source policy. The following remain manually defined semantic
policy:

- route-specific caller scope where a target is shared by unrelated callers;
- allowed KSU-internal callers;
- unsupported syscall wrappers;
- optional configuration-dependent callers;
- route target alternatives;
- wrapper/target ABI variants;
- fallback and retirement groups;
- requiredness and semantic coverage invariants;
- whether ephemeral `.init.text` or module text is in scope;
- whether an indirect operation-table path is covered elsewhere.

The truthful target is **no manual per-build manifest maintenance**, not “no
manual policy exists.”

### 4. What can be automatically discovered?

For supported direct-BL routes, the corrected analyzer can automatically derive:

- direct BL instructions in approved executable sections;
- exact decoded target;
- canonical function caller;
- caller-relative site offset;
- number of sites per caller;
- function-boundary-derived scan width;
- new callers that satisfy a route selector;
- removed callers or sites compared with the source policy;
- invalid, ambiguous, out-of-bound, aliased, or unsupported candidates;
- final vmlinux/System.map/Image identity.

It cannot safely derive the semantic meaning of every target call. A BL to
`do_filp_open` does not reveal whether it is an open-redirect path, an internal
helper, or a route that must remain untouched. That scope must be policy.

### 5. Can the complete runtime manifest be generated?

It can be materialized from a complete source policy plus binary facts, but not
from direct-BL scanning alone.

The output must preserve all current logical route boundaries, target alternatives,
ABI guards, KSU-internal exceptions, required/optional/unsupported rows, and
transaction groups. A flat list of all BL sites to each target is insufficient.

### 6. What exact artifact is analyzed?

The final analyzer input should be:

```text
final non-stripped vmlinux ELF
final System.map
final raw arch/arm64/boot/Image
active raw .config
effective generated configuration
source-policy input
selected host-tool identities
```

The discovery pass may analyze a fresh discovery vmlinux and a raw Image derived
from that same vmlinux using the selected `OBJCOPY`. It must never read an old
`arch/arm64/boot/Image` merely because the file exists.

`vmlinux.o` is not an equivalent artifact. It is relocatable `ET_REL` input with
section-relative symbols and AArch64 relocations. The current analyzer is not a
relocatable linker and must reject it.

### 7. At what point does analysis occur?

Analysis occurs after a complete link has produced vmlinux and System.map.

For the future staged build:

```text
bootstrap link
    -> discovery analysis
    -> generated manifest

final link
    -> final Image creation
    -> final independent analysis
```

`ARCH_POSTLINK` is late enough to coordinate a child final-stage build because the
parent link has completed. It is too late to be an ordinary prerequisite of the
first KSU object.

### 8. How does generated data reach final KSU compilation?

The future design should use a generated object-tree header/data object included
only by a small stable `branch_link_manifest.c` compilation unit. `branch_link_hook.c`
should consume a stable accessor and schema rather than directly including a
generated fragment.

The bootstrap pass must compile a manifest-independent conservative data object.
The final pass replaces only the generated data object and dependent KSU archive,
then relinks the final kernel.

### 9. How is stale data prevented?

Generated output must be bound to the complete current transaction:

- full vmlinux digest;
- full raw Image digest;
- full System.map digest;
- raw config digest;
- effective config digest;
- source/policy revision;
- schema revision;
- analyzer revision/hash;
- selected compiler, linker, nm, readelf, objcopy, and objdump identities;
- build ID as additional provenance;
- final manifest payload digest;
- commit marker written last.

The old manifest must never be accepted merely because it exists or because its
caller names still resolve.

### 10. How is final-image correctness verified?

After final linking, the analyzer must independently regenerate a canonical final
manifest. The verifier must compare it with the manifest compiled into the final
KSU object. The comparison must include route, target, caller, classification,
minimum site contract, actual site count, offsets, instruction fingerprints, and
scan width.

The final image must also contain a stable compile marker for the manifest schema,
policy, and payload ID. The final artifact stamp must bind the full image files.

### 11. What happens when discovery fails?

The outer build fails with nonzero status. It must remove or invalidate any
generated final metadata and must not reuse a previous manifest.

### 12. What happens when the final image differs from the discovery image?

Address relocation alone is expected. A change in canonical semantic records is
not automatically acceptable. It requires either:

- a bounded regeneration/relink iteration followed by equality; or
- an explicit policy result proving that the changed records are an allowed
  source-shape change.

If the bounded process does not converge, the build fails.

### 13. What is the 4.19 story?

Linux 4.19 and 5.4 both expose a generic post-link mechanism, but that mechanism
is too late for a normal same-pass generated header. The staged driver can be
designed with old Make-compatible constructs, but the current 4.19 runtime and
vendor-wrapper combination are not fully validated.

The canonical `docs/README.md` table marks 4.19 “Untested, likely missing API.”
Older focused documents use stronger support language. That inconsistency remains
unresolved and must not be silently converted into a compatibility claim.

### 14. What is the 5.4 story?

Linux 5.4.302 is the validated reference target. The current Kbuild has the
necessary output-tree and post-link primitives, but no ARM64 post-link integration
or staged manifest driver exists. A 5.4 implementation is technically plausible
after the analyzer and model are corrected, but it was not implemented in Phase 16.

## Existing Runtime Manifest Contract

The runtime caller structure is:

```c
struct ksu_bl_manifest_caller {
        const char *name;
        u8 classification;
        unsigned int min_sites;
        u16 width;
};
```

Defined at:

```text
kernel/hook/arm64/branch_link_hook.c:109-118
```

The semantics are caller-oriented:

- `name` is resolved through runtime kallsyms;
- `classification` is required, optional, or unsupported;
- `min_sites` is a minimum for that one caller row;
- `width` is the scan-window override;
- width `0` selects the default 1024-byte ARM64 scan width;
- the runtime additionally bounds a scan at the next symbol when available.

`ksu_bl_record_patch_manifest()` is defined at:

```text
kernel/hook/arm64/branch_link_hook.c:804-877
```

Its transaction behavior is:

1. Skip and log unsupported rows.
2. Count required rows.
3. Resolve each caller by name.
4. Fail the manifest if a required caller is unavailable.
5. Patch every matching BL in that caller region.
6. Require the result to meet that row’s `min_sites`.
7. Commit only when every required row succeeds.
8. Attempt to restore all records created by the manifest on failure; a failed
   restore can leave conflict records and a non-clean runtime state.

The current Phase 14 output emits one row per physical site. That is incompatible
with this consumer. If a caller has two BL sites, it must have one row with
`min_sites = 2`, not two identical required rows.

The runtime patch authority must remain:

- direct BL opcode validation;
- decoded target equality;
- branch range and alignment validation;
- compare-before-write text patching;
- record tracking;
- reverse-order rollback;
- conflict detection;
- family readiness gates.

Generated data must not bypass those checks.

The existing transaction helpers also require a fresh review before they can be
declared unchanged under the generated alternative-target model. In particular,
`ksu_bl_record_patch_all_width()` can return a positive partial count when a
caller does not meet its minimum, while `ksu_bl_record_patch_routes()` then tries
another target. The route helper does not necessarily roll back that partial
candidate before trying the next target, and it writes the candidate target's
original-function slot before patching. The next alternative therefore needs both
text-record rollback and function-pointer-slot rollback. This is latent in the
current Lisa single-site profile but is unsafe for generalized generated target
alternatives. The generated integration must either add per-candidate rollback
for records and slots or prove that every alternative route cannot produce a
partial positive result.

There are additional existing runtime hazards that are outside the analyzer but
must not be hidden by this phase:

- `ksu_bl_records_all_restored()` checks active records but not every retained
  conflict state, while failure paths may clear a function slot;
- late global conflict detection can occur after earlier fallback probes have
  already been retired, without re-registering those probes;
- the AVC fallback kprobe is not explicitly retired when the AVC BL family
  succeeds on a probe-enabled build;
- some required compat rows are not consistently guarded by `CONFIG_COMPAT`;
- `search_manager` is required by the iterate route but disappears when manager
  objects are disabled;
- compat syscall-table restoration is not a general mirror transaction.

These are reasons to keep the runtime transaction and fallback review separate
from the analyzer implementation. Generated metadata must not be used to claim
that these existing issues have been fixed.

## Complete Direct-BL Family Inventory

The following inventory covers all current direct-BL routes and source policy
boundaries. It is not a claim that every route is suitable for global
`ALL_DIRECT_CALLERS` discovery.

| Route ID | Target and wrapper | Policy boundary | Group/fallback |
|---|---|---|---|
| `permission/inode_permission` | `inode_permission` -> `ksu_do_inode_permission`; original slot `inode_permission_fn` | Direct BL callers of the permission helper. `generic_permission` is intentionally not a separate route because the runtime relies on the nested inode-permission path. | Permission family; NoMount permission return-probe fallback. |
| `dpath/d_path` | `d_path` -> `ksu_do_dpath`; slot `d_path_fn` | Every old symbol-scoped d_path call must remain covered, including approved KSU-internal callers and the weak `path_mount` shim. | d_path family; NoMount d_path kretprobe fallback. |
| `avc/slow_avc_audit` | `slow_avc_audit` -> `ksu_do_slow_avc_audit`; slot `slow_avc_audit_fn` | Only active when `CONFIG_AUDIT=y`; wrapper ABI is source/profile dependent and must be verified. | AVC audit family; current AVC kprobe fallback is not retired by branch-link code. |
| `getname/getname_flags` | `getname_flags` -> `ksu_nomount_getname_flags`; complete replacement, no original slot | Direct callers that formerly entered the PC-redirect kprobe. Native/compat and syscall wrapper shape must be policy-controlled. | Grouped with getname-kernel and iterate probe retirement. |
| `getname/getname_kernel` | `getname_kernel` -> `ksu_nomount_getname_kernel`; complete replacement | Includes approved KSU callers that formerly flowed through the symbol-scoped probe. | Grouped with getname-flags and iterate. |
| `iterate/iterate_dir` | `iterate_dir` -> `ksu_nomount_iterate_dir`; complete replacement | Includes native, compat, filesystem, and `search_manager` rows according to policy. | Grouped with getname routes. |
| `faccessat/do_faccessat` | `do_faccessat` -> `ksu_do_faccessat`; slot `do_faccessat_fn` | Syscall entry scope only. ABI changes with `__NR_faccessat2`, `KSU_HAS_FACCESSAT2`, and version/source shape. | Syscall dispatcher fallback remains until ready. |
| `readlink/do_readlinkat` | `do_readlinkat` -> `ksu_do_readlinkat`; slot `do_readlinkat_fn` | Native syscall wrapper required; optional wrapper and unsupported compat wrappers remain explicit. | NoMount lookup scope fallback. |
| `stat-path` | `vfs_fstatat` or `vfs_statx` -> corresponding KSU wrapper and slot | Ordered target alternatives; syscall-entry caller scope; target choice depends on version/source shape. | Syscall stat fallback. |
| `stat-fd` | `vfs_fstat` -> `ksu_vfs_fstat`, or `vfs_getattr_nosec` -> `ksu_vfs_getattr_nosec_fd` | Optional enrichment. Must not be merged with the global getattr-interior route because the slots and wrappers differ. | Existing getattr/stat layer remains authoritative when absent. |
| `statfs-path/user_statfs` | `user_statfs` -> `ksu_user_statfs`; shared `vfs_statfs_fn` | User-path syscall wrappers and optional AArch32 shape. | Atomic with fd-statfs route. |
| `statfs-fd/fd_statfs` | `fd_statfs` -> `ksu_fd_statfs`; shared `vfs_statfs_fn` | FD syscall wrappers and optional AArch32 shape. | Atomic with user-statfs route; kretprobe fallback. |
| `open-scope/do_sys_open` | `do_sys_open` -> `ksu_do_sys_open`; slot `do_sys_open_fn` | Syscall entry scope only; `__arm64_sys_open` is explicitly unsupported even if the symbol exists. | NoMount directory-fd lookup scope. |
| `susfs/do_filp_open` | `do_filp_open` -> `ksu_do_filp_open`; slot `do_filp_open_fn` | `do_sys_open` versus `do_sys_openat2` depends on openat2 source shape. KSU helper callers need explicit treatment. | SUSFS open redirect readiness. |
| `susfs/vfs_getattr_nosec` | `vfs_getattr_nosec` -> `ksu_vfs_getattr_nosec`; slot `vfs_getattr_nosec_fn` | Direct helper-interior site(s), currently `exportfs_get_name` on Lisa. Must not claim indirect `i_op->getattr` routes. | Universal getattr funnel; NoMount return fallback. |
| `susfs/vfs_create_mount` | `vfs_create_mount` -> `ksu_vfs_create_mount`; slot `vfs_create_mount_fn` | Source/version-dependent mount callers and optional inlined forms. | Atomic with clone and cleanup mount routes. |
| `susfs/clone_mnt` | `clone_mnt` -> `ksu_clone_mnt`; slot `clone_mnt_fn` | `mnt_clone_internal`, `copy_tree`, `clone_private_mount`, and version-dependent loopback caller. | Atomic mount group. |
| `susfs/cleanup_mnt` | `cleanup_mnt` -> `ksu_cleanup_mnt`; slot `cleanup_mnt_fn` | Required cleanup callers. | Atomic mount group. |
| `exec/common` | `do_execveat_common` -> `ksu_do_execveat_common`; slot `do_execveat_common_fn` | Common helper profile; native and compat syscall-entry callers. | Complete common exec transaction. |
| `execve/legacy` | `__do_execve_file` then `do_execve` alternatives; wrappers `ksu_do_execve_file` / `ksu_do_execve` | Native `execve` caller only, with target and wrapper alternatives kept together. | Exec group. |
| `execveat/legacy` | `__do_execve_file` then `do_execveat` alternatives; wrappers `ksu_do_execve_file` / `ksu_do_execveat` | Native `execveat` caller only when syscall exists. | Exec group. |
| `compat_execve/legacy` | `__do_execve_file` then `compat_do_execve`; wrappers `ksu_do_execve_file` / `ksu_compat_do_execve` | Compat `execve` ABI and source target alternatives. | Exec group. |
| `compat_execveat/legacy` | `__do_execve_file` then `compat_do_execveat`; wrappers `ksu_do_execve_file` / `ksu_compat_do_execveat` | Only when compat execveat source support exists. | Exec group. |

### Active versus conditional fallback state

The route inventory describes fallback implementations that exist in source, but
their runtime availability depends on configuration. In the current Lisa output
profile, `CONFIG_KPROBES=n` and `CONFIG_KRETPROBES=n`, so the AVC, d_path,
getattr, statfs, and NoMount probe fallbacks are not active. The reference profile
therefore relies on the zero-probe branch-link/table/operation mechanisms and
their readiness gates. The fallback descriptions above apply to probe-enabled
compatibility profiles and must not be interpreted as active rescue paths on the
current Lisa image.

The source still defines the experimental whole-text runtime helper
`ksu_branch_link_discover_family()` at `branch_link_hook.c:652`, but the current
initialization path does not call it. Production initialization calls the
hand-maintained family functions from `branch_link_hook.c:2812-2916`. The helper
and its Phase 13 keep-alive dependency are uninvoked experimental code, not
evidence that the active runtime already performs automatic discovery.

### Current caller policy details

#### Permission

The runtime currently has a mixed required/optional caller policy beginning at:

```text
branch_link_hook.c:943-1001
```

Required rows include `prctl_set_mm`, `cgroup_procs_write_permission`, BPF
permission callers, mincore/madvise callers, truncate/chdir/chroot paths,
creation/rename paths, xattr/inotify paths, overlay permission, and the
multi-site callers:

```text
do_faccessat       min_sites=2
ksys_chdir         min_sites=2
ksys_chroot        min_sites=2
vfs_rename         min_sites=3
link_path_walk     min_sites=2
```

The current optional rows include:

```text
fsverity_ioctl_enable
configfs_symlink
fuse_open_backing
fuse_access_backing
unix_find_other
```

The current generated Phase 14 artifact incorrectly marks every discovered row
required. A future generator must join policy requiredness with binary facts.

#### d_path

The source d_path manifest is at:

```text
branch_link_hook.c:1093-1127
```

All rows are required because the former hook was symbol-scoped. Approved KSU or
KSU-owned rows include:

```text
path_mount
ksu_wrapper_d_dname
ksu_mnt_ns_setns_task
ksu_install_rc_hook
ksu_sys_fstat
ksu_susfs_fdinfo_show
ksu_nomount_build_path_from_dfd       min_sites=2
ksu_nomount_handle_fd_getattr
ksu_nomount_handle_statfs_path
ksu_nomount_collect_ancestors
```

The analyzer’s global `caller.startswith("ksu_")` exclusion is therefore invalid.
It also cannot classify `path_mount` solely by name because `path_mount` is an
unprefixed weak KSU compatibility shim.

The analyzer independently found `audit_log_d_path`, which is not present in the
current hand-maintained array. This is precisely the kind of new live caller that
the generated system must surface for an explicit source-policy decision rather
than silently include or silently ignore.

#### AVC

The Lisa AUDIT=y profile has seven required caller rows at:

```text
branch_link_hook.c:1200-1211
```

They are:

```text
avc_has_extended_perms
avc_has_perm
avc_has_perm_flags
selinux_capable
selinux_file_ioctl
audit_inode_permission
has_cap_mac_admin
```

The wrapper ABI is not universally stable. `extras.c` documents multiple
`slow_avc_audit` signatures across kernel ranges. A binary target name alone does
not prove that the nine-argument Lisa wrapper matches a future target.

#### getname and iterate

The direct replacement caller arrays are at:

```text
branch_link_hook.c:1261-1276
branch_link_hook.c:1298-1314
branch_link_hook.c:1335-1345
```

The getname-kernel array deliberately includes:

```text
ksu_nomount_rebase_execve_filename
ksu_do_filp_open             min_sites=2
ksu_susfs_open_redirect_getname
```

The iterate array deliberately includes `search_manager`, a KSU manager caller
whose name does not start with `ksu_`. It disappears when manager objects are
disabled, so its requiredness must be conditional on `CONFIG_KSU_DISABLE_MANAGER`.

The current getname-flags and iterate arrays also contain required compat rows
without the same explicit `CONFIG_COMPAT` guards used by stat routes. That source
policy defect must be resolved before generated policy claims compatibility.

#### Stat and getattr

Stat paths have multiple independent semantics:

- stat-path uses `vfs_fstatat`/`vfs_statx` target alternatives;
- stat-fd uses optional `vfs_fstat`/`vfs_getattr_nosec` alternatives;
- getattr-interior uses a different `vfs_getattr_nosec` wrapper and slot;
- indirect inode-operation calls are not direct BL sites;
- old-stat and compat routes may be handled by a different return layer.

The source explicitly keeps `vfs_getattr_nosec_fn` separate from
`vfs_getattr_nosec_fd_fn` at:

```text
branch_link_hook.c:1939-1949
```

A target-only global scan would claim the same physical site for two wrappers and
would violate slot ownership.

#### Statfs

The user and fd statfs route arrays are separate:

```text
branch_link_hook.c:2164-2186
branch_link_hook.c:2188-2197
```

Both routes share `vfs_statfs_fn`, but their caller policy and wrapper semantics
are different. The route-level transaction rolls them back together if either
required route fails.

#### Open and mount

Open scope and open redirect are separate mechanisms:

- `do_sys_open` establishes a directory-fd lookup scope;
- `do_filp_open` performs SUSFS redirect logic;
- openat2 changes the target caller shape;
- KSU internal `getname_kernel` calls are part of the redirect path.

Mount routes are also separate but grouped atomically:

```text
vfs_create_mount
clone_mnt
cleanup_mnt
```

Their caller names and requiredness change with source shape and nominal version.

#### Exec

Exec routes cannot be generated by scanning only one target. Native and compat
routes use different wrappers and target alternatives. The current source uses
the `KSU_BL_EXEC_COMMON_PROFILE` condition and separate legacy arrays at:

```text
branch_link_hook.c:2923-3094
```

The policy must keep caller scope, target alternative order, wrapper ABI, original
slot, and transaction group together.

## Non-BL Interception Inventory

The complete runtime architecture includes mechanisms that must not be forced
into the generated direct-BL manifest.

| Mechanism | Current examples | Classification |
|---|---|---|
| Native syscall-table tamper | `setresuid`, `execve`, `newfstatat`, `faccessat`, `reboot`, and SUSFS `uname` | Syscall-table based; source registration and original-slot policy. |
| Compat syscall-table path | Verified compat reboot mirror mapping `88 -> 142` | Syscall-table based; not a general automatic mirror. |
| ksud read/fstat table hooks | Native init `read` and `fstat` wrappers | Syscall-table based; separate lifecycle and removal. |
| Syscall tracepoint fallback | `sys_enter` dispatch when tamper is disabled | Existing tracepoint fallback, not direct BL. |
| LSM list slots | Existing `security_hook_heads` entries | Existing function-pointer/LSM slot replacement. |
| LSM static calls | `static_calls_table` on newer kernels | Existing static-call slot replacement. |
| SELinux status operations | `/sys/fs/selinux/status` open/read | Existing `file_operations`/callback replacement. |
| SELinux write operations | `SEL_CONTEXT` and `SEL_ACCESS` `write_op` slots | Existing operation-table replacement. |
| Proc mount operations | `proc_mounts_operations`, mountinfo, mountstats, fdinfo | Existing `file_operations` replacement. |
| Proc sequence output | maps/smaps `seq_operations.show` | Existing sequence-operation replacement. |
| Proc link operations | fd/map-files `readlink` | Existing inode-operation replacement. |
| Proc map operations | map-files lookup/revalidate/iterate, selected surfaces disabled | Source-policy/ops path; not all active. |
| Proc mem/pagemap | read/write surfaces, selected paths disabled | Source-policy/ops path; not direct BL. |
| Mount namespace operation | `mntns_operations.get` | Existing function-pointer replacement. |
| Proc cmdline | `single_show` or saved command-line pointer | Existing callback/pointer replacement. |
| Dynamic SUSFS inode ops | `i_op.lookup`, `i_fop.iterate*`, `s_op` wrappers | Per-object operation replacement. |
| KSU per-file fops | init.rc file proxy and file-wrapper descriptors | Per-object KSU-owned operation replacement. |
| fsnotify | package observer registration | Existing framework callback, not discovery. |
| input handler | safe-mode volume-key observation | Existing framework callback, not discovery. |
| KSU ioctl dispatch | `ksu_ioctl_handlers[]` | KSU-owned source dispatch. |
| NoMount Generic Netlink | `ksu_nomount_genl_ops[]` | KSU-owned source dispatch. |
| Feature dispatch | `feature_handlers[]` | KSU-owned source dispatch. |

The generated BL model must not claim that these mechanisms are covered merely
because a related helper symbol appears in the ELF.

## Proposed Generated Manifest Model

The future model should use a stable source-owned schema and an object-tree
generated data payload.

### Source-owned schema

The stable schema should define route IDs and data structures such as:

```c
enum ksu_bl_manifest_route_id {
	KSU_BL_ROUTE_PERMISSION_INODE = 0,
	KSU_BL_ROUTE_DPATH,
	KSU_BL_ROUTE_AVC,
	KSU_BL_ROUTE_GETNAME_FLAGS,
	KSU_BL_ROUTE_GETNAME_KERNEL,
	KSU_BL_ROUTE_ITERATE_DIR,
	KSU_BL_ROUTE_FACCESSAT,
	KSU_BL_ROUTE_READLINK,
	KSU_BL_ROUTE_STAT_PATH,
	KSU_BL_ROUTE_STAT_FD,
	KSU_BL_ROUTE_STATFS_PATH,
	KSU_BL_ROUTE_STATFS_FD,
	KSU_BL_ROUTE_OPEN_SCOPE,
	KSU_BL_ROUTE_OPEN_REDIRECT,
	KSU_BL_ROUTE_GETATTR_INTERIOR,
	KSU_BL_ROUTE_CREATE_MOUNT,
	KSU_BL_ROUTE_CLONE_MNT,
	KSU_BL_ROUTE_CLEANUP_MNT,
	KSU_BL_ROUTE_EXEC_COMMON,
	KSU_BL_ROUTE_EXECVE,
	KSU_BL_ROUTE_EXECVEAT,
	KSU_BL_ROUTE_COMPAT_EXECVE,
	KSU_BL_ROUTE_COMPAT_EXECVEAT,
	KSU_BL_ROUTE_COUNT,
};

struct ksu_bl_manifest_caller_data {
	const char *name;
	u32 function_size;
	u16 scan_width;
	u16 min_sites;
	u8 classification;
	u8 flags;
	u16 section_id;
};

struct ksu_bl_manifest_site_data {
	u32 site_offset;
	u32 original_word;
	u16 caller_index;
	u16 flags;
};

struct ksu_bl_manifest_target_data {
	const char *name;
	const struct ksu_bl_manifest_site_data *sites;
	u32 site_count;
};

struct ksu_bl_manifest_route_data {
	u16 id;
	u16 flags;
	u32 caller_count;
	const struct ksu_bl_manifest_caller_data *callers;
	u32 target_count;
	const struct ksu_bl_manifest_target_data *targets;
};

struct ksu_bl_manifest_data {
	u32 magic;
	u16 schema;
	u16 flags;
	u32 route_count;
	u32 policy_revision;
	u8 payload_id[32];
	const struct ksu_bl_manifest_route_data *routes;
};
```

The schema must be source-controlled and must not contain per-build absolute
addresses. `function_size`, `section_id`, `site_offset`, and
`original_word` are build facts that can be kept in the generated object when
the final verifier needs the compiled payload to prove the exact site census.
The `payload_id` must be defined as a canonical digest over the payload with the
identity field excluded or zeroed; it must not be a recursive full-vmlinux hash.
The external final stamp remains the authority for complete artifact hashes.

If the runtime payload is intentionally kept smaller than the audit payload, the
design must say so explicitly and the final verifier must compare the compiled
payload ID against the separately generated full JSON/site record. The schema
cannot claim to carry offsets and instruction fingerprints while defining no
field for them.

### Generated data

The generated output should contain:

- one unique caller row per `(route, caller)`;
- policy classification and `min_sites` copied from trusted source policy;
- analyzer-derived width, checked against runtime `u16` limits;
- per-target site associations;
- site counts and offsets for audit/final verification;
- approved KSU-internal flags;
- route and target IDs;
- observed committed record budget;
- schema/policy/payload identity.

The generated output must not contain:

- runtime wrapper addresses;
- function-pointer slot addresses;
- absolute caller addresses as patch authority;
- absolute target addresses as patch authority;
- unescaped symbol names;
- a single merged array spanning unrelated target/wrapper pairs.

### Caller aggregation

The required normalization is:

```text
route + caller
    -> one caller contract
    -> site_count and site_offsets[]
```

Example:

```text
vfs_rename
    site +0xe4
    site +0x104
    site +0x444

must become:

{ name="vfs_rename", min_sites=3, width=auto, sites=3 }
```

It must not become three identical required rows.

A caller may legitimately appear in two different routes if the wrappers, target
slots, and transaction semantics differ. That is not a duplicate; it is a
different logical policy association.

### Runtime integration boundary

The source runtime should retain source-owned target binding:

```c
struct ksu_bl_manifest_target {
	const char *name;
	unsigned long hook;
	unsigned long *fn_slot;
};
```

The generated route should supply caller facts and target IDs. Source code should
map target IDs to wrapper addresses and original-function slots. This preserves
the distinction between:

- real body address used for direct BL destination comparison;
- canonical CFI address used for indirect function-pointer invocation.

The existing `ksu_bl_record_patch_manifest()`,
`ksu_bl_record_patch_routes()`, and `ksu_bl_patch_exec_route()` should remain the
transaction engines. The generated model should feed them; it should not replace
their runtime instruction checks or rollback behavior.

## KSU-Internal Caller Policy

The current analyzer’s universal prefix filter is not a valid ownership model.

The future policy must explicitly represent:

```text
approved_internal_callers
excluded_regions
target_region
wrapper_region
unclassified_internal = error
```

The following current rows require explicit policy review rather than automatic
prefix filtering:

```text
path_mount
ksu_wrapper_d_dname
ksu_mnt_ns_setns_task
ksu_install_rc_hook
ksu_sys_fstat
ksu_susfs_fdinfo_show
ksu_nomount_build_path_from_dfd
ksu_nomount_handle_fd_getattr
ksu_nomount_handle_statfs_path
ksu_nomount_collect_ancestors
ksu_nomount_rebase_execve_filename
ksu_do_filp_open
ksu_susfs_open_redirect_getname
search_manager
```

Recursion prevention must be explicit. Current wrappers mostly call original
helpers through function-pointer slots, but this should be validated as an ABI and
source invariant rather than inferred from a name prefix.

## Analyzer Audit

The actual Phase 14 analyzer is:

```text
tools/bl-analyzer/bl_discover.py
```

### Interface defects

The implementation accepts:

```text
--vmlinux
--sysmap
--output-c
--output-json
```

The module docstring advertises different flags, `--output` and `--json`.

`--sysmap` is required by argparse but never read. The analyzer obtains symbols
only through `nm` against vmlinux and obtains `.text` through `readelf`.

### Exit-status defects

`discover_family()` assigns `DRIFT_TARGET_MISSING` and `DRIFT_REMOVED_SITE`, but
`main()` always reaches the successful completion path. Required drift returns
status 0.

Direct verification against the Lisa vmlinux with a nonexistent System.map
produced:

```text
avc:        7 sites, DRIFT_NONE
permission: 46 sites, DRIFT_NONE
dpath:      11 sites, DRIFT_REMOVED_SITE
analyzer_exit=0
```

This is a confirmed fail-open behavior.

### Family coverage defects

`FAMILIES` contains only:

```text
slow_avc_audit
inode_permission
d_path
```

The runtime includes all the additional route families documented above. The
Phase 14 report’s broader seven-target claim is not backed by the implementation.

The current analyzer also accepts unsupported input shapes that must be rejected
before integration. The Lisa `out/vmlinux.o` relocatable ELF and the synthetic
x86 fixture can pass through the current parser far enough to produce a
successful or meaningless result because there is no ELF machine/type validation.
A fixture with the target symbol present but no matching site is reported as
`DRIFT_TARGET_MISSING`, even though the target was found. These are current
analyzer defects, not future-only test cases.

### Symbol defects

The parser:

- accepts zero-size three-field text symbols;
- accepts weak symbols without policy;
- admits `$x.*` mapping symbols;
- retains same-address aliases;
- selects aliases based on external `nm` ordering;
- does not validate ELF machine, class, endianness, or file type;
- does not verify that the chosen caller is an actual `STT_FUNC` extent;
- computes a positive-size address list but does not use it for lookup;
- does not reject ambiguous target names or duplicate target definitions.

The analyzer must canonicalize or reject mapping symbols, aliases, weak symbols,
zero-size symbols, and ambiguous ownership before producing runtime data.

### Boundary defects

Caller attribution uses the nearest preceding accepted symbol. It does not prove:

```text
caller_start <= site < caller_start + caller_size
```

Width is calculated from the next accepted symbol address rather than the proven
function extent. A mapping symbol or alias can therefore change both attribution
and width.

The runtime has a `u16` width field; the analyzer does not reject widths larger
than 65535.

### Section defects

Only the exact `.text` section is scanned. Executable sections such as
`.init.text`, `.exit.text`, `.text.*`, and alternative instruction sections are
not modeled.

This must become an explicit policy:

- scan and safely support persistent executable sections;
- explicitly exclude ephemeral init/exit text when it is guaranteed to be gone
  before runtime patching;
- fail closed when a required route exists only in unsupported text;
- never silently describe a partial section scan as `ALL_DIRECT_CALLERS`.

### BLR and veneer defects

The direct BL decoder is locally correct for AArch64 BL. It intentionally does not
resolve BLR or function-pointer calls. That conservative boundary is acceptable
only when the policy explicitly states that indirect paths are covered by a
different mechanism or that their absence is proven.

A BL through a veneer is not an exact BL-to-target match. The analyzer currently
ignores it rather than reporting an unsupported or incomplete required route. A
required route must fail closed if a veneer replaces a required direct site unless
the veneer is explicitly modeled and independently validated.

### Output defects

The C output is only a set of initializer fragments. It has no declaration, family
boundary, route association, target/wrapper binding, include guard, schema, or
identity.

C names are interpolated without escaping. C and JSON are written independently
with truncating writes. A failed second write can leave a mismatched pair. An
output path can even overwrite an input path because no path identity check exists.

### Determinism defects

Results are not canonically sorted by route, target, caller, and site. Equal-address
aliases can change the selected caller based on tool output order. JSON has no
declared schema and is not serialized with a canonical key policy.

## Binary Correctness Requirements

The corrected analyzer must enforce these invariants:

### ELF identity

- ELF class is AArch64 64-bit little-endian as expected by the route.
- File type is a final executable/shared PIE suitable for final vmlinux analysis.
- Relocatable `ET_REL` input is rejected unless a separate relocation-aware
  analyzer is implemented and tested.
- `.text` and every accepted executable section have valid bounds.
- section file offset plus size is within the file.
- reads return the declared number of bytes.

### Symbol identity

- target symbols resolve uniquely;
- target symbols have canonical executable function identity;
- accepted callers have positive non-overlapping function extents;
- mapping symbols are excluded from caller identity;
- aliases are canonicalized or rejected when ownership is ambiguous;
- weak symbols are accepted only through explicit source policy;
- CFI/type symbols are not confused with callable function symbols;
- cold fragments and aliases are represented according to explicit policy;
- duplicate caller names within one route are aggregated, not repeated.

### Site identity

Every accepted site must satisfy:

```text
site is 4-byte aligned
site is inside an approved executable section
raw instruction has the ARM64 BL opcode
decoded destination == exact target symbol address
caller_start <= site < caller_start + caller_size
site offset is representable
scan width covers the site and fits runtime field limits
```

The target function and wrapper region must not be implicitly treated as ordinary
callers. Recursive target calls and wrapper self-calls need an explicit policy.

### Route identity

For each route:

- every required policy caller must have a valid matching site set;
- every optional policy caller remains represented even when absent;
- every unsupported row remains explicit;
- every unlisted candidate is either policy-approved, rejected with a diagnostic,
  or causes required route failure;
- overlapping physical sites assigned to incompatible wrappers are rejected;
- alternative targets are selected according to source order and route scope;
- required route floors cannot be regenerated from the same potentially incomplete
  image in a way that hides coverage loss.

### Direct versus indirect

The analyzer should count and report unsupported indirect forms rather than
silently dropping them. It does not need to patch BLR, but it must make the
coverage boundary visible and fail required routes when policy demands complete
coverage.

## Stale-Manifest Identity Model

### Full artifact identity

The future transaction identity must hash complete files from byte zero to EOF:

```text
vmlinux_sha256
image_sha256
system_map_sha256
config_sha256
effective_config_sha256
```

It should additionally record:

```text
vmlinux_build_id
architecture
endianness
kernel release
source revision
KSU revision
compiler identity
linker identity
nm identity
readelf identity
objcopy identity
objdump identity
analyzer identity
policy identity
schema identity
manifest payload digest
```

The current Phase 14 16-MiB prefix hash is not sufficient. It does not identify
the final raw `Image`, does not include System.map, is not stored in JSON, and is
not enforced.

Independent full hashes alone do not prove that the three files came from one
link: an unrelated but well-formed `System.map` also has a valid full hash. The
future verifier must parse both symbol sources and compare relevant symbol names,
addresses, types, and (where available) sizes between ELF and System.map. A map
whose digest is valid but whose symbols do not match the analyzed vmlinux must be
rejected.

### Image versus vmlinux

The raw ARM64 Image is generated from vmlinux using objcopy rules that remove ELF
sections such as build notes and comments. It is not byte-identical to vmlinux and
requires a separate full digest and transform identity.

The future verifier must either:

- derive a fresh Image from the exact final vmlinux and compare it byte-for-byte
  with the build output; or
- use the exact selected boot transformation and bind that transformation and
  output in the transaction stamp.

### Configuration identity

The active `.config` and effective generated `include/config/auto.conf` should both
be bound. The current vendor build also embeds a config artifact that may not be
the same file as the active output config. A future verifier must model or reject
that mismatch rather than treating embedded IKCONFIG as proof of active config.

### Self-reference

The full final vmlinux digest must not be naively embedded in the compiled
manifest. Otherwise:

```text
V = Link(M)
M contains SHA256(V)
```

and the build requires a fixed point that is not guaranteed to exist.

Use an external final stamp for complete artifact hashes. If an in-image marker is
needed, it should identify the canonical manifest payload/schema/policy and not
the full final file digest. The final file digest is then recorded after linking.

### Commit marker

The transaction should publish:

```text
manifest.h or manifest_data.h
manifest.json
identity.stamp
READY
```

in one controlled output tree. All files are generated in temporary files inside
that output tree, validated, closed, and atomically renamed. `READY` is written
last. A build must never treat a directory containing files but no valid marker as
an accepted manifest transaction.

The generated-data object recipe itself must validate the transaction nonce,
stage, identity sidecar, and `READY` marker before compiling the generated data.
Normal Kbuild timestamp/dependency tracking is not sufficient: a directly entered
final-stage build could otherwise consume an old header whose timestamp appears
current. Missing, stale, malformed, or mismatched marker state must make the
generated-object recipe fail before producing an object.

## Proposed Two-Stage Build Architecture

### Stage 0: coordinator setup

The outer coordinator should:

1. Resolve the absolute source and object trees.
2. Require or strongly prefer out-of-tree `O=`.
3. Acquire an object-tree transaction lease.
4. Record source, config, tool, policy, schema, and transaction identity.
5. Remove or invalidate previous final metadata.
6. Prevent concurrent coordinators from sharing the same output tree.
7. Preserve the original build arguments for the final build goal.

### Stage 1: bootstrap/discovery

Stage 1 should:

1. Compile a manifest-independent bootstrap data object.
2. Build a complete discovery vmlinux using normal Kbuild.
3. Produce a fresh System.map.
4. Produce a fresh temporary raw Image if needed.
5. Run the corrected analyzer using the selected Kbuild host tools.
6. Reject all required failures.
7. Generate a candidate per-route manifest below the active object tree.
8. Validate C syntax, JSON schema, policy join, record budget, and identity.
9. Publish the candidate atomically as a stage-1 artifact.

### Stage 2: final compilation

Stage 2 should:

1. Re-enter the top-level kernel Makefile, not the standalone KSU module helper.
2. Preserve `ARCH`, `O=`, compiler/linker, cross-compile, Kconfig, and Kbuild
   flags.
3. Set an explicit internal stage marker and transaction nonce.
4. Make the generated data object an explicit prerequisite of the KSU data object.
5. Rebuild the generated data object and dependent KSU archive.
6. Relink final vmlinux and regenerate System.map.
7. Build the raw Image and any selected compressed/image packaging target.
8. Return from postlink without recursively launching another build.

### Stage 3: final verification

The coordinator must then:

1. Analyze final vmlinux/System.map/Image independently.
2. Extract or verify the compiled manifest marker from final vmlinux.
3. Compare canonical stage-1 and final manifest payloads.
4. Compare compiled payload ID with final analyzer payload ID.
5. Record complete final hashes.
6. Publish the final commit marker.
7. Allow packaging only after the marker exists.

Because `ARCH_POSTLINK` runs inside the `vmlinux` recipe before the parent
`Image` target, the child final-stage invocation must explicitly request and
complete the raw ARM64 `Image` (or the exact selected image-producing target)
before Stage 3 hashes it and publishes `READY`. Merely observing that an
`arch/arm64/boot/Image` file exists is unsafe because it may be left over from a
previous vmlinux. Module postlink invocations must not enter this image
transaction.

The coordinator must also account for the parent requested goal continuing after
the `vmlinux` recipe returns. A parent `make Image` can execute the downstream
`Image: vmlinux` objcopy recipe after postlink, and that recipe uses `FORCE`. The
coordinator must either suppress that duplicate image write, revalidate after the
last image-producing recipe, or move `READY` publication to a target strictly
downstream of the final image writer. Otherwise a marker can authenticate an image
that is subsequently rewritten.

### Recursion guard

The child final-stage Kbuild sees the same postlink hook. It must not launch the
coordinator again. Use an explicit validated stage and transaction nonce, not
`MAKELEVEL` alone:

```text
unset stage -> coordinator may begin
stage=bootstrap -> ordinary discovery link only
stage=final + valid nonce -> verify and return, no re-entry
stage=final + invalid nonce -> fail
unexpected stage -> fail
```

The nonce must be checked against a transaction record under the active object
tree. A child with a stale or unrelated nonce must not be able to use an old
generated header.

### `ARCH_POSTLINK` role

`ARCH_POSTLINK` is a possible synchronous coordinator hook after a link. It is
not suitable as a normal generated-header prerequisite, and this proposed
coordinator has not been implemented or validated.

Linux 5.4 provides a conditional top-level hook point after the vmlinux link.
Linux 4.19 has an equivalent generic mechanism. Neither inspected tree has an
ARM64 postlink file already providing this integration, so no ARM64 postlink
coordinator runs in the current build.

The future hook must be restricted to the vmlinux postlink invocation. Linux 5.4
also invokes the architecture postlink makefile for module links through
`scripts/Makefile.modfinal`; Linux 4.19 has a corresponding module postlink path
through `scripts/Makefile.modpost`. A manifest coordinator must no-op or preserve
the existing module behavior for `%.ko` and must never begin a vmlinux two-stage
transaction for a module postlink call.

The future hook must preserve shell failure status. The current vendor vmlinux
command joins the link script and optional postlink command with a plain
semicolon in `/home/meow/lisa_kernel/Makefile:1241-1243`; the link and script
themselves currently use shell `set -e`, so a specific masking failure was not
reproduced here. Nevertheless, the adapter must use explicit status propagation
and final artifact freshness checks rather than relying on surrounding shell
behavior.

### Packaging boundary

The discovery stage must never run packaging side effects. It must not perform:

- module installation;
- distribution copying;
- AnyKernel packaging;
- DTB packaging;
- adb upload;
- flash preparation.

Only the final verified stage may perform those actions.

## Fixed-Point Analysis

The generated manifest may move layout if it changes object contents or archive
composition. The future process must not assume stage-1 and stage-2 addresses are
identical.

The canonical comparison must ignore address relocation but include:

```text
route ID
target identity
caller identity
classification
min_sites
site count
site offsets
instruction fingerprints
scan width
route target selection
```

A bounded process is required:

```text
bootstrap -> M1
build(M1) -> final image
analyze(final) -> M2

accept if canonical(M1) == canonical(M2)
otherwise build(M2) once more
fail if result still does not converge
```

There must be no unbounded recursive retry and no acceptance of the last generated
result merely because the analyzer exited successfully.

A separate generated data object is preferable because it minimizes the chance
that manifest content changes executable callsite layout. That is an optimization,
not a proof. Final-image analysis remains mandatory for LTO, CFI, alternative
instruction, linker-stub, and vendor-layout variants.

## Output Isolation And Atomicity

All generated files must be below the active absolute object tree:

```text
$(objtree)/include/generated/ksu/branch_link_manifest_data.h
$(objtree)/.ksu-bl/manifest.json
$(objtree)/.ksu-bl/identity.stamp
$(objtree)/.ksu-bl/READY
```

They must not be written to:

```text
KernelSU-Next/tools/
KernelSU-Next/kernel/
drivers/kernelsu/
/tmp/
```

Source-tree outputs would be shared by multiple `O=` trees and KMI builds. The
current Phase 14 generated files under `tools/bl-analyzer/` are historical audit
artifacts only and are not runtime inputs.

Atomic publication requirements:

1. Create temporary output files within the object-tree transaction directory.
2. Generate C and JSON from the same in-memory canonical record set.
3. Validate both before publication.
4. Verify output paths do not alias any input artifact.
5. Close and flush files.
6. Rename each validated file into its final name.
7. Write the final stamp/READY marker last.
8. Remove READY and final generated data on any later failure.

The result must never expose C from one analysis and JSON from another.

## Linux 5.4 Compatibility

The current vendor tree is Linux 5.4.302.

Relevant facts:

- `drivers/kernelsu` is a symlink to the KSU source tree;
- `kernel/Kbuild` is preferred over the standalone KSU Makefile;
- `branch_link_hook.o` is built into KSU;
- final vmlinux is linked through `scripts/link-vmlinux.sh`;
- System.map is produced after final vmlinux;
- ARM64 Image is built downstream of vmlinux;
- generic `ARCH_POSTLINK` support exists;
- no ARM64 postlink coordinator is currently installed.

The current `kernel/Makefile` is an external-module helper and is not the normal
built-in integration path. It also contains a literal `make` and an unconditional
`-j$(nproc)` for its module workflow. It must not be used as the outer two-stage
driver.

A 5.4 implementation must:

- use `$(MAKE)` for recursive calls;
- preserve the jobserver;
- avoid adding independent heavy parallel builds;
- pass selected `NM`, `READELF`, `OBJCOPY`, and related tools;
- keep generated files in `O=`;
- distinguish regular kernel goals from module/package/install goals;
- guard the postlink re-entry.

5.4 is the only target for which the complete hookless runtime was previously
device-validated. This does not make the new staged build implementation
validated; it remains unimplemented.

## Linux 4.19 Compatibility

The inspected 4.19 trees provide:

- `O=` output-tree support;
- recursive Make behavior;
- composite built-in archives;
- generic `ARCH_POSTLINK` support;
- selected cross/LLVM tool variables;
- object-tree generated-file conventions.

They do not provide an existing ARM64 postlink implementation for this feature.

The staged coordinator could use old Make-compatible primitives, but full 4.19
compatibility is not established because:

- current branch source policy is not validated against all 4.19 API shapes;
- current runtime manifests have unguarded compat rows;
- current documentation contradicts itself about 4.19 support;
- Android 4.19 wrappers have separate config, image, install, and distribution
  phases;
- Python is not guaranteed in hermetic Android host-tool environments;
- final Image packaging can include vendor-specific transformations;
- no current-head two-stage build has been executed on 4.19.

The honest status remains:

```text
Linux 4.19: build-integration design theoretically portable;
            current hookless runtime/two-stage implementation untested.
```

Do not claim generic 4.19 support merely because the Kbuild variable exists.

## Build Wrapper Compatibility

Android vendor wrappers are multi-phase. They may invoke Make for:

- defconfig;
- vmlinux/Image;
- modules;
- modules_install;
- headers;
- distribution copy;
- packaging;
- upload.

The outer coordinator must integrate only at the image-producing kernel boundary.
Wrapping every inner Make invocation or running the full Android wrapper twice
would repeat side effects and may analyze the wrong output.

The driver must also use the selected toolchain variables. The current analyzer
uses ambient `nm` and `readelf`, while Kbuild may select cross-prefixed or LLVM
tools. That mismatch is unacceptable for exact identity and symbol interpretation.

Python 3 availability must be checked or explicitly configured. Android’s
hermetic host-tool allowlist does not universally include Python. A future
implementation should fail before the link if the configured analyzer interpreter
or required ELF tools are unavailable.

## Security Review

### Stale data

Unsafe behavior includes accepting a previous manifest because caller names still
resolve, using file timestamps, hashing only a prefix, or ignoring System.map.
The final system must reject all of those shortcuts.

### Build races

Unsafe behavior includes:

- two Kbuild invocations writing one source-tree header;
- C and JSON generated by separate concurrent commands;
- final Image being built from vmlinux while its stamp describes another vmlinux;
- postlink re-entry launching a second coordinator;
- child Make seeing an old `.cmd` file and skipping the relink;
- interrupted analyzer leaving a usable-looking old READY marker.

The per-`O=` lock, transaction nonce, real build trigger, atomic files, and final
marker are required defenses.

### Target confusion

The generated model must reject:

- a BL to the wrong target;
- a BL through an unmodeled veneer;
- a recursive BL inside the wrapper or target region;
- an alias or mapping symbol selected as a caller;
- a site outside the caller extent;
- a physical site claimed by two incompatible wrappers;
- an indirect BLR path represented as if it were a direct BL;
- a target alternative selected without route policy.

### Fail-open analyzer

The current analyzer’s required drift status 0 is a direct build-gate vulnerability.
No build driver should wrap it until fatal results return nonzero and failed output
is invalidated.

### Runtime fallback

The runtime has existing fallback retirement and readiness behavior, but that is
not a substitute for build-time proof. The current source also has late global
conflict and fallback-retirement hazards. Generated-manifest integration must not
assume that runtime fallback automatically repairs a partially integrated staged
build.

## Required Analyzer Tests Before Implementation

The current Phase 16 audit fixtures include synthetic cases for several defects,
but they are not a permanent passing test harness. They do demonstrate duplicate
caller output, ignored/mismatched System.map inputs, wrong-architecture and
relocatable input acceptance, section omissions, malformed/unsafe output cases,
and current required-drift behavior. The small `id-a`/`id-b` fixture pair is not
evidence for a mutation after the current analyzer's 16 MiB hash window: both
files are shorter than 16 MiB and byte-identical. A corrected analyzer must add
real assertions for:

| Test | Required result |
|---|---|
| Valid direct BL | Discover exact target and caller. |
| Two BLs in one caller | Emit one caller row with site count two. |
| Missing target | Nonzero exit and no usable output. |
| Target present with zero valid sites | Correct target-present drift and nonzero required result. |
| Missing System.map | Nonzero when map is required. |
| Unrelated System.map | Nonzero pair mismatch. |
| Full identity change after 16 MiB | Identity changes; stale artifact rejected. The existing short identical fixture does not test this. |
| Wrong ELF architecture | Nonzero rejection. |
| `ET_REL` input | Nonzero rejection unless relocation-aware mode exists. |
| Zero-size mapping symbol | Never selected as caller. |
| Same-address aliases | Canonicalized or rejected deterministically. |
| Weak caller | Accepted only when source policy approves it. |
| Site outside function extent | Rejected. |
| Site in unsupported executable section | Explicit rejection/failure. |
| BL through veneer | Explicit unsupported/coverage failure. |
| BLR | Counted/reported as unsupported where required. |
| Recursive target call | Excluded or rejected according to policy. |
| KSU-internal approved caller | Included. |
| KSU-internal unapproved caller | Rejected with policy diagnostic. |
| Required/optional/unsupported join | Preserve source classification. |
| Width over `u16` | Nonzero rejection. |
| Malicious C symbol characters | Escape correctly or reject. |
| C/JSON atomicity | Failed generation exposes no usable final bundle. |
| Deterministic order | Repeated runs are byte-identical. |
| Complete family policy | Every active route is present or explicitly excluded. |

## Required Build Tests Before Success Claim

No implementation results exist yet. The future integration must prove:

| Test | Required result |
|---|---|
| Clean `O=` build | Bootstrap analysis runs automatically; final generated data is compiled; final verification succeeds. |
| Missing generated data | Build automatically starts from bootstrap; never uses stale final data. |
| Analyzer failure | Build returns nonzero and package target is not reached. |
| Required site removal | Analyzer and build fail closed. |
| New caller | New policy-approved caller appears in generated metadata. |
| Layout relocation | Address changes do not require manual edits; canonical facts remain valid. |
| Final-image divergence | Regeneration occurs or build fails; no silent acceptance. |
| Corrupt header | Final build fails or regenerates from current binary; never compiles corruption. |
| Corrupt JSON/stamp | Final marker is absent and package fails. |
| Stale vmlinux/Image/System.map | Transaction detects identity mismatch. |
| Two simultaneous `O=` builds | No shared generated state or cross-contamination. |
| Parallel Kbuild | KSU data object cannot compile before generated input exists. |
| Incremental unrelated change | Correct reuse or safe reanalysis; no stale acceptance. |
| Config change | New transaction identity and fresh manifest. |
| Compiler/linker change | New transaction identity and fresh manifest. |
| Analyzer/policy change | New transaction identity and fresh manifest. |
| Clean/mrproper | No usable READY marker survives. |
| Packaging | Packaging is permitted only after final verification. |
| Final ELF extraction | Compiled manifest ID matches analyzer payload. |

## Runtime Validation Status

No Phase 16 runtime code was changed, so no Phase 16 image was built or flashed.

The required runtime validation remains outstanding:

- full deterministic suite;
- AVC test;
- BL edge tester;
- AArch32 compatibility tester;
- NoMount selftest;
- app-UID test;
- zero-probe audit;
- reboot stability;
- targeted branch-link validation;
- concurrency/stress validation;
- final-image identity verification.

The historical baseline of 80 PASS / 0 FAIL remains a Phase 12/previous-phase
result, not a Phase 16 result.

## Performance Impact

No runtime code changed in Phase 16. No new performance measurement was taken.

The existing Phase 12 baseline remains the only valid quantified comparison:

```text
sucompat=1 mean: 13666.4 ns
sucompat=0 mean: 13654.8 ns
mean overhead:   +0.089%
median overhead: +0.048%
```

A properly implemented generated data object should not alter the runtime hot
path. It may alter link layout and initialization code, so final runtime
validation would still be required after implementation.

## Documentation Status

No documentation was changed because the automatic build architecture was not
implemented.

The current documentation contains an existing misleading claim that must be
corrected even before automatic generation is implemented, plus additional text
that must be updated when the feature eventually exists:

- `docs/README.md:205-221` describes boot-time Image/System.map discovery even
  though current runtime manifests are hand-maintained. It must not be used as
  evidence that automatic discovery is currently active;
- `docs/nomount-hookless.md` and `docs/susfs-hookless.md` use stronger 4.19
  compatibility wording than the canonical README table;
- current documentation must distinguish build-time analyzer generation from
  runtime patching;
- current documentation must explain that source policy remains manual while
  per-build caller/site/width data becomes automatic;
- current documentation must describe the two-stage coordinator and final-image
  verification once those actually exist.

It would be misleading to update documentation now to say that normal builds
already generate or consume the manifest.

## Files Examined

### KernelSU-Next

- `kernel/hook/arm64/branch_link_hook.c`
- `kernel/hook/arm64/branch_link_hook.h`
- `kernel/hook/arm64/syscall_hook.c`
- `kernel/infra/symbol_resolver.c`
- `kernel/infra/symbol_resolver.h`
- `kernel/nomount/hooks.c`
- `kernel/nomount/core.c`
- `kernel/susfs/core.c`
- `kernel/susfs/kstat.c`
- `kernel/susfs/procfs.c`
- `kernel/runtime/ksud_integration.c`
- `kernel/hook/lsm_hook.c`
- `kernel/hook/lsm_hook_manual.c`
- `kernel/feature/selinux_hide.c`
- `kernel/Kbuild`
- `kernel/Kconfig`
- `kernel/Makefile`
- `kernel/setup.sh`
- `tools/bl-analyzer/bl_discover.py`
- `tools/bl-analyzer/generated_manifest.h`
- `tools/bl-analyzer/generated_manifest.json`
- `docs/README.md`
- `docs/nomount-hookless.md`
- `docs/susfs-hookless.md`
- `.gitignore`

### Linux 5.4 vendor tree

- `/home/meow/lisa_kernel/Makefile`
- `/home/meow/lisa_kernel/scripts/link-vmlinux.sh`
- `/home/meow/lisa_kernel/scripts/Makefile.build`
- `/home/meow/lisa_kernel/scripts/Kbuild.include`
- `/home/meow/lisa_kernel/arch/arm64/Makefile`
- `/home/meow/lisa_kernel/arch/arm64/boot/Makefile`
- `/home/meow/lisa_kernel/arch/arm64/configs/lisa_defconfig`
- `/home/meow/lisa_kernel/drivers/Makefile`
- `/home/meow/lisa_kernel/drivers/Kconfig`
- `/home/meow/lisa_kernel/out/vmlinux`
- `/home/meow/lisa_kernel/out/System.map`
- `/home/meow/lisa_kernel/out/arch/arm64/boot/Image`
- `/home/meow/lisa_kernel/out/.config`

### Linux 4.19 references

- local 4.19 top-level Makefile;
- local 4.19 `scripts/link-vmlinux.sh`;
- local 4.19 `scripts/Makefile.build`;
- local 4.19 ARM64 Makefiles;
- local Android kernel wrapper and build configuration.

## Files Changed

Only the Phase 16 audit record and the ignore entry for the preserved Phase 16
audit directory were added. At report creation, the report was untracked and
the ignore entry was modified; the exact local commit is recorded below after
the final scope check.

No changes were made to:

- Kbuild;
- top-level kernel Makefiles;
- `ARCH_POSTLINK`;
- branch-link runtime code;
- analyzer implementation;
- runtime manifest arrays;
- KSU wrappers;
- vendor functional source;
- kernel configuration;
- flash/package tooling.

The untracked/generated synthetic files already present under
`validation/audit/phase16/` are preserved as investigation evidence and ignored
as generated audit artifacts. They are not production inputs.

## Git State

The Phase 16 report and ignore entry were first recorded locally as:

```text
fbd00a0d docs: record Phase 16 manifest architecture blocker
```

The wording/provenance correction to this report is recorded in the follow-up
commit immediately after `fbd00a0d`; the final `git log` contains both local
commit hashes. After those commits, the final KernelSU-Next worktree is expected
to be clean. The separate parent
vendor repository retains its existing uncommitted:

```text
arch/arm64/configs/lisa_defconfig
```

modification for the Lisa hookless configuration. It was not reverted.

No generated Phase 16 runtime manifest was committed. No kernel package or Phase
16 flash artifact was created. No push was performed.

## Stop Conditions Triggered

The following explicit stop conditions were met:

- analyzer cannot yet safely model the runtime manifest;
- current generated output is not a valid runtime consumer;
- final-image identity is not yet implemented;
- same-pass Kbuild integration would be circular;
- staged build convergence is not yet implemented or tested;
- stale metadata could be accepted by the current tool;
- required drift currently returns success;
- output is not atomic;
- multiple `O=` trees would be unsafe with source-tree output;
- complete family coverage is not represented;
- KSU-internal policy is incomplete;
- no final-image verification exists;
- no 5.4 staged build or runtime regression has been run;
- 4.19 behavior is not sufficiently validated for a support claim.

Proceeding anyway would require weakening checks or papering over the cycle, both
of which were expressly forbidden.

## Required Follow-Up Sequence

The next implementation phase should proceed in this order:

1. Correct the analyzer as an independent host tool.
2. Add a permanent analyzer test harness using the existing and new synthetic
   fixtures.
3. Define the complete source-owned route policy and ABI profiles.
4. Generate a canonical policy digest from that policy.
5. Implement complete vmlinux/System.map/Image/config/tool identity.
6. Implement atomic object-tree output and nonzero fatal exits.
7. Produce one caller row per route/caller with nested site facts.
8. Add explicit KSU-internal policy and overlap detection.
9. Add the stable manifest schema and generated data object without runtime
   activation.
10. Compile-test the generated data object against every source route.
11. Add a guarded 5.4 outer two-stage coordinator.
12. Prove clean, incremental, parallel, stale, corruption, and two-`O=` behavior.
13. Re-analyze and verify the final image, including compiled manifest ID.
14. Run fresh independent build, binary, runtime, security, and compatibility
   reviews.
15. Build Lisa with `-j1`, package, flash only the fresh artifact, and run the
   complete runtime suite.
16. Consider 4.19 only after a separate current-head build and runtime validation.

## Final Required Question

Does a future kernel developer currently need to manually maintain the BL
manifest?

**Yes, currently.**

The current runtime still contains hand-maintained caller arrays, site minimums,
and width overrides. Phase 16 defined how those per-build facts should eventually
be generated, but it did not safely replace them.

The answer may become **No** only after the complete route-aware generated model,
guarded two-stage build, final-image verification, and failure/race test matrix
are implemented and independently reviewed.

## Final Verdict

```text
BLOCKED
```

This is an intentional and evidence-based stop. The safe future architecture is
an object-tree generated manifest data object coordinated by a bounded outer
two-stage build, not a naive generated-header prerequisite and not a post-link
claim that the already-linked image contains newly generated data.

**NO PUSH PERFORMED.**
