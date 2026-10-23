# KernelSU Runtime NoMount

This tree hosts a NoMount-compatible policy engine inside KernelSU-Next while
leaving the main kernel `fs/` sources untouched.  "Hookless" means no kprobes,
kretprobes, or ftrace-style runtime probes: interception uses compiled
branch-link call-site rewrites, syscall-table slots, and existing
function-pointer/ops-table structures (the permission probe pair, d_path,
getattr, getname, and iterate_dir probes were all migrated off kprobes).
The behavior is modeled on `maxsteeel/nomount` `master`, not its
`experimental/hookless` branch.

## Configuration

Enable:

```text
CONFIG_KSU_HOOK_CORE=y
CONFIG_KSU_HOOKLESS_SUSFS=y
CONFIG_KSU_HOOKLESS_NOMOUNT=y
```

`KSU_HOOKLESS_NOMOUNT` also requires `KEYS` (the `nomount` key type) and
`ARM64`.  Android ARM64 4.19 and 5.4 are the
supported targets.  Initialization is fail-closed: if a required pathname,
directory, permission, `d_path`, `vfs_getattr_nosec`, or `statfs` probe cannot
be registered, the keyring transport is not exposed.

## Architecture

NoMount owns:

- exact virtual-to-real pathname rules and whiteouts
- RCU-protected directory child arrays
- real/visible inode identity metadata
- backend ancestor and private-directory policy
- UID exclusions
- the `nomount` key type

The runtime redirects the two native filename constructors, so every new
pathname lookup evaluates current policy before the global dcache is used.
`iterate_dir` is redirected to filter replaced names and emit injected names.
The permission, `d_path`, `vfs_getattr_nosec`, and `statfs` behavior used by
upstream NoMount is provided by the same branch-link call-site rewrites, so
the runtime does not need the kretprobes upstream uses for it.  The kretprobe
route is still compiled in for kernels that have `CONFIG_KRETPROBES`, and it
is the fallback that keeps working when a branch-link family does not
install completely; on a kernel without kretprobes the branch-link route is
the only one, and the runtime stays fail-closed when it cannot commit.  On
ARM64, branch-link syscall wrappers also finish `stat*`, `fstat*`, and
`statfs*` results when vendor LTO inlines the VFS helper and bypasses its
return probe.  SUSFS's proc-maps runtime provides the remaining mapped-file
inode/device metadata view.

The implementation deliberately does **not** create a front inode, insert a
synthetic inode into a real filesystem's inode hash, replace a file's mapping,
or proxy one open file through a second `struct file`.  The retired SUSFS
NoMount bridge entry points and lookup/readdir branches have been removed, so
NoMount rules cannot re-enter that unsafe fabricated-inode path.

## Rule behavior

`nm add <virtual> <real>` resolves the real object with KernelSU credentials,
records its inode identity and required ancestors, and publishes the rule only
after its parent directory state is ready.  The real pathname must fit in the
smallest native `struct filename` allocation; near-`PATH_MAX` backends are
rejected instead of overwriting the embedded pathname buffer.

When the original virtual object exists, only its inode/device/filesystem
identity is retained.  Size, mode, ownership, blocks, and timestamps continue
to come from the live backend object.  A missing virtual object receives a
stable full-width synthetic directory-entry inode number; no inode with that
number is instantiated.

Missing intermediate virtual directories are represented by internal rules.
Each needs a distinct existing backend directory identity because readdir has
only the opened inode, not the original pathname, available at that point.
Native aliases that resolve to the same parent (for example `/vendor` and
`/system/vendor`) may share an identical child mapping.  Different child or
backend mappings on one directory identity are rejected.  Internal rules are
omitted from `GET_LIST` and pruned when their last child disappears.

Regular-file and symlink rules remain exact child replacements.  A directory
rule also supplies a recursive backend prefix for descendants, so a lookup
such as `virtual-dir/child` reaches the matching backend child while readdir
continues to merge native and injected entries.  Readdir and userspace
`stat*` wrappers preserve the visible child inode/device view; descriptors and
`statfs*` use the same path-aware correction.

Backend directories without other-execute permission are tracked by both
pathname and inode identity.  The temporary permission bridge is bound to the
specific redirected backend inode and its ancestors, rather than every active
NoMount rule.  This keeps one virtual pathname from authorizing a different
private backend through another pathname in the same syscall.

`nm block <uid>` makes that UID bypass all NoMount behavior.  Because policy is
checked in the filename constructor and in readdir, block/unblock and rule
deletion do not depend on dropping global dentries.

UID-scoped rules (ABI 16) narrow a rule to a UID window.  `--uid a` sets one
inlet (`start == end == a`), `--uid-range a b` sets `[a, b]`, and a rule with
`start == 0 && end == 0` is the global fallback that covers every UID outside
its deny window.  `--uid-excluded c` carves a single-UID denial window inside
the scope: UIDs inside the scope but inside the deny window resolve the stock
path.  Scopes may not overlap one virtual path (`EEXIST`), deny windows must
stay inside their scope (`EINVAL` otherwise), and rules with the same scope
but different deny windows may coexist.  Deleting a rule matches all of its
fields exactly (virtual path, real path, flags and the UID/deny windows);
anything less exact is rejected with `ENOENT` so a scoped rule can never be
removed by a plain alias.

Directory rules accept the `--opaque` flag.  An opaque directory stops
resolving stock children by name (lookups return negative dentries) while
readdir still enumerates the backend directory, matching upstream v2.2.0
semantics.

## Keyring transport ABI

The public ABI is:

- key type name `nomount`
- transport version `2`
- module ABI version `16`
- commands `GET_VERSION`, `ADD_RULE`, `DEL_RULE`, `CLEAR_ALL`, `ADD_UID`,
  `DEL_UID`, `GET_LIST`, `CLEAR_RULES`, `CLEAR_UIDS`, `GET_UIDS`,
  `BLOCK_ISOLATED`, and `GET_ISOLATED_STATE`

The runtime is driven the way upstream NoMount drives it: the client hands the
kernel the address of a command payload with `add_key(2)` using the `nomount`
key type, and the kernel applies the command while the key type preparses that
payload.  The key is never instantiated, so the command is applied exactly
once and nothing is left behind in a keyring.

The permission check lives in the preparse callback and requires
`CAP_SYS_ADMIN` in the *initial* user namespace.  `capable()` resolves
against `init_user_ns`, so an app that unshares a user namespace and holds
`CAP_SYS_ADMIN` only inside it is rejected.  This is why the transport is not
a Generic Netlink family: `GENL_ADMIN_PERM` resolves to
`ns_capable(sock_net(skb)->user_ns, CAP_NET_ADMIN)`, which an app satisfies by
unsharing a user *and* a network namespace, and NoMount rules are global, so
such an app could install system-wide rules.

The command payload is a single fixed size structure that the kernel reads
from and writes back to the client:

```text
u64 magic        "NOMOUNT" signature
u32 cmd          command number
u32 target_uid   uid argument of the UID commands
s32 status       result of the command, 0 on success
u32 data_size    number of valid bytes in buffer
u64 arg1         command argument, continuation token of the rule dump
u8  buffer[]     command payload
```

The batch format follows the upstream v2.2.0 layout: `ADD_RULE` carries
records prefixed with a 24-byte rule header (`u32 flags | u32 uid_start |
u32 uid_end | u32 deny_start | u32 deny_end | u16 v_len | u16 r_len`),
`DEL_RULE` carries records prefixed with an 18-byte deletion header
(`u32 uid_start | u32 uid_end | u32 deny_start | u32 deny_end | u16 v_len`),
each followed by the virtual and real pathnames.  `GET_UIDS` pages the UID
exclusion list through `arg1` the same way `GET_LIST` pages rules.
Batches are fully shape-checked before any rule is changed and embedded NULs
are rejected.  One rule exists per (virtual path, scope, deny window)
triple, matched exactly or as a directory prefix for extensions, with
whiteout and opaque carried in the record flags.

`GET_LIST` pages through the rule table: the kernel returns as many records
as fit into the payload buffer and stores the continuation token in `arg1`,
which the client sends back with the next command.

## Kernel version support

NoMount's interception is the same on every kernel this tree targets: the
runtime redirects the native filename constructors and patches the compiled
call sites of the functions it needs. What differs between kernels is which
of those call sites exist, and that is discovered at runtime rather than
assumed at compile time - a family that cannot be installed completely rolls
itself back and the runtime keeps the stock behaviour.

The transport is the part with the smallest API surface, and it is the one
that has to exist on every kernel:

| What it uses | Kernel API | Minimum | On older kernels |
| --- | --- | --- | --- |
| key type registration | `register_key_type()`, `unregister_key_type()` | 2.6.x | none, both have been there since the keyring was introduced |
| the key type's own ops | `preparse`, `free_preparse`, `instantiate` | 2.6.36 | none, all three are original `struct key_type` members |
| the parsed payload | `struct key_preparsed_payload`'s `data`/`datalen` | 2.6.36 | none, the fields are direct members, not behind a version-specific accessor |
| the permission check | `capable(CAP_SYS_ADMIN)` | 2.6.x | none, and it resolves against the initial user namespace on every kernel |
| the payload copy | `get_unaligned()`/`put_unaligned()` | 2.6.x | none, only the include moved (`asm/unaligned.h` became `linux/unaligned.h` in 6.12) |

The interception side needs more from the kernel, and the tree asks for it by
name at runtime instead of by version: `getname_flags`, `getname_kernel`,
`iterate_dir`, `inode_permission`, `generic_permission`, `d_path`,
`vfs_getattr_nosec` and `vfs_statfs` all have to be resolvable symbols, and
the ARM64 branch-link route additionally has to find every call site of the
function it replaces. A kernel where one of them is missing, or whose call
sites do not match the manifest, gets the stock behaviour and a boot log
that says which family did not commit - never a half-installed redirect.

`CONFIG_KSU_HOOKLESS_NOMOUNT` depends on `CONFIG_KSU_HOOKLESS_SUSFS` because
the two share one rule engine: NoMount asks SUSFS whether a path is hidden
before it applies its own policy. A configuration that asks for NoMount
without SUSFS is therefore not a configuration Kconfig can produce; the
dependency is enforced there rather than in the code.

## The SUSFS loadable module is gone

Upstream's SUSFS ships as a loadable module, `susfs_guard_lkm.ko`, and every
one of its interception mechanisms is a kprobe or a kretprobe. This kernel
disables kprobes on purpose - they cost too much on the hot paths a
probe-based implementation has to watch - so the module could never have been
used here.

The tree therefore carries no module at all: `kernel/susfs_lkm/` is deleted,
the `CONFIG_KSU_SUSFS_LKM` option is gone with it, and so are the mutual
exclusion it had with `CONFIG_KSU_HOOKLESS_SUSFS` and the build-time guard
that refused a config with both. The behaviours the module provided are
either answered by the hookless SUSFS implementation (the readlink face, the
O_PATH face, the kallsyms symbol hiding) or, where they need the module's own
machinery, simply not present. Nothing in this tree depends on
`CONFIG_KPROBES`.

## Compatibility limits

- File and symlink rules are exact path rules, matching upstream master.
  Directory rules intentionally support recursive descendant lookup, but they
  are not recursive subtree mounts and do not fabricate a VFS inode tree.
- Relative path reconstruction uses the current working directory only after a
  NoMount or SUSFS basename candidate is found.  Native filename constructors
  do not expose a non-`AT_FDCWD` dirfd to this hook.
- An internal or redirected directory ultimately opens a real backend
  directory.  Backend directory identities therefore must be unique among
  active virtual parents, except for compatible native aliases sharing the
  same child and backend.
- The target kernel must expose exact probeable symbols for `getname_flags`,
  `getname_kernel`, `iterate_dir`, `inode_permission`, `generic_permission`,
  `d_path`, `vfs_getattr_nosec`, and `vfs_statfs`.

No build, flash, or live-device validation status should be inferred from this
document; those are separate release checks.

## Version 16

The NoMount ABI version is 16 and the transport version is 2.  Version 15
introduced the keyring transport (version 14 and transport version 1 were
the Generic Netlink family; the transport was replaced because the netlink
family could be reached from a user namespace and therefore allowed an
unprivileged app to install global NoMount rules).  Version 16 grew the
batch records to the upstream v2.2.0 headers and added the UID scoping,
deny windows, opaque directories, the `CLEAR_RULES`/`CLEAR_UIDS`/`GET_UIDS`
commands and the isolated-UID blocking toggle; a v16 CLI cannot talk to a
v15 driver and vice versa.

The runtime is modelled on
`maxsteeel/nomount` `master` (v2.1.1, `NOMOUNT_BASE_VERSION` 21) rather
than copied from it, so the version numbers are independent of upstream's
and only mean "this tree's NoMount ABI".
