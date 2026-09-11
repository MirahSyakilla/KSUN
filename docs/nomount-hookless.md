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

`KSU_HOOKLESS_NOMOUNT` also requires `NET`.  Android ARM64 4.19 and 5.4 are the
supported targets.  Initialization is fail-closed: if a required pathname,
directory, permission, `d_path`, `vfs_getattr_nosec`, or `statfs` probe cannot
be registered, the Generic Netlink family is not exposed.

## Architecture

NoMount owns:

- exact virtual-to-real pathname rules and whiteouts
- RCU-protected directory child arrays
- real/visible inode identity metadata
- backend ancestor and private-directory policy
- UID exclusions
- the `nomount` Generic Netlink family

The runtime redirects the two native filename constructors, so every new
pathname lookup evaluates current policy before the global dcache is used.
`iterate_dir` is redirected to filter replaced names and emit injected names.
Kretprobes provide the permission, `d_path`, `vfs_getattr_nosec`, and `statfs`
behavior used by upstream NoMount.  On ARM64, branch-link syscall wrappers
also finish `stat*`, `fstat*`, and `statfs*` results when vendor LTO inlines
the VFS helper and bypasses its return probe.  SUSFS's proc-maps runtime
provides the remaining mapped-file inode/device metadata view.

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

## Netlink ABI

The public ABI remains:

- family name `nomount`
- family version `1`
- module ABI version `13`
- commands `GET_VERSION`, `ADD_RULE`, `DEL_RULE`, `CLEAR_ALL`, `ADD_UID`,
  `DEL_UID`, and `GET_LIST`

String attributes and the existing packed batch format are supported.  Packed
messages are fully shape-checked before any rule is changed and embedded NULs
are rejected.  Kbuild inspects the actual Generic Netlink structure layout so
old kernels receive per-operation policy while newer kernels receive family
policy.

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
