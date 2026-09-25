#!/usr/bin/env python3
"""Source-owned Branch-Link policy (Phase 17).

Single source of truth for every direct-BL route's semantic policy.  The
runtime arrays in kernel/hook/arm64/branch_link_hook.c remain the production
mechanism; this file is the offline authority that the v2 analyzer validates
against.  KSU-internal callers are EXPLICIT owner= policy -- name-prefix
matching is forbidden.

Condition expressions are evaluated by the analyzer against a context of:
  CONFIG_*   (bool/int from .config)
  __NR_*     (bool: syscall number exists)
  KSU_HAS_*  / KSU_EXECVE_* (source-shape probes supplied on the CLI)
  kver       (kernel version tuple)
  KV(a,b,c)  -> version tuple helper
"""

import hashlib
from dataclasses import dataclass, field
from typing import Tuple, List, Dict

POLICY_ID = "arm64-branch-link"
POLICY_REVISION = 1
SCHEMA_VERSION = 2

# classification
REQUIRED = "required"
OPTIONAL = "optional"
UNSUPPORTED = "unsupported"

# ownership (explicit; never name-prefix derived)
KERNEL = "kernel"
KSU = "ksu"


def KV(a, b, c):
    return (a, b, c)


@dataclass(frozen=True)
class Caller:
    name: str
    classification: str = REQUIRED
    min_sites: int = 1
    width: int = 0                 # 0 = auto (function-size-bounded)
    owner: str = KERNEL
    cond: str = ""                 # empty = unconditional
    acknowledged: bool = False     # True: known census/runtime gap; advisory only
    explicitly_excluded: bool = False  # True: UNSUPPORTED with live census sites
                                       # is an explicit documented decision
    note: str = ""


@dataclass(frozen=True)
class Target:
    symbol: str                    # real-body symbol; BL immediates match this
    hook: str                      # KSU wrapper installed at the site
    fn_slot: str = ""              # shared slot; "" = pure replacement
    binding: str = "canonical"     # canonical (cfi_jt) | realbody
    cond: str = ""


@dataclass(frozen=True)
class Route:
    id: str
    kind: str                      # "manifest" | "routes" | "exec"
    cond: str = ""
    targets: Tuple[Target, ...] = ()
    callers: Tuple[Caller, ...] = ()
    ksu_internal: str = "explicit"  # explicit: only owner=KSU listed callers
    census_expected_sites: int = 0  # reference-image census (0 = unknown)
    advisory_only: bool = False     # readiness never vetoes a feature
    acknowledge_unlisted: bool = False  # census callers without policy rows are
                                        # known coverage gaps, warn not fail
    group: str = ""
    profile: str = ""
    note: str = ""


# ---------------------------------------------------------------------------
# Policy content transcribed from branch_link_hook.c (Phase 17, revision 1).
# ---------------------------------------------------------------------------

ROUTES: List[Route] = [
    # -- faccessat -----------------------------------------------------------
    Route(
        id="faccessat/do_faccessat", kind="manifest", group="faccessat",
        profile="arm64-faccessat2|arm64-vendor-flags|arm64-legacy",
        targets=(Target("do_faccessat", "ksu_do_faccessat", "do_faccessat_fn"),),
        callers=(
            Caller("__arm64_sys_faccessat", REQUIRED, 1),
            Caller("__arm64_sys_access", OPTIONAL, 1, cond="CONFIG_COMPAT",
                   note="adjacent tiny wrapper; scanner overrun may pre-cover it"),
            Caller("__arm64_sys_faccessat2", REQUIRED, 1, cond="__NR_faccessat2"),
            Caller("__arm64_compat_sys_faccessat", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT",
                   note="vendor compat wrapper outside this profile"),
            Caller("__arm64_compat_sys_faccessat2", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
        ),
    ),
    # -- readlink ------------------------------------------------------------
    Route(
        id="readlink/do_readlinkat", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="readlink",
        profile="arm64-compat|arm64-native",
        targets=(Target("do_readlinkat", "ksu_do_readlinkat",
                        "do_readlinkat_fn"),),
        callers=(
            Caller("__arm64_sys_readlinkat", REQUIRED, 1),
            Caller("__arm64_sys_readlink", OPTIONAL, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_readlinkat", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_readlink", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
        ),
    ),
    # -- permission ----------------------------------------------------------
    Route(
        id="permission/inode_permission", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="permission",
        profile="lisa-5.4",
        census_expected_sites=46,
        targets=(Target("inode_permission", "ksu_do_inode_permission",
                        "inode_permission_fn"),),
        callers=(
            Caller("prctl_set_mm", REQUIRED, 1),
            Caller("cgroup_procs_write_permission", REQUIRED, 1),
            Caller("bpf_obj_get_user", REQUIRED, 1),
            Caller("bpf_prog_get_type_path", REQUIRED, 1),
            Caller("__arm64_sys_mincore", REQUIRED, 1),
            Caller("do_madvise", REQUIRED, 1),
            Caller("madvise_cold_or_pageout_pte_range", REQUIRED, 1),
            Caller("vfs_truncate", REQUIRED, 1),
            Caller("do_faccessat", REQUIRED, 2),
            Caller("ksys_chdir", REQUIRED, 2),
            Caller("__arm64_sys_fchdir", REQUIRED, 1),
            Caller("ksys_chroot", REQUIRED, 2),
            Caller("vfs_dedupe_file_range_one", REQUIRED, 1),
            Caller("flush_old_exec", REQUIRED, 1, width=0x600),
            Caller("would_dump", REQUIRED, 1),
            Caller("prepare_binprm", REQUIRED, 1),
            Caller("lookup_one_len_common", REQUIRED, 1),
            Caller("vfs_create", REQUIRED, 1),
            Caller("vfs_mkobj", REQUIRED, 1),
            Caller("vfs_tmpfile", REQUIRED, 1),
            Caller("path_openat", REQUIRED, 1),
            Caller("vfs_mknod", REQUIRED, 1),
            Caller("vfs_mkdir", REQUIRED, 1),
            Caller("may_delete", REQUIRED, 1),
            Caller("vfs_symlink", REQUIRED, 1),
            Caller("vfs_link", REQUIRED, 1),
            Caller("do_linkat", REQUIRED, 1),
            Caller("vfs_rename", REQUIRED, 3, width=0x470),
            Caller("vfs_whiteout", REQUIRED, 1),
            Caller("link_path_walk", REQUIRED, 2),
            Caller("may_open", REQUIRED, 1),
            Caller("notify_change", REQUIRED, 1),
            Caller("xattr_permission", REQUIRED, 1),
            Caller("__arm64_sys_inotify_add_watch", REQUIRED, 1),
            Caller("fsverity_ioctl_enable", OPTIONAL, 1),
            Caller("configfs_symlink", OPTIONAL, 1),
            Caller("fuse_open_backing", OPTIONAL, 1),
            Caller("fuse_access_backing", OPTIONAL, 1),
            Caller("ovl_permission", REQUIRED, 1),
            Caller("unix_find_other", OPTIONAL, 1),
        ),
    ),
    # -- dpath (KSU-internal explicit) ----------------------------------------
    Route(
        id="dpath/d_path", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="dpath",
        profile="lisa-5.4",
        census_expected_sites=22,
        ksu_internal="explicit",
        targets=(Target("d_path", "ksu_do_dpath", "d_path_fn"),),
        callers=(
            Caller("bpf_d_path", REQUIRED, 1),
            Caller("linker_ctx", REQUIRED, 1),
            Caller("file_path", REQUIRED, 1),
            Caller("success_walk_trace", REQUIRED, 1),
            Caller("mnt_warn_timestamp_expiry", REQUIRED, 1),
            Caller("seq_path", REQUIRED, 1),
            Caller("proc_pid_readlink", REQUIRED, 1),
            Caller("ext4_file_open", REQUIRED, 1),
            Caller("path_mount", REQUIRED, 1, owner=KSU,
                   note="KSU weak shim; no ksu_ prefix"),
            Caller("ksu_wrapper_d_dname", REQUIRED, 1, owner=KSU),
            Caller("ksu_mnt_ns_setns_task", REQUIRED, 1, owner=KSU),
            Caller("ksu_install_rc_hook", REQUIRED, 1, owner=KSU),
            Caller("ksu_sys_fstat", REQUIRED, 1, owner=KSU),
            Caller("ksu_susfs_fdinfo_show", REQUIRED, 1, owner=KSU),
            Caller("ksu_susfs_proc_actor", REQUIRED, 1, owner=KSU,
                   note="d_path call in inlined ksu_susfs_proc_dir_is_ext4"),
            Caller("ksu_nomount_build_path_from_dfd", REQUIRED, 2, owner=KSU),
            Caller("ksu_nomount_handle_fd_getattr", REQUIRED, 1, owner=KSU),
            Caller("ksu_nomount_handle_statfs_path", REQUIRED, 1, owner=KSU),
            Caller("ksu_nomount_collect_ancestors", REQUIRED, 1, owner=KSU),
            Caller("seq_buf_path", REQUIRED, 1),
            Caller("audit_log_d_path", REQUIRED, 1, cond="CONFIG_AUDIT",
                   note="Phase 18 ADOPTED: old symbol-scoped d_path kretprobe "
                        "fired here; runtime array now carries this row"),
        ),
    ),
    # -- AVC ------------------------------------------------------------------
    Route(
        id="avc/slow_avc_audit", kind="manifest",
        cond="CONFIG_KSU_HOOK_CORE && CONFIG_AUDIT", group="avc",
        profile="lisa-5.4-audit",
        census_expected_sites=7,
        targets=(Target("slow_avc_audit", "ksu_do_slow_avc_audit",
                        "slow_avc_audit_fn"),),
        callers=(
            Caller("avc_has_extended_perms", REQUIRED, 1),
            Caller("avc_has_perm", REQUIRED, 1),
            Caller("avc_has_perm_flags", REQUIRED, 1),
            Caller("selinux_capable", REQUIRED, 1),
            Caller("selinux_file_ioctl", REQUIRED, 1),
            Caller("audit_inode_permission", REQUIRED, 1),
            Caller("has_cap_mac_admin", REQUIRED, 1),
        ),
    ),
    # -- getname / iterate -----------------------------------------------------
    Route(
        id="getname/getname_flags", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="getname-iterate",
        profile="lisa-5.4",
        census_expected_sites=22,
        targets=(Target("getname_flags", "ksu_nomount_getname_flags"),),
        callers=(
            Caller("__arm64_sys_execveat", REQUIRED, 1),
            Caller("__arm64_compat_sys_execveat", REQUIRED, 1),
            Caller("getname", REQUIRED, 1),
            Caller("user_path_at_empty", REQUIRED, 1),
            Caller("user_path_create", REQUIRED, 1),
            Caller("do_mknodat", REQUIRED, 2),
            Caller("do_mkdirat", REQUIRED, 2),
            Caller("do_rmdir", REQUIRED, 1),
            Caller("__arm64_sys_unlinkat", REQUIRED, 1),
            Caller("__arm64_sys_unlink", REQUIRED, 1),
            Caller("do_symlinkat", REQUIRED, 3),
            Caller("do_linkat", REQUIRED, 4),
            Caller("do_renameat2", REQUIRED, 2),
            Caller("__arm64_sys_fsconfig", REQUIRED, 1),
        ),
    ),
    Route(
        id="getname/getname_kernel", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="getname-iterate",
        profile="lisa-5.4",
        census_expected_sites=15,
        ksu_internal="explicit",
        targets=(Target("getname_kernel", "ksu_nomount_getname_kernel"),),
        callers=(
            Caller("run_init_process", REQUIRED, 1),
            Caller("call_usermodehelper_exec_async", REQUIRED, 1),
            Caller("filp_open", REQUIRED, 1),
            Caller("do_sys_open", REQUIRED, 1),
            Caller("open_exec", REQUIRED, 1),
            Caller("kern_path_locked", REQUIRED, 1),
            Caller("kern_path", REQUIRED, 1),
            Caller("vfs_path_lookup", REQUIRED, 1),
            Caller("do_file_open_root", REQUIRED, 1),
            Caller("kern_path_create", REQUIRED, 1),
            Caller("fs_lookup_param", REQUIRED, 1),
            Caller("ksu_nomount_rebase_execve_filename", REQUIRED, 1, owner=KSU),
            Caller("ksu_do_filp_open", REQUIRED, 2, owner=KSU),
            Caller("ksu_susfs_open_redirect_getname", REQUIRED, 1, owner=KSU),
        ),
    ),
    Route(
        id="iterate/iterate_dir", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_NOMOUNT", group="getname-iterate",
        profile="lisa-5.4",
        census_expected_sites=10,
        ksu_internal="explicit",
        targets=(Target("iterate_dir", "ksu_nomount_iterate_dir"),),
        callers=(
            Caller("__arm64_sys_getdents", REQUIRED, 1),
            Caller("ksys_getdents64", REQUIRED, 1),
            Caller("__arm64_compat_sys_getdents", REQUIRED, 1),
            Caller("exportfs_get_name", REQUIRED, 1),
            Caller("fuse_readdir_backing", REQUIRED, 1),
            Caller("ovl_dir_read", REQUIRED, 1),
            Caller("ovl_iterate", REQUIRED, 2, width=0x600),
            Caller("iterate_incfs_dir", REQUIRED, 1),
            Caller("search_manager", REQUIRED, 1, owner=KSU,
                   note="KSU manager; no ksu_ prefix"),
        ),
    ),
    # -- stat-path (target alternatives; known compat census gap acknowledged) --
    Route(
        id="stat-path", kind="routes", group="stat-path",
        profile="lisa-5.4",
        census_expected_sites=7,
        targets=(
            Target("vfs_fstatat", "ksu_vfs_fstatat", "vfs_fstatat_fn",
                   cond="kver >= KV(5, 10, 0)"),
            Target("vfs_statx", "ksu_vfs_statx", "vfs_statx_fn"),
        ),
        callers=(
            Caller("__arm64_sys_newfstatat", REQUIRED, 1),
            Caller("__arm64_sys_fstatat64", REQUIRED, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_sys_statx", REQUIRED, 1, cond="__NR_statx"),
            Caller("__arm64_compat_sys_newfstatat", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
            # Phase 18 ADOPTED: the Phase 17 census proved live vfs_statx
            # sites in the old-stat/compat wrappers (the Phase 12-era comment
            # claiming no such sites was wrong); the old symbol-scoped
            # vfs_getattr_nosec kretprobe covered these callers.
            Caller("__arm64_sys_stat64", REQUIRED, 1,
                   note="ADOPTED Phase 18: live vfs_statx site at +0x54"),
            Caller("__arm64_sys_lstat64", REQUIRED, 1,
                   note="ADOPTED Phase 18: live vfs_statx site at +0x54"),
            Caller("__arm64_compat_sys_newstat", REQUIRED, 1,
                   note="ADOPTED Phase 18: live vfs_statx site"),
            Caller("__arm64_compat_sys_newlstat", REQUIRED, 1,
                   note="ADOPTED Phase 18: live vfs_statx site"),
        ),
    ),
    # -- stat-fd (all optional; dedicated fd slot) ------------------------------
    Route(
        id="stat-fd", kind="routes", cond="CONFIG_KSU_HOOKLESS_SUSFS",
        group="stat-fd", advisory_only=True, acknowledge_unlisted=True,
        profile="lisa-5.4 (vfs_fstat inlined; 0 expected sites)",
        targets=(
            Target("vfs_fstat", "ksu_vfs_fstat", "vfs_fstat_fn"),
            Target("vfs_getattr_nosec", "ksu_vfs_getattr_nosec_fd",
                   "vfs_getattr_nosec_fd_fn"),
        ),
        callers=(
            Caller("__arm64_sys_newfstat", OPTIONAL, 1),
            Caller("__arm64_sys_fstat64", OPTIONAL, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_newfstat", OPTIONAL, 1,
                   cond="CONFIG_COMPAT"),
            Caller("vfs_statx_fd", OPTIONAL, 1),
            Caller("__arm64_sys_fstat", UNSUPPORTED, 0),
            Caller("__arm64_compat_sys_fstat", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_fstat64", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT"),
        ),
        note="fd wrappers inline through vfs_getattr on 5.4; optional only",
    ),
    # -- statfs -----------------------------------------------------------------
    Route(
        id="statfs-path/user_statfs", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="statfs",
        targets=(Target("user_statfs", "ksu_user_statfs", "vfs_statfs_fn"),),
        callers=(
            Caller("__arm64_sys_statfs", REQUIRED, 1),
            Caller("__arm64_compat_sys_statfs", REQUIRED, 1,
                   cond="CONFIG_COMPAT"),
            Caller("kcompat_sys_statfs64", OPTIONAL, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_aarch32_statfs64", OPTIONAL, 1,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_sys_statfs64", UNSUPPORTED, 0),
            Caller("__arm64_compat_sys_statfs64", UNSUPPORTED, 0),
        ),
    ),
    Route(
        id="statfs-fd/fd_statfs", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="statfs",
        targets=(Target("fd_statfs", "ksu_fd_statfs", "vfs_statfs_fn"),),
        callers=(
            Caller("__arm64_sys_fstatfs", REQUIRED, 1),
            Caller("__arm64_compat_sys_fstatfs", REQUIRED, 1,
                   cond="CONFIG_COMPAT"),
            Caller("kcompat_sys_fstatfs64", OPTIONAL, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_aarch32_fstatfs64", OPTIONAL, 1,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_sys_fstatfs64", UNSUPPORTED, 0),
            Caller("__arm64_compat_sys_fstatfs64", UNSUPPORTED, 0),
        ),
    ),
    # -- open scope / redirect ---------------------------------------------------
    Route(
        id="open-scope/do_sys_open", kind="routes",
        cond="CONFIG_KSU_HOOKLESS_SUSFS && CONFIG_KSU_HOOKLESS_NOMOUNT",
        group="open-scope",
        targets=(Target("do_sys_open", "ksu_do_sys_open", "do_sys_open_fn"),),
        callers=(
            Caller("__arm64_sys_openat", REQUIRED, 1),
            Caller("__arm64_compat_sys_open", REQUIRED, 1,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_openat", REQUIRED, 1,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_sys_creat", REQUIRED, 1, cond="CONFIG_COMPAT"),
            Caller("__arm64_sys_open", UNSUPPORTED, 0,
                   note="compiled but wired into no table"),
        ),
    ),
    Route(
        id="susfs/do_filp_open", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="open-redirect",
        targets=(Target("do_filp_open", "ksu_do_filp_open", "do_filp_open_fn",
                        binding="realbody"),),
        callers=(
            Caller("do_sys_openat2", REQUIRED, 1, cond="KSU_HAS_OPENAT2"),
            Caller("do_sys_open", OPTIONAL, 1, cond="KSU_HAS_OPENAT2"),
            Caller("do_open_execat", REQUIRED, 1,
                   note="ADOPTED Phase 18: execve(2)/execveat(2) pathname "
                        "entry; live do_filp_open site (+0x7c)"),
            Caller("file_open_name", REQUIRED, 1,
                   note="ADOPTED Phase 18: kernel-internal named-open "
                        "helper; live do_filp_open site (+0xf8)"),
            Caller("open_exec", OPTIONAL, 1,
                   note="no direct do_filp_open; calls do_open_execat"),
            Caller("do_sys_open", REQUIRED, 1, cond="!KSU_HAS_OPENAT2"),
            Caller("do_sys_openat2", UNSUPPORTED, 0, cond="!KSU_HAS_OPENAT2"),
        ),
    ),
    # -- unix abstract-socket hide ------------------------------------------------
    Route(
        id="susfs/unix_find_other", kind="routes",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="unix-abstract",
        targets=(Target("unix_find_other", "ksu_unix_find_other",
                        "unix_find_other_fn"),),
        callers=(
            Caller("unix_stream_connect", OPTIONAL, 1),
            Caller("unix_dgram_connect", OPTIONAL, 1),
            Caller("unix_dgram_sendmsg", OPTIONAL, 1),
        ),
    ),
    # -- getattr interior ---------------------------------------------------------
    Route(
        id="susfs/vfs_getattr_nosec", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="getattr-interior",
        targets=(Target("vfs_getattr_nosec", "ksu_vfs_getattr_nosec",
                        "vfs_getattr_nosec_fn"),),
        callers=(Caller("exportfs_get_name", REQUIRED, 1),),
    ),
    # -- mount trio ----------------------------------------------------------------
    Route(
        id="susfs/vfs_create_mount", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="mount",
        targets=(Target("vfs_create_mount", "ksu_vfs_create_mount",
                        "vfs_create_mount_fn"),),
        callers=(
            Caller("fc_mount", REQUIRED, 1),
            Caller("do_new_mount_fc", OPTIONAL, 1),
            Caller("do_new_mount", OPTIONAL, 1),
            Caller("__arm64_sys_fsmount", REQUIRED, 1,
                   cond="kver >= KV(5, 0, 0)"),
            Caller("__do_sys_fsmount", OPTIONAL, 1,
                   cond="kver >= KV(5, 0, 0)"),
            Caller("__se_sys_fsmount", OPTIONAL, 1,
                   cond="kver >= KV(5, 0, 0)"),
            Caller("fuse_dentry_automount", OPTIONAL, 1),
            Caller("vfs_kern_mount", UNSUPPORTED, 0, explicitly_excluded=True,
                   note="Phase 18 EXPLICITLY OUT OF PROFILE: live "
                        "vfs_create_mount site, but internal multi-mount "
                        "helper; readiness would gate the whole atomic mount "
                        "trio on an LTO-fragile symbol, and fc_mount row "
                        "already covers its fc_mount-like callers.  Known "
                        "documented behavior change vs the pre-branch-link "
                        "symbol-scoped probe."),
        ),
    ),
    Route(
        id="susfs/clone_mnt", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="mount",
        targets=(Target("clone_mnt", "ksu_clone_mnt", "clone_mnt_fn"),),
        callers=(
            Caller("mnt_clone_internal", OPTIONAL, 1,
                   cond="kver >= KV(5, 0, 0)"),
            Caller("mnt_clone_internal", REQUIRED, 1,
                   cond="kver < KV(5, 0, 0)"),
            Caller("copy_tree", REQUIRED, 2),
            Caller("clone_private_mount", REQUIRED, 1),
            Caller("do_loopback", REQUIRED, 1, cond="kver < KV(5, 0, 0)"),
            Caller("__do_loopback", REQUIRED, 1, cond="kver >= KV(5, 0, 0)"),
        ),
    ),
    Route(
        id="susfs/cleanup_mnt", kind="manifest",
        cond="CONFIG_KSU_HOOKLESS_SUSFS", group="mount",
        targets=(Target("cleanup_mnt", "ksu_cleanup_mnt", "cleanup_mnt_fn"),),
        callers=(
            Caller("__cleanup_mnt", REQUIRED, 1),
            Caller("delayed_mntput", REQUIRED, 1),
            Caller("mntput_no_expire", REQUIRED, 1),
        ),
    ),
    # -- exec (legacy profile for 4.19/5.4; common profile for 5.9+) ---------------
    Route(
        id="execve/do_execveat_common", kind="manifest",
        cond="KSU_EXECVE_COMMON_HELPER", group="exec",
        targets=(Target("do_execveat_common", "ksu_do_execveat_common",
                        "do_execveat_common_fn"),),
        callers=(
            Caller("__arm64_sys_execve", REQUIRED, 1),
            Caller("__arm64_sys_execveat", REQUIRED, 1, cond="__NR_execveat"),
            Caller("__arm64_compat_sys_execve", REQUIRED, 1,
                   cond="CONFIG_COMPAT"),
            Caller("__arm64_compat_sys_execveat", REQUIRED, 1,
                   cond="KSU_HAS_COMPAT_EXECVEAT"),
            Caller("__arm64_compat_sys_execveat", UNSUPPORTED, 0,
                   cond="CONFIG_COMPAT && !KSU_HAS_COMPAT_EXECVEAT"),
        ),
    ),
    Route(
        id="execve", kind="exec", cond="!KSU_EXECVE_COMMON_HELPER",
        acknowledge_unlisted=True,
        group="exec",
        targets=(Target("__do_execve_file", "ksu_do_execve_file",
                        "__do_execve_file_fn"),
                 Target("do_execve", "ksu_do_execve", "do_execve_fn")),
        callers=(Caller("__arm64_sys_execve", REQUIRED, 1),),
    ),
    Route(
        id="execveat", kind="exec", cond="!KSU_EXECVE_COMMON_HELPER",
        acknowledge_unlisted=True,
        group="exec",
        targets=(Target("__do_execve_file", "ksu_do_execve_file",
                        "__do_execve_file_fn"),
                 Target("do_execveat", "ksu_do_execveat", "do_execveat_fn")),
        callers=(Caller("__arm64_sys_execveat", REQUIRED, 1,
                        cond="__NR_execveat"),),
    ),
    Route(
        id="compat_execve", kind="exec",
        acknowledge_unlisted=True,
        cond="!KSU_EXECVE_COMMON_HELPER && CONFIG_COMPAT", group="exec",
        targets=(Target("__do_execve_file", "ksu_do_execve_file",
                        "__do_execve_file_fn"),
                 Target("compat_do_execve", "ksu_compat_do_execve",
                        "compat_do_execve_fn")),
        callers=(Caller("__arm64_compat_sys_execve", REQUIRED, 1),),
    ),
    Route(
        id="compat_execveat", kind="exec",
        acknowledge_unlisted=True,
        cond="!KSU_EXECVE_COMMON_HELPER && CONFIG_COMPAT && "
             "KSU_HAS_COMPAT_EXECVEAT",
        group="exec",
        targets=(Target("__do_execve_file", "ksu_do_execve_file",
                        "__do_execve_file_fn"),
                 Target("compat_do_execveat", "ksu_compat_do_execveat",
                        "compat_do_execveat_fn")),
        callers=(Caller("__arm64_compat_sys_execveat", REQUIRED, 1),),
    ),
]

GROUPS: Dict[str, Tuple[str, ...]] = {
    "faccessat": ("faccessat/do_faccessat",),
    "readlink": ("readlink/do_readlinkat",),
    "permission": ("permission/inode_permission",),
    "dpath": ("dpath/d_path",),
    "avc": ("avc/slow_avc_audit",),
    "getname-iterate": ("getname/getname_flags", "getname/getname_kernel",
                        "iterate/iterate_dir"),
    "stat-path": ("stat-path",),
    "stat-fd": ("stat-fd",),
    "statfs": ("statfs-path/user_statfs", "statfs-fd/fd_statfs"),
    "open-scope": ("open-scope/do_sys_open",),
    "open-redirect": ("susfs/do_filp_open",),
    "getattr-interior": ("susfs/vfs_getattr_nosec",),
    "mount": ("susfs/vfs_create_mount", "susfs/clone_mnt",
              "susfs/cleanup_mnt"),
    "exec": ("execve/do_execveat_common",),
}

# Runtime capacity: must match KSU_BL_MAX_RECORDS (branch_link_hook.c).
# Phase 18: 160 -> 176. Phase 23: 176 -> 192 after census 181
# exceeded capacity (headroom for multi-site row growth).
MAX_RECORDS = 192
# Runtime default scan width: KSU_BL_SCAN_WIDTH = 128 * sizeof(void *).
SCAN_WIDTH = 0x400
# Runtime width field is u16 (branch_link_hook.c:117).
WIDTH_FIELD_MAX = 0xFFFF

ALLOWED_TEXT_SECTIONS = (".text",)


def policy_digest() -> str:
    with open(__file__, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def enabled_routes(ctx) -> List[Route]:
    """Return routes whose condition evaluates true under context."""
    out = []
    for r in ROUTES:
        if not r.cond or eval_cond(r.cond, ctx):
            out.append(r)
    return out


class ConditionError(Exception):
    """Raised when a policy condition cannot be evaluated."""


def eval_cond(expr: str, ctx) -> bool:
    import re
    # accept C-style && / || / ! as well as Python and/or/not.
    # '!' translation: only bare '!' (not '!=') followed by an identifier or
    # '(' is translated; anything else raises ConditionError in eval.
    py = expr.replace("&&", " and ").replace("||", " or ")
    py = re.sub(r"!\s*([A-Za-z_(])", r"not \1", py)
    if "!" in py.replace("!=", ""):
        raise ConditionError("untranslatable '!' in condition %r" % expr)
    env = {
        "kver": ctx.get("kver", (0, 0, 0)),
        "KV": KV,
    }
    env.update(ctx)
    return bool(eval(py, {"__builtins__": {}}, env))
