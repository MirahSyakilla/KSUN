#ifndef __KSU_H_SUSFS_PROCFS
#define __KSU_H_SUSFS_PROCFS

#include <linux/types.h>
#include <linux/uaccess.h>

struct mount;
struct ns_common;
struct vfsmount;

int ksu_susfs_procfs_init(void);
void ksu_susfs_procfs_exit(void);
bool ksu_susfs_unix_should_hide_abstract(const char *sun_path, int path_len);

bool ksu_susfs_handle_mount_compat(void __user *arg);
bool ksu_susfs_handle_cmdline_compat(void __user *arg);
bool ksu_susfs_handle_uname_compat(void __user *arg);
bool ksu_susfs_handle_avc_compat(void __user *arg);
bool ksu_susfs_mount_hide_view_enabled(void);
void ksu_susfs_handle_setuid(uid_t old_uid, uid_t new_uid);

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
bool ksu_susfs_should_hide_new_vfsmount(void);
bool ksu_susfs_should_hide_cloned_mount(struct mount *old);
void ksu_susfs_mark_vfsmount_hidden(struct vfsmount *mnt, bool hide);
void ksu_susfs_mark_mount_hidden(struct mount *mnt, bool hide);
void ksu_susfs_handle_cleanup_mnt(struct mount *mnt);
struct ns_common *ksu_susfs_handle_mntns_get(struct ns_common *orig_ns);
bool ksu_susfs_mount_runtime_available(void);
void ksu_susfs_set_mount_runtime_ready(bool ready);
bool ksu_susfs_mntns_get_runtime_ready(void);
void ksu_susfs_disable_mount_probe_fallback(void);
void ksu_susfs_disable_mntns_probe_fallback(void);
#endif

#endif // __KSU_H_SUSFS_PROCFS
