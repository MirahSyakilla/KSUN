#ifndef __KSU_H_SUSFS
#define __KSU_H_SUSFS

#include <linux/fs.h>
#include <linux/version.h>

#include "uapi/susfs.h"

struct filename;
struct kstat;
struct kstatfs;
struct path;

#ifndef d_backing_inode
#define d_backing_inode(dentry) d_inode(dentry)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#define KSU_SUSFS_IDMAP_ARG struct mnt_idmap *idmap,
#define KSU_SUSFS_IDMAP_CALL idmap,
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define KSU_SUSFS_IDMAP_ARG struct user_namespace *mnt_userns,
#define KSU_SUSFS_IDMAP_CALL mnt_userns,
#else
#define KSU_SUSFS_IDMAP_ARG
#define KSU_SUSFS_IDMAP_CALL
#endif

#ifdef KSU_SUSFS_HAS_PATH_GETATTR
#define KSU_SUSFS_GETATTR_ARGS \
	KSU_SUSFS_IDMAP_ARG const struct path *path, struct kstat *stat, \
	u32 request_mask, unsigned int query_flags
#define KSU_SUSFS_GETATTR_DENTRY path->dentry
#define KSU_SUSFS_GETATTR_PREP() do { } while (0)
#else
#define KSU_SUSFS_GETATTR_ARGS \
	struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat
#define KSU_SUSFS_GETATTR_DENTRY dentry
#define KSU_SUSFS_GETATTR_PREP() ((void)mnt)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define KSU_SUSFS_ACTOR_RET bool
#define KSU_SUSFS_ACTOR_CONTINUE true
#else
#define KSU_SUSFS_ACTOR_RET int
#define KSU_SUSFS_ACTOR_CONTINUE 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 12, 0) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0)
#define KSU_SUSFS_XATTR_FLAGS_ARG , int flags
#define KSU_SUSFS_XATTR_FLAGS_VAL , flags
#else
#define KSU_SUSFS_XATTR_FLAGS_ARG
#define KSU_SUSFS_XATTR_FLAGS_VAL
#endif

void ksu_susfs_init(void);
void ksu_susfs_exit(void);
bool ksu_susfs_handle_compat(unsigned int cmd, void __user *arg);
void ksu_susfs_apply_default_rules(void);
void ksu_susfs_handle_boot_completed(void);
bool ksu_susfs_path_filter_active(void);
bool ksu_susfs_should_hide_path(const char *path, size_t len);
bool ksu_susfs_inode_is_hidden(const struct inode *inode);
bool ksu_susfs_inode_identity_is_hidden(unsigned long ino, dev_t dev);
bool ksu_susfs_stat_should_be_enoent(const struct kstat *stat);
const char *ksu_susfs_hidden_dpath_name(void);
bool ksu_susfs_relative_hide_rule_may_match(const char *path, size_t len);
bool ksu_susfs_open_redirect_active(void);
bool ksu_susfs_open_redirect_runtime_ready(void);
void ksu_susfs_set_open_redirect_ready(bool ready);
struct filename *ksu_susfs_open_redirect_getname(struct inode *inode);
bool ksu_susfs_open_redirect_apply_kstat(struct inode *inode,
					struct kstat *stat);
bool ksu_susfs_open_redirect_apply_kstat_identity(struct kstat *stat);
bool ksu_susfs_open_redirect_spoof_inode_identity(struct inode *inode,
						  dev_t *dev,
						  unsigned long *ino);
bool ksu_susfs_open_redirect_apply_statfs(struct inode *inode,
					 struct kstatfs *statfs);
char *ksu_susfs_open_redirect_dpath(const struct path *path, char *buf,
				    int buflen);

#endif // __KSU_H_SUSFS
