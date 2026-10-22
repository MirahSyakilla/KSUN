#ifndef __KSU_H_SUSFS_KSTAT
#define __KSU_H_SUSFS_KSTAT

#include <linux/types.h>
#include <linux/uaccess.h>

struct kstat;
struct path;
struct file;

int ksu_susfs_kstat_init(void);
void ksu_susfs_kstat_exit(void);

bool ksu_susfs_handle_kstat_compat(unsigned int cmd, void __user *arg);
bool ksu_susfs_handle_sus_map_compat(void __user *arg);
bool ksu_susfs_kstat_active_for_current(void);

/* Number of map/smap lines the show probes have dropped.  Reported
 * through the enabled-features list so the userspace side can tell a
 * kernel that is hiding nothing from one whose hiding is not being
 * applied. */
int ksu_susfs_show_hides_count(void);

/* The readlink face: true when the path the caller asked about resolves to
 * a sus_path-hidden inode and therefore has to answer -ENOENT, exactly as
 * the stat family answers for it. */
bool ksu_susfs_readlink_should_be_enoent(int dfd, const char __user *pathname);

/* The O_PATH face: true when the file the open produced is an O_PATH
 * descriptor for a sus_path-hidden inode. */
bool ksu_susfs_opath_should_be_enoent(const struct file *file);

/* The kallsyms face: how many lines the show callback dropped, and whether
 * the callback is hooked at all. */
int ksu_susfs_kallsyms_hides_count(void);
bool ksu_susfs_kallsyms_hide_ready(void);

/* Which faces the interception layer managed to arm. */
void ksu_susfs_set_readlink_ready(bool ready);
bool ksu_susfs_readlink_runtime_ready(void);
void ksu_susfs_set_opath_ready(bool ready);
bool ksu_susfs_opath_runtime_ready(void);

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
void ksu_susfs_handle_vfs_getattr_nosec(const struct path *path,
					struct kstat *stat, long ret);
void ksu_susfs_handle_stat_result(struct kstat *stat, long ret);
void ksu_susfs_set_getattr_ready(bool ready);
bool ksu_susfs_kstat_runtime_ready(void);
#endif

#endif // __KSU_H_SUSFS_KSTAT
