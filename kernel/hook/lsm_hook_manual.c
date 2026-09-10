#include <linux/version.h>
#include <linux/security.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/uidgid.h>
#include <linux/lsm_hooks.h>

#include "manager/throne_tracker.h"
#include "compat/kernel_compat.h"
#include "ksu.h"
#include "klog.h"
#include "setuid_hook.h"
#include "manager/throne_tracker.h"

extern bool ksu_init_rc_hook __read_mostly;

static int ksu_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
    return ksu_handle_setresuid(new->uid.val, old->uid.val);
}

extern void ksu_install_rc_hook(struct file *file);
static int ksu_file_permission(struct file *file, int mask)
{
    if (unlikely(ksu_init_rc_hook))
        ksu_install_rc_hook(file);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
static int ksu_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode,
                            struct dentry *new_dentry)
{
    // skip kernel threads
    if (current->flags & PF_KTHREAD) {
        return 0;
    }

    // skip non system uid
    if (current_uid().val != 1000) {
        return 0;
    }

    if (!old_dentry || !new_dentry) {
        return 0;
    }

    // /data/system/packages.list.tmp -> /data/system/packages.list
    if (strcmp(new_dentry->d_iname, "packages.list")) {
        return 0;
    }

    char path[128];
    char *buf = dentry_path_raw(new_dentry, path, sizeof(path));
    if (IS_ERR(buf)) {
        pr_err("dentry_path_raw failed.\n");
        return 0;
    }

    if (!strstr(buf, "/system/packages.list")) {
        return 0;
    }

    pr_info("renameat: %s -> %s, new path: %s\n", old_dentry->d_iname, new_dentry->d_iname, buf);

    track_throne(false);

    return 0;
}
#endif

static struct security_hook_list ksu_hooks[] = {
    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
    LSM_HOOK_INIT(file_permission, ksu_file_permission),
};

void __init ksu_lsm_hook_built_in_init(void)
{
    if (ARRAY_SIZE(ksu_hooks) == 0)
        return;

        // https://github.com/torvalds/linux/commit/d69dece5f5b6bc7a5e39d2b6136ddc69469331fe
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_REQUIRE_PROVIDE_LSM_NAME)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    // https://elixir.bootlin.com/linux/v4.10.17/source/include/linux/lsm_hooks.h#L1892
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}
