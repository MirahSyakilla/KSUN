#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/proc_ns.h>
#include <linux/pid.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task.h>
#else
#include <linux/sched.h>
#endif
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <uapi/linux/fs.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include <uapi/linux/mount.h>
#else
#include <linux/mount.h>
#endif

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "infra/su_mount_ns.h"
#include "util.h"

extern int path_mount(const char *dev_name, struct path *path,
                      const char *type_page, unsigned long flags,
                      void *data_page);

#ifndef ksu_sys_setns
#if defined(__aarch64__) && defined(KSU_ARM64_HAS_PTREGS_SYSCALL)
extern long __arm64_sys_setns(const struct pt_regs *regs);
#elif defined(__x86_64__)
extern long __x64_sys_setns(const struct pt_regs *regs);
#endif

static long ksu_sys_setns(int fd, int flags)
{
#if (defined(__aarch64__) && defined(KSU_ARM64_HAS_PTREGS_SYSCALL)) || \
	defined(__x86_64__)
    struct pt_regs regs;

    memset(&regs, 0, sizeof(regs));

    PT_REGS_PARM1(&regs) = fd;
    PT_REGS_PARM2(&regs) = flags;
#endif

#if defined(__aarch64__) && defined(KSU_ARM64_HAS_PTREGS_SYSCALL)
    return __arm64_sys_setns(&regs);
#elif defined(__aarch64__)
    return sys_setns(fd, flags);
#elif defined(__x86_64__)
    return __x64_sys_setns(&regs);
#else
#error "Unsupported arch"
#endif
}
#endif

static long ksu_mnt_ns_setns_task(struct task_struct *task)
{
    char *pwd_path = NULL;
    char *pwd_buf;
    struct path saved_pwd;
    struct path ns_path;
    struct file *ns_file;
    long ret;
    int fd;

    if (unlikely(!task)) {
        return -EINVAL;
    }

    // save current working directory as absolute path before setns
    pwd_buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!pwd_buf) {
        pr_warn("no mem for pwd buffer, skip restore pwd!!\n");
        goto try_setns;
    }

    get_fs_pwd(current->fs, &saved_pwd);
    pwd_path = d_path(&saved_pwd, pwd_buf, PATH_MAX);
    path_put(&saved_pwd);

    if (IS_ERR(pwd_path)) {
        if (PTR_ERR(pwd_path) == -ENAMETOOLONG) {
            pr_warn("absolute pwd longer than: %d, skip restore pwd!!\n",
                    PATH_MAX);
        } else {
            pr_warn("get absolute pwd failed: %ld\n", PTR_ERR(pwd_path));
        }
        pwd_path = NULL;
    }

try_setns:
    ret = ns_get_path(&ns_path, task, &mntns_operations);
    if (ret) {
        pr_warn("failed get path for target mount namespace: %ld\n", ret);
        goto out_free;
    }
    ns_file = dentry_open(&ns_path, O_RDONLY, ksu_cred);

    path_put(&ns_path);
    if (IS_ERR(ns_file)) {
        pr_warn("failed open file for target mount namespace: %ld\n",
                PTR_ERR(ns_file));
        ret = PTR_ERR(ns_file);
        goto out_free;
    }

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0) {
        pr_warn("failed to get an unused fd: %d\n", fd);
        fput(ns_file);
        ret = fd;
        goto out_free;
    }

    fd_install(fd, ns_file);
    ret = ksu_sys_setns(fd, CLONE_NEWNS);

    ksu_close_fd(fd);

    if (ret) {
        goto out_free;
    }
    // try to restore working directory using absolute path after setns
    if (pwd_path) {
        struct path new_pwd;
        int err = kern_path(pwd_path, 0, &new_pwd);
        if (!err) {
            set_fs_pwd(current->fs, &new_pwd);
            path_put(&new_pwd);
        } else {
            pr_warn("restore pwd failed: %d, path: %s\n", err, pwd_path);
        }
    }

out_free:
    kfree(pwd_buf);
    return ret;
}

// global mode , need CAP_SYS_ADMIN and CAP_SYS_CHROOT to perform setns
static void ksu_mnt_ns_global(void)
{
    struct task_struct *pid1_task;

    rcu_read_lock();
    // &init_task is not init, but swapper/idle, which forks the init process
    // so we need find init process
    pid1_task = get_pid_task(find_vpid(1), PIDTYPE_PID);
    rcu_read_unlock();
    if (unlikely(!pid1_task)) {
        pr_warn("failed to get task_struct for PID 1\n");
        return;
    }

    if (ksu_mnt_ns_setns_task(pid1_task)) {
        pr_warn("failed to join init mount namespace\n");
    }
    put_task_struct(pid1_task);
}

// individual mode , need CAP_SYS_ADMIN to perform unshare and remount
static void ksu_mnt_ns_individual(void)
{
#ifdef KSU_HAS_KSYS_UNSHARE
    long ret = ksys_unshare(CLONE_NEWNS);
#else
    long ret = sys_unshare(CLONE_NEWNS);
#endif
    if (ret) {
        pr_warn("unshare mount namespace failed: %ld\n", ret);
        return;
    }

    // make root mount private
    struct path root_path;
    get_fs_root(current->fs, &root_path);
    int pm_ret = path_mount(NULL, &root_path, NULL, MS_PRIVATE | MS_REC, NULL);
    path_put(&root_path);

    if (pm_ret < 0) {
        pr_err("failed to make root private, err: %d\n", pm_ret);
    }
}

void setup_mount_ns(int32_t ns_mode)
{
    // inherit mode
    if (ns_mode == KSU_NS_INHERITED) {
        // do nothing
        return;
    }

    if (ns_mode != KSU_NS_GLOBAL && ns_mode != KSU_NS_INDIVIDUAL) {
        pr_warn("pid: %d ,unknown mount namespace mode: %d\n", current->pid,
                ns_mode);
        return;
    }

    const struct cred *old_cred = override_creds(ksu_cred);
    if (ns_mode == KSU_NS_GLOBAL) {
        ksu_mnt_ns_global();
    } else {
        ksu_mnt_ns_individual();
    }
    revert_creds(old_cred);
}

int ksu_join_task_mount_ns(struct task_struct *task)
{
    const struct cred *old_cred;
    long ret;

    if (!task) {
        return -EINVAL;
    }

    if (current->fs && current->fs->users != 1) {
        ret = unshare_fs_struct();
        if (ret) {
            pr_warn("failed to unshare fs before setns: %ld\n", ret);
            return (int)ret;
        }
    }

    old_cred = override_creds(ksu_cred);
    ret = ksu_mnt_ns_setns_task(task);
    revert_creds(old_cred);
    return ret ? (int)ret : 0;
}
