#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/thread_info.h>
#include <linux/seccomp.h>
#include <linux/printk.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#include "policy/allowlist.h"
#include "hook/setuid_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include "supercall/supercall.h"
#include "hook/tp_marker.h"
#include "feature/kernel_umount.h"
#ifdef CONFIG_KSU_HOOKLESS_SUSFS
#include "susfs/procfs.h"
#endif

extern void disable_seccomp();

int ksu_handle_setresuid(uid_t old_uid, uid_t new_uid)
{
    // we rely on the fact that zygote always call setresuid(3) with same uids

    pr_info("handle_setresuid from %d to %d\n", old_uid, new_uid);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    if (unlikely(is_uid_manager(new_uid))) {
        spin_lock_irq(&current->sighand->siglock);
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
#if defined(CONFIG_KSU_HOOK_CORE) && \
        !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
        ksu_set_task_tracepoint_flag(current);
#endif
        spin_unlock_irq(&current->sighand->siglock);

        pr_info("install fd for manager: %d\n", new_uid);
        ksu_install_fd();
        return 0;
    }

    if (ksu_is_allow_uid_for_current(new_uid)) {
        if (current->seccomp.mode == SECCOMP_MODE_FILTER &&
            current->seccomp.filter) {
            spin_lock_irq(&current->sighand->siglock);
            ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
            spin_unlock_irq(&current->sighand->siglock);
        }
#if defined(CONFIG_KSU_HOOK_CORE) && \
        !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
        ksu_set_task_tracepoint_flag(current);
#endif
    }
#if defined(CONFIG_KSU_HOOK_CORE) && \
        !defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE)
    else {
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }
#endif

#else // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    if (ksu_is_allow_uid_for_current(new_uid)) {
        disable_seccomp();

        if (unlikely(is_uid_manager(new_uid))) {
            pr_info("install fd for ksu manager(uid=%d)\n", new_uid);
            ksu_install_fd();
        }

        return 0;
    }
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
    ksu_susfs_handle_setuid(old_uid, new_uid);
#endif

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}

void __init ksu_setuid_hook_init(void)
{
    ksu_kernel_umount_init();
}

void __exit ksu_setuid_hook_exit(void)
{
    pr_info("ksu_core_exit\n");
    ksu_kernel_umount_exit();
}
