#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/jump_label.h"
#include "linux/printk.h"
#include "selinux/selinux.h"
#include <asm/syscall.h>
#include <linux/fcntl.h>
#include <linux/ptrace.h>
#include <linux/static_key.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "policy/app_profile.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "supercall/supercall.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "feature/adb_root.h"
#include "preinit/preinit.h"
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#include "hook/arm64/branch_link_hook.h"
#endif

static int ksu_handle_init_mark_tracker(const char __user **filename_user)
{
    char path[64];
    unsigned long addr;
    const char __user *fn;
    long ret;

    if (unlikely(!filename_user))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    ret = strncpy_from_user(path, fn, sizeof(path));
    if (ret < 0)
        return 0;

    path[sizeof(path) - 1] = '\0';
    if (unlikely(strcmp(path, KSUD_PATH) == 0)) {
        pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
        escape_to_root_for_init();
    } else if (likely(strstr(path, "/app_process") == NULL &&
                    strstr(path, "/stub_zygote") == NULL &&
                    strstr(path, "/adbd") == NULL)) {
#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
        pr_info("hook_manager: unmark %d exec %s\n", current->pid, path);
        ksu_clear_task_tracepoint_flag_if_needed(current);
#endif
    }

    return 0;
}

long __nocfi ksu_hook_newfstatat(int orig_nr, const struct pt_regs *regs)
{
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
    /* Keep the dispatcher hook installed as the su-redirect fallback during
     * branch-link installation and after a failed family transaction; the
     * branch sites cover newfstatat itself once the family is READY. */
    if (ksu_branch_link_stat_path_ready())
        return ksu_invoke_syscall_nr(orig_nr, regs);
#endif
    if (!ksu_su_compat_enabled)
        return ksu_invoke_syscall_nr(orig_nr, regs);

    return ksu_handle_stat_sucompat(orig_nr, (struct pt_regs *)regs);
}

long __nocfi ksu_hook_faccessat(int orig_nr, const struct pt_regs *regs)
{
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
    /* Keep the dispatcher hook installed as the fallback during branch-link
     * installation and after a failed family transaction. */
    if (ksu_branch_link_faccessat_ready())
        return ksu_invoke_syscall_nr(orig_nr, regs);
#endif
    if (!ksu_su_compat_enabled)
        return ksu_invoke_syscall_nr(orig_nr, regs);

    return ksu_handle_faccessat_sucompat(orig_nr, (struct pt_regs *)regs);
}

DEFINE_STATIC_KEY_TRUE(ksud_execve_key);

bool ksu_ksud_execve_hook_enabled(void)
{
    return static_branch_unlikely(&ksud_execve_key);
}

void ksu_stop_ksud_execve_hook()
{
    static_branch_disable(&ksud_execve_key);
}

long __nocfi ksu_hook_execve(int orig_nr, const struct pt_regs *regs)
{
    const char __user **filename_user = (const char __user **)&PT_REGS_PARM1(regs);
    const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
    bool current_is_init = is_init(current_cred());
    struct ksu_sulog_pending_event *pending_root_execve = NULL;
    long ret;

    /*
     * The preinit runner has to be swapped in on PID 1's very first exec,
     * before the SELinux policy is loaded.  It replaces the exec target
     * itself, so it must run *before* the branch-link fast path below,
     * which only rewrites exec targets.
     */
    if (unlikely(current->pid == 1) &&
        ksu_preinit_handle_execve(filename_user, argv_user, orig_nr, (struct pt_regs *)regs, &ret))
        return ret;

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
    /* Branch-link owns this syscall only after its complete manifest commits. */
    if (ksu_branch_link_exec_ready())
        return ksu_invoke_syscall_nr(orig_nr, regs);
#endif

    if (static_branch_unlikely(&ksud_execve_key))
        ksu_execve_hook_ksud(regs);

    if (current_euid().val == 0)
        pending_root_execve = ksu_sulog_capture_root_execve(*filename_user, argv_user, GFP_KERNEL);

    if (current->pid != 1 && current_is_init) {
        ksu_handle_init_mark_tracker(filename_user);
        ret = ksu_adb_root_handle_execve((struct pt_regs *)regs);
        if (ret) {
            pr_err("adb root failed: %ld\n", ret);
        }
    } else if (ksu_su_compat_enabled) {
        ret = ksu_handle_execve_sucompat(filename_user, orig_nr, (struct pt_regs *)regs);
        ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
        return ret;
    }

    ret = ksu_invoke_syscall_nr(orig_nr, regs);
    ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
    return ret;
}

long __nocfi ksu_hook_execveat(int orig_nr, const struct pt_regs *regs)
{
    const char __user **filename_user = (const char __user **)&PT_REGS_PARM2(regs);
    const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM3(regs);
    long ret;

    /*
     * Newer Android releases' init execs selinux_setup with execveat()
     * rather than execve().  Only an AT_EMPTY_PATH exec of an fd has no
     * path for preinit to swap.
     */
    if (unlikely(current->pid == 1) && !(PT_REGS_PARM5(regs) & AT_EMPTY_PATH) &&
        ksu_preinit_handle_execve(filename_user, argv_user, orig_nr, (struct pt_regs *)regs, &ret))
        return ret;

    return ksu_invoke_syscall_nr(orig_nr, regs);
}

long __nocfi ksu_hook_setresuid(int orig_nr, const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = ksu_invoke_syscall_nr(orig_nr, regs);

    if (ret < 0)
        return ret;

    ksu_handle_setresuid(old_uid, current_uid().val);
    return ret;
}

long __nocfi ksu_hook_reboot(int orig_nr, const struct pt_regs *regs)
{
    int magic1 = (int)PT_REGS_PARM1(regs);
    int magic2 = (int)PT_REGS_PARM2(regs);
    unsigned int cmd = (unsigned int)PT_REGS_PARM3(regs);
    void __user *arg = (void __user *)PT_REGS_SYSCALL_PARM4(regs);

    ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
    return ksu_invoke_syscall_nr(orig_nr, regs);
}
