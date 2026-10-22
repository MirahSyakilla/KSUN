#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif
#include <linux/pid.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "compat/kernel_compat.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "selinux/selinux.h"
#ifdef CONFIG_KSU_HOOKLESS_SUSFS
#include "susfs/susfs.h"
#endif

#include "sulog/event.h"

/*
 * The reboot supercall's kprobe route is the legacy fallback for kernels
 * whose syscall table cannot be tampered with.  It needs a kernel that
 * actually HAS kprobes: this tree builds with CONFIG_KPROBES=n on purpose
 * (kprobes cost too much on the hot paths), so the route is compiled out
 * there instead of failing to build.  The guard therefore asks for the
 * kernel's kprobe support, not only for the absence of the tamper route.
 */
#if defined(CONFIG_KSU_HOOK_CORE) && \
	!defined(CONFIG_KSU_TAMPER_SYSCALL_TABLE) && \
	defined(CONFIG_KPROBES)
#define KSU_REBOOT_KPROBE
#endif

uint32_t ksuver_override = 0;

#ifdef CONFIG_KSU_HOOK_CORE
struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
struct ksu_susfs_tw {
    struct callback_head cb;
    unsigned int cmd;
    void __user *arg;
};

static bool ksu_susfs_may_sleep_now(void)
{
    return !in_interrupt() && !in_atomic() && !irqs_disabled() &&
           !oops_in_progress;
}
#endif

#endif

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
static bool ksu_susfs_supercall_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain_fast();
}
#endif

#define KSU_DRIVER_PERMISSION_SU_SESSION (1UL << 0)

struct ksu_driver_context {
    unsigned long permissions;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    kfree(filp->private_data);
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(filp, cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

static int ksu_install_fd_with_permissions(unsigned int fd_flags, unsigned long permissions)
{
    struct ksu_driver_context *context;
    struct file *filp;
    const char *name;
    int fd;

    context = kzalloc(sizeof(*context), GFP_KERNEL);
    if (!context)
        return -ENOMEM;

    context->permissions = permissions;
    name = permissions & KSU_DRIVER_PERMISSION_SU_SESSION ? "[ksu_driver_su]" : "[ksu_driver]";

    fd = get_unused_fd_flags(fd_flags);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        kfree(context);
        return fd;
    }

    filp = anon_inode_getfile(name, &anon_ksu_fops, context, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        kfree(context);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

int ksu_install_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, 0);
}

int ksu_install_su_fd(void)
{
    return ksu_install_fd_with_permissions(O_CLOEXEC, KSU_DRIVER_PERMISSION_SU_SESSION);
}

int ksu_install_su_fd_inherit(void)
{
    return ksu_install_fd_with_permissions(0, KSU_DRIVER_PERMISSION_SU_SESSION);
}

bool ksu_is_su_session_fd(const struct file *filp)
{
    const struct ksu_driver_context *context;

    if (!filp)
        return false;
    context = filp->private_data;
    return context && (context->permissions & KSU_DRIVER_PERMISSION_SU_SESSION);
}

#ifdef CONFIG_KSU_HOOK_CORE
static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
static void ksu_susfs_tw_func(struct callback_head *cb)
{
    struct ksu_susfs_tw *tw = container_of(cb, struct ksu_susfs_tw, cb);

    /*
     * SUSFS compat handlers resolve paths, take mutexes, and touch
     * user buffers, so they must not run from the reboot kprobe's
     * atomic pre-handler context.
     */
    if (ksu_susfs_may_sleep_now())
        ksu_susfs_handle_compat(tw->cmd, tw->arg);
    else
        pr_warn_ratelimited("susfs task_work ran in atomic context\n");
    kfree(tw);
}

static bool ksu_susfs_defer_compat(unsigned int cmd, void __user *arg)
{
    struct ksu_susfs_tw *tw;

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return false;

    tw->cmd = cmd;
    tw->arg = arg;
    tw->cb.func = ksu_susfs_tw_func;

    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        pr_warn("susfs add task_work failed\n");
        return false;
    }

    return true;
}

static void ksu_susfs_handle_compat_safely(unsigned int cmd, void __user *arg,
                                           bool force_defer)
{
    if (force_defer || !ksu_susfs_may_sleep_now()) {
        if (!ksu_susfs_defer_compat(cmd, arg) && !force_defer &&
            ksu_susfs_may_sleep_now())
            ksu_susfs_handle_compat(cmd, arg);
        return;
    }

    ksu_susfs_handle_compat(cmd, arg);
}
#endif
#endif

int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
			  void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	pr_info("sys_reboot: intercepted call! magic: 0x%x id: %d\n", magic1,
		magic2);
#endif

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		int fd = ksu_install_fd();
		// downstream: dereference all arg usage!
		if (copy_to_user((void __user *)*arg, &fd, sizeof(fd))) {
			pr_err("install ksu fd reply err\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
		close_fd(fd);
#else
		__close_fd(current->files, fd);
#endif
		}
		return 0;
	}

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
	if (magic2 == KSU_SUSFS_MAGIC) {
		if (!ksu_susfs_supercall_allowed())
			return 0;
#ifdef CONFIG_KSU_HOOK_CORE
		ksu_susfs_handle_compat_safely(cmd, *arg, false);
#else
		ksu_susfs_handle_compat(cmd, *arg);
#endif
		return 0;
	}
#endif

	// extensions 
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}
	
	if (magic2 == GET_SULOG_DUMP_V2) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		int ret = ksu_sulog_handle_compat_dump(*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		// only root is allowed for this command 
		if (current_uid().val != 0)
			return 0;

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void __user **ppptr = (void __user **)*arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
			strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#else
			strlcpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strlcpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#endif
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
		strscpy(u->release, release_buf, sizeof(u->release));
		strscpy(u->version, version_buf, sizeof(u->version));
#else
		strlcpy(u->release, release_buf, sizeof(u->release));
		strlcpy(u->version, version_buf, sizeof(u->version));
#endif
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

#if defined(KSU_REBOOT_KPROBE)
static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

    /* Check if this is a request to install KSU fd */
    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
    }

#ifdef CONFIG_KSU_HOOKLESS_SUSFS
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_SUSFS_MAGIC) {
		if (!ksu_susfs_supercall_allowed())
			return 0;
		ksu_susfs_handle_compat_safely(cmd, (void __user *)arg4, true);
		return 0;
    }
#endif

    if (magic1 != KSU_INSTALL_MAGIC1)
        return 0;

    if (magic2 == CHANGE_MANAGER_UID) {
        /* only root is allowed for this command */
        if (current_uid().val != 0)
            return 0;

        pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
        ksu_set_manager_appid(cmd);

        if (cmd == ksu_get_manager_appid()) {
            if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
                pr_info("sys_reboot: reply fail\n");
        }

        return 0;
    }

    if (magic2 == GET_SULOG_DUMP_V2) {
        if (current_uid().val != 0)
            return 0;

        int ret = ksu_sulog_handle_compat_dump((void __user *)arg4);
        if (ret)
            return 0;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
    }

    if (magic2 == CHANGE_KSUVER) {
        if (current_uid().val != 0)
            return 0;

        pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
        ksuver_override = cmd;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
    }

    // WARNING!!! triple ptr zone! ***
    // https://wiki.c2.com/?ThreeStarProgrammer
    if (magic2 == CHANGE_SPOOF_UNAME) {
        // only root is allowed for this command
        if (current_uid().val != 0)
            return 0;

        char release_buf[65];
        char version_buf[65];
        static char original_release_buf[65] = {0};
        static char original_version_buf[65] = {0};

        // basically void * void __user * void __user *arg
        void __user **ppptr = (void __user **)arg4;

        // user pointer storage
        // init this as zero so this works on 32-on-64 compat (LE)
        uint64_t u_pptr = 0;
        uint64_t u_ptr = 0;

        pr_info("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

        // arg here is ***, pull out user-space ** via copy_from_user
        if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
            return 0;

        pr_info("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

        // now we got the __user **
        // we cannot dereference this as this is __user
        // we just do another copy_from_user to get it
        if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
            return 0;

        pr_info("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

        // for release
        if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
            return 0;
        release_buf[sizeof(release_buf) - 1] = '\0';

        // for version
        if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
            return 0;
        version_buf[sizeof(version_buf) - 1] = '\0';

        if (original_release_buf[0] == '\0') {
            struct new_utsname *u_curr = utsname();
            // we save current version as the original before modifying
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
            strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
            strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#else
            strlcpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
            strlcpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
#endif
            pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
        }

        // so user can reset
        if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
            memcpy(release_buf, original_release_buf, sizeof(release_buf));
            memcpy(version_buf, original_version_buf, sizeof(version_buf));
        }

        pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

        struct new_utsname *u = utsname();

        down_write(&uts_sem);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
        strscpy(u->release, release_buf, sizeof(u->release));
        strscpy(u->version, version_buf, sizeof(u->version));
#else
        strlcpy(u->release, release_buf, sizeof(u->release));
        strlcpy(u->version, version_buf, sizeof(u->version));
#endif
        up_write(&uts_sem);

        // we write our confirmation on **
        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
            return 0;
    }

    return 0;
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};
#endif

void __init ksu_supercalls_init(void)
{
    ksu_supercall_dump_commands();

#ifdef KSU_REBOOT_KPROBE
    int rc;

    rc = register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }
#endif
}

void __exit ksu_supercalls_exit(void)
{
#ifdef KSU_REBOOT_KPROBE
    unregister_kprobe(&reboot_kp);
#endif
    ksu_supercall_cleanup_state();
}
