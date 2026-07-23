#include <linux/file.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <linux/build_bug.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/compiler_types.h>
#endif
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/types.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/task_stack.h>
#else
#include <linux/sched.h>
#endif
#include <linux/ptrace.h>
#include <asm/unaligned.h>

#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "policy/app_profile.h"
#include "selinux/selinux.h"
#include "compat/kernel_compat.h"
#ifdef CONFIG_KSU_KPROBES_HOOK
#include "hook/syscall_hook.h"
#endif
#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#include "feature/adb_root.h"
#endif
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
#include "hook/syscall_event_bridge.h"
#include "hook/tp_marker.h"
#endif
#include "sulog/event.h"
#include "ksu.h"
#include "util.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"
#define APP_DATA_PATH "/data/data/"
#define APP_USER_PATH "/data/user/"
#define KSU_SU_PATH_WORDS 2
#define KSU_SU_PATH_PREFIX ((u16)'/' | ((u16)'s' << 8))
#define KSU_APP_DATA_PATH_PREFIX ((u16)'/' | ((u16)'d' << 8))
#define KSU_APP_DATA_PATH_LEN (sizeof(APP_DATA_PATH) - 1)
#define KSU_APP_USER_PATH_LEN (sizeof(APP_USER_PATH) - 1)
#define KSU_APP_DATA_PATH_WORDS 2
#define KSU_APP_DATA_TAIL_MASK 0x0000000000ffffffULL
#define KSU_APP_DATA_SCAN_MAX 256
#define KSU_SU_TAIL_MASK 0x00ffffffffffffffULL

bool ksu_su_compat_enabled __read_mostly = true;

static int su_compat_feature_get(u64 *value)
{
	*value = ksu_su_compat_enabled ? 1 : 0;
	return 0;
}

static int su_compat_feature_set(u64 value)
{
	bool enable = value != 0;

	if (enable == ksu_su_compat_enabled)
		return 0;

	ksu_su_compat_enabled = enable;
	pr_info("su_compat: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
	.feature_id = KSU_FEATURE_SU_COMPAT,
	.name = "su_compat",
	.get_handler = su_compat_feature_get,
	.set_handler = su_compat_feature_set,
};

static __always_inline bool ksu_sucompat_current_allowed(void)
{
	uid_t uid = current_uid().val;

	if (!uid)
		return is_ksu_domain_fast() || unlikely(is_ksu_domain());

	return __ksu_is_allow_uid(uid);
}

static const char su_path_cmp[KSU_SU_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = SU_PATH;
static const char app_data_path_cmp[KSU_APP_DATA_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = APP_DATA_PATH;
static const char app_user_path_cmp[KSU_APP_DATA_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = APP_USER_PATH;

static void __user *ksu_sucompat_stack_buffer(const void *d, size_t len)
{
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

static __always_inline const char __user *ksu_sucompat_user_su_arg0(void)
{
	static const char su_arg0[] = "su";

	return ksu_sucompat_stack_buffer(su_arg0, sizeof(su_arg0));
}

static __always_inline void ksu_sucompat_set_argv0_su(struct user_arg_ptr *argv)
{
	const char __user *arg0;

	if (!argv)
		return;

	arg0 = ksu_sucompat_user_su_arg0();
	if (!arg0)
		return;

#ifdef CONFIG_COMPAT
	if (unlikely(argv->is_compat)) {
		compat_uptr_t compat_arg0 = ptr_to_compat((void __user *)arg0);

		if (argv->ptr.compat)
			(void)put_user(compat_arg0,
				       (compat_uptr_t __user *)argv->ptr.compat);
		return;
	}
#endif
	if (argv->ptr.native)
		(void)put_user(arg0,
			       (const char __user *__user *)argv->ptr.native);
}

#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
static __always_inline bool
ksu_sucompat_kernel_system_path_matches(const char *filename)
{
	const u64 *su_words = (const u64 *)su_path_cmp;
	u64 word;

	if (!filename)
		return false;

	BUILD_BUG_ON(sizeof(SU_PATH) + 1 != sizeof(su_path_cmp));
	if (likely(get_unaligned((const u16 *)filename) != KSU_SU_PATH_PREFIX))
		return false;

	word = get_unaligned((const u64 *)filename + KSU_SU_PATH_WORDS - 1);
	if (likely((word & KSU_SU_TAIL_MASK) !=
		   (su_words[KSU_SU_PATH_WORDS - 1] & KSU_SU_TAIL_MASK)))
		return false;

	return get_unaligned((const u64 *)filename) == su_words[0];
}

static __always_inline bool
ksu_sucompat_kernel_app_data_su_path_matches(const char *filename)
{
	const u64 *app_words = (const u64 *)app_data_path_cmp;
	const u64 *user_words = (const u64 *)app_user_path_cmp;
	const char *base, *p;
	unsigned int base_len;
	unsigned int i;
	u64 word;

	BUILD_BUG_ON(KSU_APP_DATA_PATH_LEN != 11);
	BUILD_BUG_ON(KSU_APP_USER_PATH_LEN != 11);

	word = get_unaligned((const u64 *)filename);
	if (word == app_words[0]) {
		word = get_unaligned((const u64 *)filename + 1);
		if (likely((word & KSU_APP_DATA_TAIL_MASK) !=
			   (app_words[1] & KSU_APP_DATA_TAIL_MASK)))
			return false;
		base_len = KSU_APP_DATA_PATH_LEN;
	} else if (word == user_words[0]) {
		word = get_unaligned((const u64 *)filename + 1);
		if (likely((word & KSU_APP_DATA_TAIL_MASK) !=
			   (user_words[1] & KSU_APP_DATA_TAIL_MASK)))
			return false;
		base_len = KSU_APP_USER_PATH_LEN;
	} else {
		return false;
	}

	base = filename + base_len;
	p = base;
	for (i = base_len; i < KSU_APP_DATA_SCAN_MAX; i++, p++) {
		char c = *p;

		if (!c)
			break;
		if (c == '/')
			base = p + 1;
	}
	if (unlikely(i == KSU_APP_DATA_SCAN_MAX || i + 1 < sizeof(KSUD_PATH)))
		return false;

	return base[0] == 's' && base[1] == 'u' && base[2] == '\0';
}

static __always_inline bool
ksu_sucompat_kernel_exec_path_matches(const char *filename)
{
	u16 prefix;

	if (!filename)
		return false;

	prefix = get_unaligned((const u16 *)filename);
	if (likely(prefix != KSU_APP_DATA_PATH_PREFIX)) {
		if (likely(prefix != KSU_SU_PATH_PREFIX))
			return false;
		return ksu_sucompat_kernel_system_path_matches(filename);
	}

	return ksu_sucompat_kernel_app_data_su_path_matches(filename);
}
#endif

#ifdef CONFIG_KSU_KPROBES_HOOK
static __always_inline bool
ksu_sucompat_user_system_path_matches(const char __user *path)
{
	const u64 *su_words = (const u64 *)su_path_cmp;
	const u64 __user *user_words;
	u16 prefix;
	u64 word;

	BUILD_BUG_ON(sizeof(SU_PATH) + 1 != sizeof(su_path_cmp));
	if (get_user(prefix, (const u16 __user *)path))
		return false;
	if (likely(prefix != KSU_SU_PATH_PREFIX))
		return false;

	user_words = (const u64 __user *)path;

	if (get_user(word, &user_words[KSU_SU_PATH_WORDS - 1]))
		return false;
	if (likely((word & KSU_SU_TAIL_MASK) !=
		   (su_words[KSU_SU_PATH_WORDS - 1] & KSU_SU_TAIL_MASK)))
		return false;
	if (unlikely(get_user(word, &user_words[0])))
		return false;
	return word == su_words[0];
}

static __always_inline bool
ksu_sucompat_user_path_matches(const char __user *filename)
{
	const char __user *path;

	if (!filename)
		return false;

	path = (const char __user *)untagged_addr((unsigned long)filename);
	return ksu_sucompat_user_system_path_matches(path);
}

static __always_inline bool
ksu_sucompat_user_app_data_su_path_matches(const char __user *path)
{
	const u64 *data_words = (const u64 *)app_data_path_cmp;
	const u64 *user_path_words = (const u64 *)app_user_path_cmp;
	const u64 __user *path_words = (const u64 __user *)path;
	const char __user *base, *p;
	unsigned int base_len;
	unsigned int i;
	u64 word;
	char c;

	BUILD_BUG_ON(KSU_APP_DATA_PATH_LEN != 11);
	BUILD_BUG_ON(KSU_APP_USER_PATH_LEN != 11);

	if (get_user(word, &path_words[0]))
		return false;

	if (word == data_words[0]) {
		if (get_user(word, &path_words[1]) ||
		    (word & KSU_APP_DATA_TAIL_MASK) !=
			    (data_words[1] & KSU_APP_DATA_TAIL_MASK))
			return false;
		base_len = KSU_APP_DATA_PATH_LEN;
	} else if (word == user_path_words[0]) {
		if (get_user(word, &path_words[1]) ||
		    (word & KSU_APP_DATA_TAIL_MASK) !=
			    (user_path_words[1] & KSU_APP_DATA_TAIL_MASK))
			return false;
		base_len = KSU_APP_USER_PATH_LEN;
	} else {
		return false;
	}

	base = path + base_len;
	p = base;
	for (i = base_len; i < KSU_APP_DATA_SCAN_MAX; i++, p++) {
		if (get_user(c, p))
			return false;
		if (!c)
			break;
		if (c == '/')
			base = p + 1;
	}
	if (unlikely(i == KSU_APP_DATA_SCAN_MAX || i + 1 < sizeof(KSUD_PATH)))
		return false;

	if (get_user(c, base) || c != 's')
		return false;
	if (get_user(c, base + 1) || c != 'u')
		return false;
	if (get_user(c, base + 2) || c)
		return false;

	return true;
}

static __always_inline bool
ksu_sucompat_user_exec_path_matches(const char __user *filename)
{
	const char __user *path;
	u16 prefix;

	if (!filename)
		return false;

	path = (const char __user *)untagged_addr((unsigned long)filename);
	if (get_user(prefix, (const u16 __user *)path))
		return false;

	if (likely(prefix != KSU_APP_DATA_PATH_PREFIX)) {
		if (likely(prefix != KSU_SU_PATH_PREFIX))
			return false;
		return ksu_sucompat_user_system_path_matches(path);
	}

	return ksu_sucompat_user_app_data_su_path_matches(path);
}

static char __user *ksud_user_path(void)
{
	static const char ksud_path[] = KSUD_PATH;

	return ksu_sucompat_stack_buffer(ksud_path, sizeof(ksud_path));
}

static char __user *empty_user_path(void)
{
	return ksu_sucompat_stack_buffer("", sizeof(""));
}

static bool is_ksud_exists()
{
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path) < 0) {
		return false;
	}
	path_put(&path);
	return true;
}

long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		goto do_orig_facessat;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_facessat;
	old_cred = override_creds(ksu_cred);
	if (!is_ksud_exists()) {
		revert_creds(old_cred);
		goto do_orig_facessat;
	}
	ksu_compat_sulog('a');
	pr_info("faccessat su->ksud!\n");
	orig_filename = *filename_user;
	*filename_user = ksud_user_path();
	ret = ksu_invoke_syscall_nr(orig_nr, regs);
	revert_creds(old_cred);
	*filename_user = orig_filename;
	return ret;

do_orig_facessat:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs)
{
	const char __user **filename_user, *orig_filename;
	long ret;
	const struct cred *old_cred;

	filename_user = (const char __user **)&PT_REGS_PARM2(regs);

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		goto do_orig_stat;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_stat;
	old_cred = override_creds(ksu_cred);
	if (!is_ksud_exists()) {
		revert_creds(old_cred);
		goto do_orig_stat;
	}
	ksu_compat_sulog('s');
	pr_info("newfstatat su->ksud!\n");
	orig_filename = *filename_user;
	*filename_user = ksud_user_path();
	ret = ksu_invoke_syscall_nr(orig_nr, regs);
	revert_creds(old_cred);
	*filename_user = orig_filename;
	return ret;

do_orig_stat:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static const struct cred *ksu_redirect_su_path(const char __user **filename_user,
					       char event)
{
	const char __user *new_filename;
	const struct cred *old_cred;

	if (unlikely(!ksu_su_compat_enabled))
		return NULL;
	if (!filename_user)
		return NULL;

	if (likely(!ksu_sucompat_user_path_matches(*filename_user)))
		return NULL;
	if (!ksu_sucompat_current_allowed())
		return NULL;

	old_cred = override_creds(ksu_cred);
	if (!is_ksud_exists()) {
		revert_creds(old_cred);
		return NULL;
	}

	new_filename = ksud_user_path();
	if (!new_filename) {
		revert_creds(old_cred);
		return NULL;
	}

	ksu_compat_sulog(event);
	*filename_user = new_filename;
	return old_cred;
}

const struct cred *ksu_handle_faccessat(int *dfd,
					const char __user **filename_user,
					int *mode, int *flags)
{
	const struct cred *old_cred;

	(void)dfd;
	(void)mode;
	(void)flags;

	old_cred = ksu_redirect_su_path(filename_user, 'a');
	if (old_cred)
		pr_info("faccessat su->ksud!\n");
	return old_cred;
}

const struct cred *ksu_handle_stat(int *dfd,
				   const char __user **filename_user,
				   int *flags)
{
	const struct cred *old_cred;

	(void)dfd;
	(void)flags;

	old_cred = ksu_redirect_su_path(filename_user, 's');
	if (old_cred)
		pr_info("newfstatat su->ksud!\n");
	return old_cred;
}

bool ksu_handle_stat_kernel_filename(char *filename)
{
	const struct cred *old_cred;
	bool exists;

	if (unlikely(!ksu_su_compat_enabled))
		return false;
	if (!filename)
		return false;
	if (likely(!ksu_sucompat_kernel_system_path_matches(filename)))
		return false;
	if (!ksu_sucompat_current_allowed())
		return false;

	old_cred = override_creds(ksu_cred);
	exists = is_ksud_exists();
	revert_creds(old_cred);
	if (!exists)
		return false;

	if (sizeof(KSUD_PATH) > sizeof(SU_PATH))
		return false;
	ksu_compat_sulog('s');
	memcpy(filename, KSUD_PATH, sizeof(KSUD_PATH));
	pr_info("stat filename su->ksud!\n");
	return true;
}
#endif

long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs)
{
	const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
	struct user_arg_ptr exec_argv = { .ptr.native = argv_user };
	struct ksu_sulog_pending_event *pending_sucompat = NULL;
	long ret, orig_regs[5];
	int tmp_fd;
	struct file *ksud_file;
	const struct cred *old_cred;

	if (unlikely(!filename_user))
		goto do_orig_execve;
	if (unlikely(!*filename_user))
		goto do_orig_execve;

	if (likely(!ksu_sucompat_user_exec_path_matches(*filename_user)))
		goto do_orig_execve;
	if (!ksu_sucompat_current_allowed())
		goto do_orig_execve;

	ksu_compat_sulog('x');
	pr_info("sys_execve su found\n");

	tmp_fd = get_unused_fd_flags(O_CLOEXEC);
	if (tmp_fd < 0) {
		pr_err("alloc tmp fd err: %d\n", tmp_fd);
		goto do_orig_execve;
	}

	old_cred = override_creds(ksu_cred);
	ksud_file = filp_open(KSUD_PATH, O_PATH, 0);
	revert_creds(old_cred);
	if (IS_ERR(ksud_file)) {
		pr_err("open ksud err: %ld\n", PTR_ERR(ksud_file));
		put_unused_fd(tmp_fd);
		goto do_orig_execve;
	}

	fd_install(tmp_fd, ksud_file);

	pending_sucompat = ksu_sulog_capture_sucompat(*filename_user, argv_user, GFP_KERNEL);
	ksu_sucompat_set_argv0_su(&exec_argv);
	// execve(file, argv, environ)
	// execveat(fd, file, argv, environ, flags)
	orig_regs[0] = regs->__PT_PARM1_REG;
	orig_regs[1] = regs->__PT_PARM2_REG;
	orig_regs[2] = regs->__PT_PARM3_REG;
	orig_regs[3] = regs->__PT_SYSCALL_PARM4_REG;
	orig_regs[4] = regs->__PT_PARM5_REG;
	regs->__PT_PARM5_REG = AT_EMPTY_PATH;
	regs->__PT_SYSCALL_PARM4_REG = regs->__PT_PARM3_REG;
	regs->__PT_PARM3_REG = regs->__PT_PARM2_REG;
	regs->__PT_PARM2_REG = empty_user_path();
	regs->__PT_PARM1_REG = tmp_fd;

	ret = escape_with_root_profile();
	if (ret) {
		pr_err("escape_with_root_profile failed: %ld\n", ret);
	}
	ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

	ret = ksu_invoke_syscall_nr(__NR_execveat, regs);
	if (ret < 0) {
		ksu_close_fd(tmp_fd);
		regs->__PT_PARM1_REG = orig_regs[0];
		regs->__PT_PARM2_REG = orig_regs[1];
		regs->__PT_PARM3_REG = orig_regs[2];
		regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
		regs->__PT_PARM5_REG = orig_regs[4];
	}
	return ret;

do_orig_execve:
	return ksu_invoke_syscall_nr(orig_nr, regs);
}

#endif // CONFIG_KSU_KPROBES_HOOK

#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
#ifndef CONFIG_KSU_KPROBES_HOOK
extern bool ksud_execve_key;
static inline bool ksu_ksud_execve_hook_enabled(void)
{
	return ksud_execve_key;
}
#endif

static inline int do_ksu_handle_execveat_sucompat(int *fd, const char *filename, void *argv)
{
	struct path kpath;

	(void)fd;
	(void)argv;

	if (unlikely(!ksu_su_compat_enabled))
		return 0;
	if (!filename)
		return 0;
	if (likely(!ksu_sucompat_kernel_exec_path_matches(filename)))
		return 0;
	if (!ksu_sucompat_current_allowed())
		return 0;

	ksu_compat_sulog('x');
	pr_info("do_execveat_common su found\n");
	escape_with_root_profile();
	ksu_sucompat_set_argv0_su(argv);

	if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &kpath)) {
		pr_info("sucompat: /data/adb/ksud not found, fallback to /system/bin/sh");
		memcpy((void *)filename, SH_PATH, sizeof(SH_PATH));
	} else {
		path_put(&kpath);
		memcpy((void *)filename, KSUD_PATH, sizeof(KSUD_PATH));
	}

	return 0;
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static void ksu_handle_execveat_init_mark_tracker(const char *filename)
{
	if (!filename)
		return;

	if (unlikely(strcmp(filename, KSUD_PATH) == 0)) {
		pr_info("hook_manager: escape to root for init executing ksud\n");
		escape_to_root_for_init();
	} else if (likely(!strstr(filename, "/app_process") &&
			  !strstr(filename, "/adbd"))) {
		pr_info("hook_manager: unmark %d exec %s\n", current->pid,
			filename);
		ksu_clear_task_tracepoint_flag_if_needed(current);
	}
}
#endif

int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags)
{
	long ret;

	(void)flags;

	if (current->pid != 1 && is_init(current_cred())) {
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
		ksu_handle_execveat_init_mark_tracker(filename);
#endif
		ret = ksu_adb_root_handle_execveat(filename, (struct user_arg_ptr *)envp);
		if (ret)
			pr_err("adb root failed: %ld\n", ret);
	}

	if (unlikely(ksu_ksud_execve_hook_enabled())) {
		ksu_handle_execveat_ksud(filename, (struct user_arg_ptr *)argv);
	}

	if (current_uid().val == 0) {
		ksu_compat_sulog('x');
	}

	return do_ksu_handle_execveat_sucompat(fd, filename, argv);
}

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags)
{
	if (!filename_ptr || !*filename_ptr || IS_ERR(*filename_ptr))
		return 0;

	return ksu_handle_execve(fd, (*filename_ptr)->name, argv, envp, flags);
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *__never_use_argv, void *__never_use_envp,
				 int *__never_use_flags)
{
	return ksu_handle_execveat(fd, filename_ptr, __never_use_argv, __never_use_envp,
				   __never_use_flags);
}

#endif // !CONFIG_KSU_KPROBES_HOOK || CONFIG_KSU_HACK_ARM64_BRANCH_LINK

// sucompat: permitted process can execute 'su' to gain root access.
void __init ksu_sucompat_init()
{
	if (ksu_register_feature_handler(&su_compat_handler)) {
		pr_err("Failed to register su_compat feature handler\n");
	}
}

void __exit ksu_sucompat_exit()
{
	ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
