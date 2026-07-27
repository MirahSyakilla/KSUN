#ifdef __aarch64__

#include "branch_link_hook.h"

#include <linux/compat.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "internal.h"
#include "pnode.h"
#include "../patch_memory.h"
#include "compat/kernel_compat.h"
#include "feature/sucompat.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#ifdef CONFIG_KSU_KPROBES_SUSFS
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
#include "nomount/nomount.h"
#endif
#include "susfs/kstat.h"
#include "susfs/procfs.h"
#include "susfs/susfs.h"
#endif

#define KSU_BL_SCAN_WIDTH (128 * sizeof(void *))
#define KSU_BL_MAX_RECORDS 96
#define KSU_AARCH64_BL_OPCODE 0x94000000U
#define KSU_AARCH64_BL_MASK 0xfc000000U
#define KSU_AARCH64_BRANCH_IMM_MASK 0x03ffffffU
#define KSU_BL_SU_PATH "/system/bin/su"
#define KSU_BL_SU_PATH_WORDS 2
#define KSU_BL_SU_PATH_PREFIX ((u16)'/' | ((u16)'s' << 8))
#define KSU_BL_SU_TAIL_MASK 0x00ffffffffffffffULL

static const char ksu_bl_su_path_cmp[KSU_BL_SU_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = KSU_BL_SU_PATH;

struct ksu_bl_record {
	const char *name;
	unsigned long site;
	unsigned long original;
	unsigned long hook;
};

static DEFINE_MUTEX(ksu_bl_lock);
static struct ksu_bl_record ksu_bl_records[KSU_BL_MAX_RECORDS];
static int ksu_bl_record_count;
static bool ksu_bl_initialized;

static unsigned long ksu_bl_lookup(const char *name)
{
	unsigned long addr;

	addr = find_kernel_symbol_exact(name);
	if (!addr)
		addr = (unsigned long)ksu_resolve_symbol_for_functable_hook(name);

	pr_info("branch_link: %s=0x%lx\n", name, addr);
	return addr;
}

static __always_inline bool ksu_bl_user_path_is_su(const char __user *filename)
{
	const u64 *su_words = (const u64 *)ksu_bl_su_path_cmp;
	const char __user *path;
	const u64 __user *user_words;
	u16 prefix;
	u64 word;

	if (!filename)
		return false;

	BUILD_BUG_ON(sizeof(KSU_BL_SU_PATH) + 1 !=
		     sizeof(ksu_bl_su_path_cmp));
	path = (const char __user *)untagged_addr((unsigned long)filename);
	if (get_user(prefix, (const u16 __user *)path))
		return false;
	if (likely(prefix != KSU_BL_SU_PATH_PREFIX))
		return false;

	user_words = (const u64 __user *)path;
	if (get_user(word, &user_words[KSU_BL_SU_PATH_WORDS - 1]))
		return false;
	if (likely((word & KSU_BL_SU_TAIL_MASK) !=
		   (su_words[KSU_BL_SU_PATH_WORDS - 1] &
		    KSU_BL_SU_TAIL_MASK)))
		return false;
	if (unlikely(get_user(word, &user_words[0])))
		return false;
	return word == su_words[0];
}

static __always_inline bool ksu_aarch64_insn_is_bl(u32 instruction)
{
	return (instruction & KSU_AARCH64_BL_MASK) == KSU_AARCH64_BL_OPCODE;
}

static __always_inline long ksu_aarch64_get_branch_offset(u32 instruction)
{
	u32 imm26 = instruction & KSU_AARCH64_BRANCH_IMM_MASK;

	if (imm26 & (1U << 25))
		imm26 |= ~KSU_AARCH64_BRANCH_IMM_MASK;

	return (long)(s32)imm26 * sizeof(u32);
}

static __always_inline u32
ksu_aarch64_gen_branch(unsigned long site, unsigned long destination)
{
	long offset = (long)destination - (long)site;
	s32 imm26 = (s32)(offset >> 2);

	return KSU_AARCH64_BL_OPCODE |
	       (imm26 & KSU_AARCH64_BRANCH_IMM_MASK);
}

static int ksu_arm64_bl_replace_at(unsigned long site, unsigned long expected,
				   unsigned long replacement)
{
	const long bl_max_delta = (1L << 25) * sizeof(u32);
	long delta = (long)replacement - (long)site;
	unsigned long destination;
	u32 raw_instruction;
	u32 instruction;
	long offset;
	int ret;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)site,
				     sizeof(raw_instruction)))
		return -EFAULT;
	if (!ksu_aarch64_insn_is_bl(raw_instruction))
		return -EINVAL;

	offset = ksu_aarch64_get_branch_offset(raw_instruction);
	destination = site + offset;
	if (destination != expected)
		return -ENOENT;

	if (delta >= bl_max_delta || delta < -bl_max_delta) {
		pr_info("branch_link: site 0x%lx -> 0x%lx out of range (%ld)\n",
			site, replacement, delta);
		return -ERANGE;
	}
	if (delta & 0x3)
		return -EINVAL;

	instruction = ksu_aarch64_gen_branch(site, replacement);
	ret = ksu_patch_text((void *)site, &instruction, sizeof(instruction),
			     KSU_PATCH_TEXT_FLUSH_ICACHE);
	pr_info("branch_link: patch site 0x%lx 0x%lx -> 0x%lx: %d\n",
		site, expected, replacement, ret);
	return ret;
}

static int ksu_arm64_bl_patch(unsigned long start, size_t width,
			      unsigned long original, unsigned long hook,
			      unsigned long *site_out)
{
	unsigned long site;
	unsigned long end = start + width;
	u32 raw_instruction;
	long offset;

	if (!start || !original || !hook)
		return -EINVAL;

	might_sleep();

	for (site = start; site < end; site += sizeof(raw_instruction)) {
		if (copy_from_kernel_nofault(&raw_instruction, (void *)site,
					     sizeof(raw_instruction)))
			continue;
		if (!ksu_aarch64_insn_is_bl(raw_instruction))
			continue;

		offset = ksu_aarch64_get_branch_offset(raw_instruction);
		if (site + offset != original)
			continue;

		if (site_out)
			*site_out = site;
		return ksu_arm64_bl_replace_at(site, original, hook);
	}

	pr_info("branch_link: callsite for 0x%lx not found from 0x%lx\n",
		original, start);
	return -ENOENT;
}

static int ksu_bl_record_patch(const char *name, unsigned long start,
			       unsigned long original, unsigned long hook)
{
	struct ksu_bl_record *record;
	unsigned long site = 0;
	int ret;

	if (ksu_bl_record_count >= ARRAY_SIZE(ksu_bl_records))
		return -ENOSPC;

	ret = ksu_arm64_bl_patch(start, KSU_BL_SCAN_WIDTH, original, hook, &site);
	if (ret)
		return ret;

	record = &ksu_bl_records[ksu_bl_record_count++];
	record->name = name;
	record->site = site;
	record->original = original;
	record->hook = hook;
	return 0;
}

static void ksu_bl_restore_records_from(int first_record)
{
	while (ksu_bl_record_count > first_record) {
		struct ksu_bl_record *record =
			&ksu_bl_records[ksu_bl_record_count - 1];
		int ret;

		ret = ksu_arm64_bl_replace_at(record->site, record->hook,
					      record->original);
		pr_info("branch_link: restore %s: %d\n", record->name, ret);
		if (ret)
			break;
		ksu_bl_record_count--;
	}
}

static int ksu_bl_record_patch_all(const char *name, unsigned long start,
				   unsigned long original, unsigned long hook)
{
	int first_record = ksu_bl_record_count;
	int count = 0;
	int ret;

	do {
		ret = ksu_bl_record_patch(name, start, original, hook);
		if (!ret)
			count++;
	} while (!ret);

	if (count && ret == -ENOENT)
		return count;

	/* Do not report a partially patched caller as success when the next
	 * callsite ran out of record capacity or text patching failed. */
	if (ret != -ENOENT) {
		ksu_bl_restore_records_from(first_record);
		return ret;
	}
	return count ? count : -ENOENT;
}

static int ksu_bl_record_patch_callers(const char *name,
				       const char * const *callers,
				       size_t caller_count,
				       unsigned long original,
				       unsigned long hook,
				       unsigned int *found_callers,
				       unsigned int *patched_callers)
{
	int count = 0;
	unsigned int found = 0;
	unsigned int patched = 0;
	size_t i;

	for (i = 0; i < caller_count; i++) {
		unsigned long caller_addr = ksu_bl_lookup(callers[i]);
		int ret;

		if (!caller_addr)
			continue;
		found++;

		ret = ksu_bl_record_patch_all(name, caller_addr, original, hook);
		if (ret > 0) {
			count += ret;
			patched++;
		} else {
			pr_info("branch_link: %s from %s: %d\n", name,
				callers[i], ret);
		}
	}
	if (found_callers)
		*found_callers = found;
	if (patched_callers)
		*patched_callers = patched;

	return count ? count : -ENOENT;
}

static void ksu_bl_restore_records(void)
{
	ksu_bl_restore_records_from(0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0) || defined(KSU_HAS_FACCESSAT2)
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode,
			       int flags);
static long __nocfi ksu_do_faccessat(int dfd, const char __user *filename,
				     int mode, int flags)
{
	const struct cred *old_cred = NULL;
	long ret;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	struct ksu_nomount_lookup_scope lookup_scope;
#endif

	if (unlikely(ksu_su_compat_enabled && ksu_bl_user_path_is_su(filename)))
		old_cred = ksu_handle_faccessat(&dfd, &filename, &mode,
						&flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	ret = do_faccessat_fn(dfd, filename, mode, flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
	if (old_cred)
		revert_creds(old_cred);
	return ret;
}
#else
static long (*do_faccessat_fn)(int dfd, const char __user *filename, int mode);
static long __nocfi ksu_do_faccessat(int dfd, const char __user *filename,
				     int mode)
{
	const struct cred *old_cred = NULL;
	long ret;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	struct ksu_nomount_lookup_scope lookup_scope;
#endif

	if (unlikely(ksu_su_compat_enabled && ksu_bl_user_path_is_su(filename)))
		old_cred = ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	ret = do_faccessat_fn(dfd, filename, mode);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
	if (old_cred)
		revert_creds(old_cred);
	return ret;
}
#endif

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
static int (*do_readlinkat_fn)(int dfd, const char __user *pathname,
				char __user *buf, int bufsiz);

static int __nocfi ksu_do_readlinkat(int dfd, const char __user *pathname,
				     char __user *buf, int bufsiz)
{
	struct ksu_nomount_lookup_scope lookup_scope;
	int (*orig_do_readlinkat)(int, const char __user *, char __user *, int);
	int ret;

	orig_do_readlinkat = READ_ONCE(do_readlinkat_fn);
	if (unlikely(!orig_do_readlinkat))
		return -EOPNOTSUPP;
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
	ret = orig_do_readlinkat(dfd, pathname, buf, bufsiz);
	ksu_nomount_lookup_scope_exit(&lookup_scope);
	return ret;
}

static bool ksu_branch_link_patch_readlink_family(void)
{
	static const char * const callers[] = {
		"__arm64_sys_readlinkat",
		"__arm64_sys_readlink",
	};
	unsigned long target = ksu_bl_lookup("do_readlinkat");
	unsigned int found = 0;
	unsigned int patched = 0;
	int count;

	WRITE_ONCE(do_readlinkat_fn, (void *)target);
	count = ksu_bl_record_patch_callers(
		"readlink/do_readlinkat", callers, ARRAY_SIZE(callers), target,
		(unsigned long)ksu_do_readlinkat, &found, &patched);
	if (count <= 0)
		WRITE_ONCE(do_readlinkat_fn, NULL);
	pr_info("branch_link: readlink family=%u/%u sites=%d\n", patched,
		found, count);
	return target && found && patched == found;
}
#endif

static void ksu_bl_handle_stat_result(struct kstat *stat, int ret)
{
#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_susfs_handle_stat_result(stat, ret);
#else
	(void)stat;
	(void)ret;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
static int (*vfs_fstatat_fn)(int dfd, const char __user *filename,
			     struct kstat *stat, int flags);
static int __nocfi ksu_vfs_fstatat(int dfd, const char __user *filename,
				   struct kstat *stat, int flags)
{
	const struct cred *old_cred = NULL;
	int ret;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	struct ksu_nomount_lookup_scope lookup_scope;
#endif

	if (unlikely(ksu_su_compat_enabled && ksu_bl_user_path_is_su(filename)))
		old_cred = ksu_handle_stat(&dfd, &filename, &flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	ret = vfs_fstatat_fn(dfd, filename, stat, flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
	if (old_cred)
		revert_creds(old_cred);
	ksu_bl_handle_stat_result(stat, ret);
	return ret;
}
#endif

#if defined(CONFIG_KSU_KPROBES_NOMOUNT) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
/*
 * Android 6.1 LTO can inline vfs_fstatat() into newfstatat(), leaving the
 * branch-link stat hook on vfs_statx() after getname_flags() has already run.
 * Rebuild only candidate dirfd-relative names so NoMount/SUSFS can see the dfd.
 */
static __always_inline bool ksu_nomount_statx_relative_may_match(
	const char *path)
{
	bool nomount_active;
	bool susfs_active;
	size_t len;

	if (unlikely(!path || !path[0]))
		return false;
	if (likely(path[0] == '/'))
		return false;

	nomount_active = ksu_nomount_active_for_current();
	susfs_active = ksu_susfs_path_filter_active();
	if (!nomount_active && !susfs_active)
		return false;

	len = strlen(path);
	if (nomount_active && ksu_nomount_relative_rule_may_match(path, len))
		return true;
	if (susfs_active && ksu_susfs_relative_hide_rule_may_match(path, len))
		return true;

	return false;
}

static __always_inline struct filename *ksu_nomount_rebase_statx_filename(
	int dfd, struct filename *filename)
{
	struct ksu_nomount_lookup_scope lookup_scope;
	struct filename *rebased;
	const char *path;

	if (likely(dfd == AT_FDCWD))
		return NULL;
	if (unlikely(!filename || IS_ERR(filename)))
		return NULL;
	path = filename->name;
	if (!ksu_nomount_statx_relative_may_match(path))
		return NULL;

	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
	rebased = getname_kernel(path);
	ksu_nomount_lookup_scope_exit(&lookup_scope);

	return rebased;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
static int (*vfs_statx_fn)(int dfd, struct filename *filename, int flags,
			   struct kstat *stat, u32 request_mask);
static int __nocfi ksu_vfs_statx(int dfd, struct filename *filename,
				 int flags, struct kstat *stat,
				 u32 request_mask)
{
	struct filename *lookup_name = filename;
	struct filename *rebased = NULL;
	int ret;

	if (filename && !IS_ERR(filename))
		ksu_handle_stat_kernel_filename((char *)filename->name);
#if defined(CONFIG_KSU_KPROBES_NOMOUNT) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	rebased = ksu_nomount_rebase_statx_filename(dfd, filename);
	if (IS_ERR(rebased)) {
		ret = PTR_ERR(rebased);
		ksu_bl_handle_stat_result(stat, ret);
		return ret;
	}
	if (rebased)
		lookup_name = rebased;
#endif
	ret = vfs_statx_fn(dfd, lookup_name, flags, stat, request_mask);
#if defined(CONFIG_KSU_KPROBES_NOMOUNT) && \
	LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	if (rebased)
		putname(rebased);
#endif
	ksu_bl_handle_stat_result(stat, ret);
	return ret;
}
#else
static int (*vfs_statx_fn)(int dfd, const char __user *filename, int flags,
			   struct kstat *stat, u32 request_mask);
static int __nocfi ksu_vfs_statx(int dfd, const char __user *filename,
				 int flags, struct kstat *stat,
				 u32 request_mask)
{
	const struct cred *old_cred = NULL;
	int ret;
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	struct ksu_nomount_lookup_scope lookup_scope;
#endif

	if (unlikely(ksu_su_compat_enabled && ksu_bl_user_path_is_su(filename)))
		old_cred = ksu_handle_stat(&dfd, &filename, &flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	ret = vfs_statx_fn(dfd, filename, flags, stat, request_mask);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
	if (old_cred)
		revert_creds(old_cred);
	ksu_bl_handle_stat_result(stat, ret);
	return ret;
}
#endif

#ifdef CONFIG_KSU_KPROBES_SUSFS
static int (*vfs_getattr_nosec_fn)(const struct path *path, struct kstat *stat,
				   u32 request_mask, unsigned int query_flags);

static int __nocfi ksu_vfs_getattr_nosec(const struct path *path,
					 struct kstat *stat, u32 request_mask,
					 unsigned int query_flags)
{
	int ret = vfs_getattr_nosec_fn(path, stat, request_mask, query_flags);

	ksu_susfs_handle_vfs_getattr_nosec(path, stat, ret);
	return ret;
}

static int __nocfi ksu_vfs_getattr_nosec_fd(const struct path *path,
					    struct kstat *stat,
					    u32 request_mask,
					    unsigned int query_flags)
{
	int ret = vfs_getattr_nosec_fn(path, stat, request_mask, query_flags);

	ksu_susfs_handle_vfs_getattr_nosec(path, stat, ret);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	/* Direct fstat callers retain the resolved path, so descendants of a
	 * redirected directory can restore the visible device as well. */
	ksu_nomount_handle_fd_getattr(ret, path, stat);
#endif
	return ret;
}

static int (*vfs_fstat_fn)(unsigned int fd, struct kstat *stat);

static int __nocfi ksu_vfs_fstat(unsigned int fd, struct kstat *stat)
{
	int ret = vfs_fstat_fn(fd, stat);

	/* This 5.4 LTO tree emits vfs_fstat() as a private helper that performs
	 * getattr through an indirect inode-operation call.  There is therefore no
	 * vfs_getattr_nosec branch for the old fd-stat patch to replace. */
	ksu_bl_handle_stat_result(stat, ret);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (!ret && ksu_nomount_active_for_current()) {
		struct fd f = fdget_raw(fd);

		if (f.file) {
			ksu_nomount_handle_fd_getattr(ret, &f.file->f_path, stat);
			fdput(f);
		}
	}
#endif
	return ret;
}
#endif

#ifdef CONFIG_KSU_KPROBES_SUSFS
static int (*vfs_statfs_fn)(const struct path *path, struct kstatfs *statfs);

static void ksu_handle_statfs_result(const struct path *path,
					     struct kstatfs *statfs, int ret)
{
	struct inode *inode;

	if (ret || !path || !path->dentry || !statfs)
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	ksu_susfs_open_redirect_apply_statfs(inode, statfs);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_handle_statfs_path(ret, path, statfs);
#endif
}

static int __nocfi ksu_user_statfs(const char __user *pathname,
					struct kstatfs *statfs)
{
	struct path path;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT;
	int ret;

retry:
	ret = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!ret) {
		ret = vfs_statfs_fn(&path, statfs);
		ksu_handle_statfs_result(&path, statfs, ret);
		path_put(&path);
		if (retry_estale(ret, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return ret;
}

static int __nocfi ksu_fd_statfs(int fd, struct kstatfs *statfs)
{
	struct fd f = fdget_raw(fd);
	int ret = -EBADF;

	if (f.file) {
		ret = vfs_statfs_fn(&f.file->f_path, statfs);
		ksu_handle_statfs_result(&f.file->f_path, statfs, ret);
		fdput(f);
	}
	return ret;
}
#endif

static bool ksu_branch_link_patch_stat_path_family(void)
{
	static const char * const callers[] = {
		"__arm64_sys_newfstatat",
		"__arm64_sys_fstatat64",
		"__arm64_compat_sys_newfstatat",
		"__arm64_sys_statx",
	};
	unsigned int found = 0;
	unsigned int patched = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(callers); i++) {
		unsigned long caller = ksu_bl_lookup(callers[i]);
		unsigned long target;
		int ret;

		if (!caller)
			continue;
		found++;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		target = ksu_bl_lookup("vfs_fstatat");
		vfs_fstatat_fn = (void *)target;
		ret = ksu_bl_record_patch("stat-path/vfs_fstatat", caller,
					  target, (unsigned long)ksu_vfs_fstatat);
		if (ret) {
			target = ksu_bl_lookup("vfs_statx");
			vfs_statx_fn = (void *)target;
			ret = ksu_bl_record_patch("stat-path/vfs_statx", caller,
						  target,
						  (unsigned long)ksu_vfs_statx);
		}
#else
		target = ksu_bl_lookup("vfs_statx");
		vfs_statx_fn = (void *)target;
		ret = ksu_bl_record_patch("stat-path/vfs_statx", caller,
					  target, (unsigned long)ksu_vfs_statx);
#endif
		if (!ret)
			patched++;
		else
			pr_info("branch_link: stat path caller %s: %d\n",
				callers[i], ret);
	}

	pr_info("branch_link: stat path family found=%u patched=%u\n",
		found, patched);
	return found > 0 && found == patched;
}

static bool ksu_branch_link_patch_stat_fd_family(void)
{
#ifdef CONFIG_KSU_KPROBES_SUSFS
	static const char * const direct_callers[] = {
		"vfs_statx_fd",
	};
	static const char * const fstat_callers[] = {
		"__arm64_sys_newfstat",
		"__arm64_sys_fstat",
		"__arm64_sys_fstat64",
		"__arm64_compat_sys_newfstat",
		"__arm64_compat_sys_fstat",
		"__arm64_compat_sys_fstat64",
	};
	unsigned long getattr_target = ksu_bl_lookup("vfs_getattr_nosec");
	unsigned long fstat_target = ksu_bl_lookup("vfs_fstat");
	unsigned int direct_found = 0;
	unsigned int direct_patched = 0;
	unsigned int direct_sites = 0;
	unsigned int fstat_found = 0;
	unsigned int fstat_patched = 0;
	unsigned int failures = 0;
	size_t i;

	vfs_getattr_nosec_fn = (void *)getattr_target;
	vfs_fstat_fn = (void *)fstat_target;
	for (i = 0; i < ARRAY_SIZE(direct_callers); i++) {
		unsigned long caller = ksu_bl_lookup(direct_callers[i]);
		int ret;

		if (!caller)
			continue;
		direct_found++;
		ret = ksu_bl_record_patch_all(
			"stat-fd/vfs_getattr_nosec", caller, getattr_target,
			(unsigned long)ksu_vfs_getattr_nosec_fd);
		if (ret > 0) {
			direct_patched++;
			direct_sites += ret;
		} else {
			failures++;
			pr_info("branch_link: stat fd caller %s: %d\n",
				 direct_callers[i], ret);
		}
	}
	if (fstat_target) {
		int ret = ksu_bl_record_patch_callers(
			"stat-fd/vfs_fstat", fstat_callers,
			ARRAY_SIZE(fstat_callers), fstat_target,
			(unsigned long)ksu_vfs_fstat, &fstat_found,
			&fstat_patched);

		if (ret <= 0 || fstat_patched != fstat_found)
			failures++;
	} else {
		failures++;
	}

	pr_info("branch_link: stat fd direct=%u/%u sites=%u fstat=%u/%u failures=%u\n",
		 direct_patched, direct_found, direct_sites, fstat_patched,
		 fstat_found, failures);
	return getattr_target && direct_found && direct_patched == direct_found &&
		fstat_target && fstat_found && fstat_patched == fstat_found &&
		!failures;
#else
	return false;
#endif
}

#ifdef CONFIG_KSU_KPROBES_SUSFS
static bool ksu_branch_link_patch_statfs_family(void)
{
	static const char * const path_callers[] = {
		"__arm64_sys_statfs",
		"__arm64_sys_statfs64",
		"__arm64_compat_sys_statfs",
		"__arm64_compat_sys_statfs64",
	};
	static const char * const fd_callers[] = {
		"__arm64_sys_fstatfs",
		"__arm64_sys_fstatfs64",
		"__arm64_compat_sys_fstatfs",
		"__arm64_compat_sys_fstatfs64",
	};
	unsigned int path_found = 0, path_patched = 0;
	unsigned int fd_found = 0, fd_patched = 0;
	unsigned long target = ksu_bl_lookup("vfs_statfs");
	unsigned long user_statfs_target = ksu_bl_lookup("user_statfs");
	unsigned long fd_statfs_target = ksu_bl_lookup("fd_statfs");
	size_t i;

	vfs_statfs_fn = (void *)target;
	for (i = 0; i < ARRAY_SIZE(path_callers); i++) {
		unsigned long caller = ksu_bl_lookup(path_callers[i]);
		int ret;

		if (!caller)
			continue;
		path_found++;
		ret = ksu_bl_record_patch("statfs-path/user_statfs", caller,
					  user_statfs_target,
					  (unsigned long)ksu_user_statfs);
		if (!ret)
			path_patched++;
		else
			pr_info("branch_link: statfs path caller %s: %d\n",
				path_callers[i], ret);
	}
	for (i = 0; i < ARRAY_SIZE(fd_callers); i++) {
		unsigned long caller = ksu_bl_lookup(fd_callers[i]);
		int ret;

		if (!caller)
			continue;
		fd_found++;
		ret = ksu_bl_record_patch("statfs-fd/fd_statfs", caller,
					  fd_statfs_target,
					  (unsigned long)ksu_fd_statfs);
		if (!ret)
			fd_patched++;
		else
			pr_info("branch_link: statfs fd caller %s: %d\n",
				fd_callers[i], ret);
	}

	pr_info("branch_link: statfs family path=%u/%u fd=%u/%u\n",
		path_patched, path_found, fd_patched, fd_found);
	return target && user_statfs_target && fd_statfs_target &&
		path_found && path_found == path_patched &&
		fd_found && fd_found == fd_patched;
}
#endif

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
static int ksu_nomount_rebase_execve_filename(
	int fd, struct filename **filename_ptr)
{
	struct filename *replacement;
	struct ksu_nomount_lookup_scope lookup_scope;
	struct filename *filename;

	if (!filename_ptr || !*filename_ptr || IS_ERR(*filename_ptr) ||
	    fd == AT_FDCWD)
		return 0;
	filename = *filename_ptr;
	if (!filename->name || !filename->name[0] || filename->name[0] == '/')
		return 0;
	if (!ksu_nomount_active_for_current() &&
	    !ksu_susfs_path_filter_active())
		return 0;
	ksu_nomount_lookup_scope_enter(&lookup_scope, fd);
	replacement = getname_kernel(filename->name);
	ksu_nomount_lookup_scope_exit(&lookup_scope);
	if (IS_ERR(replacement)) {
		putname(filename);
		*filename_ptr = NULL;
		return PTR_ERR(replacement);
	}
	putname(filename);
	*filename_ptr = replacement;
	return 0;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
static int (*do_execveat_common_fn)(int fd, struct filename *filename,
					struct user_arg_ptr argv,
				    struct user_arg_ptr envp, int flags);
static int __nocfi ksu_do_execveat_common(int fd, struct filename *filename,
					  struct user_arg_ptr argv,
					  struct user_arg_ptr envp, int flags)
{
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ret = ksu_nomount_rebase_execve_filename(fd, &filename);
	if (ret)
		return ret;
#endif
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return do_execveat_common_fn(fd, filename, argv, envp, flags);
}
#else
static int (*__do_execve_file_fn)(int fd, struct filename *filename,
				  struct user_arg_ptr argv,
				  struct user_arg_ptr envp, int flags,
				  struct file *file);
static int __nocfi ksu_do_execve_file(int fd, struct filename *filename,
				      struct user_arg_ptr argv,
				      struct user_arg_ptr envp, int flags,
				      struct file *file)
{
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ret = ksu_nomount_rebase_execve_filename(fd, &filename);
	if (ret)
		return ret;
#endif
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return __do_execve_file_fn(fd, filename, argv, envp, flags, file);
}

static int (*do_execve_fn)(struct filename *filename,
			   const char __user *const __user *__argv,
			   const char __user *const __user *__envp);
static int __nocfi ksu_do_execve(struct filename *filename,
				 const char __user *const __user *__argv,
				 const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	int fd = AT_FDCWD;
	int flags = 0;

	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return do_execve_fn(filename, argv.ptr.native, envp.ptr.native);
}

static int (*do_execveat_fn)(int fd, struct filename *filename,
			     const char __user *const __user *__argv,
			     const char __user *const __user *__envp,
			     int flags);
static int __nocfi ksu_do_execveat(int fd, struct filename *filename,
				   const char __user *const __user *__argv,
				   const char __user *const __user *__envp,
				   int flags)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ret = ksu_nomount_rebase_execve_filename(fd, &filename);
	if (ret)
		return ret;
#endif
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return do_execveat_fn(fd, filename, argv.ptr.native, envp.ptr.native,
			      flags);
}

#ifdef CONFIG_COMPAT
static int (*compat_do_execve_fn)(struct filename *filename,
				  const compat_uptr_t __user *__argv,
				  const compat_uptr_t __user *__envp);
static int __nocfi ksu_compat_do_execve(struct filename *filename,
					const compat_uptr_t __user *__argv,
					const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = { .is_compat = true, .ptr.compat = __argv };
	struct user_arg_ptr envp = { .is_compat = true, .ptr.compat = __envp };
	int fd = AT_FDCWD;
	int flags = 0;

	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return compat_do_execve_fn(filename, argv.ptr.compat, envp.ptr.compat);
}

static int (*compat_do_execveat_fn)(int fd, struct filename *filename,
				    const compat_uptr_t __user *__argv,
				    const compat_uptr_t __user *__envp,
				    int flags);
static int __nocfi ksu_compat_do_execveat(
	int fd, struct filename *filename,
	const compat_uptr_t __user *__argv,
	const compat_uptr_t __user *__envp, int flags)
{
	struct user_arg_ptr argv = { .is_compat = true, .ptr.compat = __argv };
	struct user_arg_ptr envp = { .is_compat = true, .ptr.compat = __envp };
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ret = ksu_nomount_rebase_execve_filename(fd, &filename);
	if (ret)
		return ret;
#endif
	ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);
	return compat_do_execveat_fn(fd, filename, argv.ptr.compat,
				     envp.ptr.compat, flags);
}
#endif
#endif

#ifdef CONFIG_KSU_KPROBES_SUSFS
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
static long (*do_sys_open_fn)(int dfd, const char __user *filename, int flags,
			      umode_t mode);

static long __nocfi ksu_do_sys_open(int dfd, const char __user *filename,
				    int flags, umode_t mode)
{
	struct ksu_nomount_lookup_scope lookup_scope;
	long (*orig_do_sys_open)(int, const char __user *, int, umode_t);
	long ret;

	orig_do_sys_open = READ_ONCE(do_sys_open_fn);
	if (unlikely(!orig_do_sys_open))
		return -EOPNOTSUPP;
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
	ret = orig_do_sys_open(dfd, filename, flags, mode);
	ksu_nomount_lookup_scope_exit(&lookup_scope);
	return ret;
}
#endif

static struct file *(*do_filp_open_fn)(int dfd, struct filename *pathname,
				       const struct open_flags *op);
static struct file *__nocfi
ksu_do_filp_open(int dfd, struct filename *pathname,
			 const struct open_flags *op)
{
	struct file *(*orig_do_filp_open)(int, struct filename *,
					 const struct open_flags *);
	struct filename *redirected_name = NULL;
	struct filename *lookup_name;
	struct filename *owned_name = NULL;
	struct filename *open_name = pathname;
	struct path target_path;
	struct file *file;
	int lookup_err;

	orig_do_filp_open = READ_ONCE(do_filp_open_fn);
	if (unlikely(!orig_do_filp_open))
		return ERR_PTR(-EOPNOTSUPP);

	if (!pathname || IS_ERR(pathname) || !op)
		return orig_do_filp_open(dfd, pathname, op);

	/* getname() cannot see an arbitrary directory fd.  Rebuild a temporary
	 * filename while the NoMount lookup scope supplies that fd, then retain the
	 * caller-owned original filename for do_sys_open() to release. */
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (dfd != AT_FDCWD && pathname->name[0] && pathname->name[0] != '/' &&
	    !ksu_nomount_lookup_scope_matches(dfd)) {
		struct ksu_nomount_lookup_scope lookup_scope;

		ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
		owned_name = getname_kernel(pathname->name);
		ksu_nomount_lookup_scope_exit(&lookup_scope);
		if (IS_ERR(owned_name))
			return ERR_CAST(owned_name);
		open_name = owned_name;
	}
#endif

	if (!ksu_susfs_open_redirect_active())
		goto open;

	/* Resolve the visible pathname without opening or creating it.  The old
	 * probe-open approach changed O_EXCL/O_TRUNC semantics and could create
	 * unrelated files before deciding that no redirect applied. */
	/* filename_lookup() consumes its filename argument.  Probe with a separate
	 * copy so the caller-owned pathname (or our owned relative-path copy) stays
	 * valid for the actual open below. */
	lookup_name = getname_kernel(open_name->name);
	if (IS_ERR(lookup_name)) {
		file = ERR_CAST(lookup_name);
		goto out;
	}
	lookup_err = filename_lookup(dfd, lookup_name, op->lookup_flags,
				     &target_path, NULL);
	if (lookup_err)
		goto open;

	redirected_name = ksu_susfs_open_redirect_getname(
		d_backing_inode(target_path.dentry));
	path_put(&target_path);
	if (IS_ERR(redirected_name)) {
		file = ERR_CAST(redirected_name);
		goto out;
	}
	if (redirected_name) {
		file = orig_do_filp_open(dfd, redirected_name, op);
		putname(redirected_name);
		goto out;
	}

open:
	file = orig_do_filp_open(dfd, open_name, op);
out:
	if (owned_name)
		putname(owned_name);
	return file;
}

static struct vfsmount *(*vfs_create_mount_fn)(struct fs_context *fc);
static struct vfsmount *__nocfi ksu_vfs_create_mount(struct fs_context *fc)
{
	bool hide = ksu_susfs_should_hide_new_vfsmount();
	struct vfsmount *mnt = vfs_create_mount_fn(fc);

	ksu_susfs_mark_vfsmount_hidden(mnt, hide);
	return mnt;
}

static struct mount *(*clone_mnt_fn)(struct mount *old, struct dentry *root,
				     int flag);
static struct mount *__nocfi ksu_clone_mnt(struct mount *old,
					  struct dentry *root, int flag)
{
	bool hide = ksu_susfs_should_hide_cloned_mount(old);
	struct mount *mnt = clone_mnt_fn(old, root, flag);

	ksu_susfs_mark_mount_hidden(mnt, hide);
	return mnt;
}

static void (*cleanup_mnt_fn)(struct mount *mnt);
static void __nocfi ksu_cleanup_mnt(struct mount *mnt)
{
	ksu_susfs_handle_cleanup_mnt(mnt);
	cleanup_mnt_fn(mnt);
}

static bool ksu_branch_link_patch_susfs(void)
{
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	static const char * const do_sys_open_callers[] = {
		"__arm64_sys_open",
		"__arm64_sys_openat",
		"__arm64_compat_sys_open",
		"__arm64_compat_sys_openat",
	};
#endif
	static const char * const do_filp_open_callers[] = {
		"do_sys_open",
		"do_sys_openat2",
	};
	static const char * const vfs_create_mount_callers[] = {
		"fc_mount",
		"do_new_mount_fc",
		"__do_sys_fsmount",
		"__se_sys_fsmount",
		"__arm64_sys_fsmount",
		"fuse_dentry_automount",
	};
	static const char * const clone_mnt_callers[] = {
		"mnt_clone_internal",
		"copy_tree",
		"clone_private_mount",
		"__do_loopback",
	};
	static const char * const cleanup_mnt_callers[] = {
		"__cleanup_mnt",
		"delayed_mntput",
		"mntput_no_expire",
	};
	unsigned long caller_addr;
	unsigned long target_addr;
	int create_count;
	int clone_count;
	int cleanup_count;
	int open_count;
	unsigned int open_callers_found = 0;
	unsigned int open_callers_patched = 0;
	bool open_ready = false;
	bool direct_getattr_ready;
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	{
		unsigned int open_scope_found = 0;
		unsigned int open_scope_patched = 0;
		int open_scope_count;

		target_addr = ksu_bl_lookup("do_sys_open");
		WRITE_ONCE(do_sys_open_fn, (void *)target_addr);
		open_scope_count = ksu_bl_record_patch_callers(
			"nomount/do_sys_open", do_sys_open_callers,
			ARRAY_SIZE(do_sys_open_callers), target_addr,
			(unsigned long)ksu_do_sys_open, &open_scope_found,
			&open_scope_patched);
		if (open_scope_count <= 0)
			WRITE_ONCE(do_sys_open_fn, NULL);
		pr_info("branch_link: open dfd scope=%u/%u sites=%d\n",
			open_scope_patched, open_scope_found, open_scope_count);
	}
#endif

	target_addr = ksu_bl_lookup("do_filp_open");
	if (target_addr) {
		/* Publish the original before the first text patch. stop_machine()
		 * releases other CPUs before the patch helper returns, so publishing
		 * afterwards would leave a small NULL-call window. */
		WRITE_ONCE(do_filp_open_fn, (void *)target_addr);
		open_count = ksu_bl_record_patch_callers(
			"susfs/do_filp_open", do_filp_open_callers,
			ARRAY_SIZE(do_filp_open_callers), target_addr,
			(unsigned long)ksu_do_filp_open, &open_callers_found,
			&open_callers_patched);
		open_ready = open_count > 0 && open_callers_found > 0 &&
			     open_callers_patched == open_callers_found;
	} else {
		open_count = -ENOENT;
	}
	if (open_count <= 0)
		WRITE_ONCE(do_filp_open_fn, NULL);
	pr_info("branch_link: susfs/do_filp_open patched: %d\n", open_count);
	ksu_susfs_set_open_redirect_ready(open_ready);

	caller_addr = ksu_bl_lookup("vfs_getattr");
	target_addr = ksu_bl_lookup("vfs_getattr_nosec");
	vfs_getattr_nosec_fn = (void *)target_addr;
	ret = ksu_bl_record_patch_all("susfs/vfs_getattr_nosec", caller_addr,
				      target_addr,
				      (unsigned long)ksu_vfs_getattr_nosec);
	pr_info("branch_link: susfs/vfs_getattr_nosec: %d\n", ret);
	direct_getattr_ready = ret > 0;

	target_addr = ksu_bl_lookup("vfs_create_mount");
	vfs_create_mount_fn = (void *)target_addr;
	create_count = ksu_bl_record_patch_callers(
		"susfs/vfs_create_mount", vfs_create_mount_callers,
		ARRAY_SIZE(vfs_create_mount_callers), target_addr,
		(unsigned long)ksu_vfs_create_mount, NULL, NULL);
	pr_info("branch_link: susfs/vfs_create_mount patched: %d\n",
		create_count);

	target_addr = ksu_bl_lookup("clone_mnt");
	clone_mnt_fn = (void *)target_addr;
	clone_count = ksu_bl_record_patch_callers(
		"susfs/clone_mnt", clone_mnt_callers,
		ARRAY_SIZE(clone_mnt_callers), target_addr,
		(unsigned long)ksu_clone_mnt, NULL, NULL);
	pr_info("branch_link: susfs/clone_mnt patched: %d\n", clone_count);

	target_addr = ksu_bl_lookup("cleanup_mnt");
	cleanup_mnt_fn = (void *)target_addr;
	cleanup_count = ksu_bl_record_patch_callers(
		"susfs/cleanup_mnt", cleanup_mnt_callers,
		ARRAY_SIZE(cleanup_mnt_callers), target_addr,
		(unsigned long)ksu_cleanup_mnt, NULL, NULL);
	pr_info("branch_link: susfs/cleanup_mnt patched: %d\n",
		cleanup_count);

	ksu_susfs_set_mount_runtime_ready(create_count > 0 && clone_count > 0 &&
					  cleanup_count > 0);
	return direct_getattr_ready;
}
#endif

int ksu_branch_link_patch_init(void)
{
	unsigned long caller_addr;
	unsigned long target_addr;
	bool stat_path_ready;
	bool stat_fd_ready;
	bool nomount_getattr_ready = false;
	int ret;

	mutex_lock(&ksu_bl_lock);
	if (ksu_bl_initialized) {
		mutex_unlock(&ksu_bl_lock);
		return 0;
	}

	caller_addr = ksu_bl_lookup("__arm64_sys_faccessat");
	target_addr = ksu_bl_lookup("do_faccessat");
	do_faccessat_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("faccessat/do_faccessat", caller_addr,
				  target_addr, (unsigned long)ksu_do_faccessat);
	pr_info("branch_link: faccessat/do_faccessat: %d\n", ret);

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_branch_link_patch_readlink_family();
#endif

	stat_path_ready = ksu_branch_link_patch_stat_path_family();
	stat_fd_ready = ksu_branch_link_patch_stat_fd_family();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	{
		static const char * const execve_callers[] = {
			"__arm64_sys_execve",
			"__arm64_sys_execveat",
#ifdef CONFIG_COMPAT
			"__arm64_compat_sys_execve",
			"__arm64_compat_sys_execveat",
#endif
		};
		unsigned int execve_found = 0;
		unsigned int execve_patched = 0;

		target_addr = ksu_bl_lookup("do_execveat_common");
		do_execveat_common_fn = (void *)target_addr;
		ret = ksu_bl_record_patch_callers(
			"execve/do_execveat_common", execve_callers,
			ARRAY_SIZE(execve_callers), target_addr,
			(unsigned long)ksu_do_execveat_common, &execve_found,
			&execve_patched);
		pr_info("branch_link: execve/do_execveat_common family=%u/%u sites=%d\n",
			execve_patched, execve_found, ret);
	}
#else
	caller_addr = ksu_bl_lookup("__arm64_sys_execve");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("execve/__do_execve_file", caller_addr,
				  target_addr, (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: execve/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("do_execve");
		do_execve_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("execve/do_execve", caller_addr,
					  target_addr,
					  (unsigned long)ksu_do_execve);
		pr_info("branch_link: execve/do_execve: %d\n", ret);
	}
	caller_addr = ksu_bl_lookup("__arm64_sys_execveat");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("execveat/__do_execve_file", caller_addr,
				  target_addr, (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: execveat/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("do_execveat");
		do_execveat_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("execveat/do_execveat", caller_addr,
					  target_addr,
					  (unsigned long)ksu_do_execveat);
		pr_info("branch_link: execveat/do_execveat: %d\n", ret);
	}
#ifdef CONFIG_COMPAT
	caller_addr = ksu_bl_lookup("__arm64_compat_sys_execve");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("compat_execve/__do_execve_file",
				  caller_addr, target_addr,
				  (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: compat_execve/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("compat_do_execve");
		compat_do_execve_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("compat_execve/compat_do_execve",
					  caller_addr, target_addr,
					  (unsigned long)ksu_compat_do_execve);
		pr_info("branch_link: compat_execve/compat_do_execve: %d\n",
			ret);
	}
	caller_addr = ksu_bl_lookup("__arm64_compat_sys_execveat");
	target_addr = ksu_bl_lookup("__do_execve_file");
	__do_execve_file_fn = (void *)target_addr;
	ret = ksu_bl_record_patch("compat_execveat/__do_execve_file",
				  caller_addr, target_addr,
				  (unsigned long)ksu_do_execve_file);
	pr_info("branch_link: compat_execveat/__do_execve_file: %d\n", ret);
	if (ret) {
		target_addr = ksu_bl_lookup("compat_do_execveat");
		compat_do_execveat_fn = (void *)target_addr;
		ret = ksu_bl_record_patch("compat_execveat/compat_do_execveat",
					  caller_addr, target_addr,
					  (unsigned long)ksu_compat_do_execveat);
		pr_info("branch_link: compat_execveat/compat_do_execveat: %d\n",
			ret);
	}
#endif
#endif

	#ifdef CONFIG_KSU_KPROBES_SUSFS
	{
		bool direct_getattr_ready = ksu_branch_link_patch_susfs();
		bool statfs_ready = ksu_branch_link_patch_statfs_family();

	#ifdef CONFIG_KSU_KPROBES_NOMOUNT
		nomount_getattr_ready = ksu_nomount_getattr_runtime_ready();
	#endif
		/* The fd family has its own LTO path (vfs_fstat) and cannot be
		 * considered covered merely because the ordinary getattr return probe
		 * registered successfully.  Advertise kstat only when that family is
		 * patched, while allowing either direct getattr or the stat-path
		 * fallback to cover pathname stats. */
		ksu_susfs_set_getattr_ready(
			stat_fd_ready &&
			(direct_getattr_ready || stat_path_ready ||
			 nomount_getattr_ready));
		pr_info("branch_link: completed stat fallback ready=%d, statfs ready=%d, "
			"getattr-return ready=%d\n",
			stat_path_ready && stat_fd_ready, statfs_ready,
			nomount_getattr_ready);
	}
	#endif

	ksu_bl_initialized = true;
	mutex_unlock(&ksu_bl_lock);
	return 0;
}

void ksu_branch_link_patch_exit(void)
{
	mutex_lock(&ksu_bl_lock);
	if (!ksu_bl_initialized) {
		mutex_unlock(&ksu_bl_lock);
		return;
	}

#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_susfs_set_open_redirect_ready(false);
	ksu_susfs_set_getattr_ready(false);
	ksu_susfs_set_mount_runtime_ready(false);
#endif
	ksu_bl_restore_records();
	ksu_bl_initialized = false;
	mutex_unlock(&ksu_bl_lock);
}

#endif /* __aarch64__ */
