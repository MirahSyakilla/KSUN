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
#include <asm/unistd.h>

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#define KSU_BL_CONSERVATIVE_RUNTIME_PATCHES 1
#define KSU_BL_MAX_RECORDS 96
#else
#define KSU_BL_CONSERVATIVE_RUNTIME_PATCHES 0
#define KSU_BL_MAX_RECORDS 160
#endif
#define KSU_AARCH64_BL_OPCODE 0x94000000U
#define KSU_AARCH64_BL_MASK 0xfc000000U
#define KSU_AARCH64_BRANCH_IMM_MASK 0x03ffffffU
#define KSU_BL_SU_PATH "/system/bin/su"
#define KSU_BL_SU_PATH_WORDS 2
#define KSU_BL_SU_PATH_PREFIX ((u16)'/' | ((u16)'s' << 8))
#define KSU_BL_SU_TAIL_MASK 0x00ffffffffffffffULL
#if defined(__NR_faccessat2)
#define KSU_BL_FACCESSAT_PROFILE "arm64-faccessat2"
#elif defined(KSU_HAS_FACCESSAT2)
#define KSU_BL_FACCESSAT_PROFILE "arm64-vendor-flags"
#else
#define KSU_BL_FACCESSAT_PROFILE "arm64-legacy"
#endif
#ifdef CONFIG_COMPAT
#define KSU_BL_READLINK_PROFILE "arm64-compat"
#else
#define KSU_BL_READLINK_PROFILE "arm64-native"
#endif

#if defined(KSU_EXECVE_COMMON_HELPER) || \
	(!defined(KSU_EXECVE_LEGACY_HELPER) && \
	 LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0))
#define KSU_BL_EXEC_COMMON_PROFILE 1
#else
#define KSU_BL_EXEC_COMMON_PROFILE 0
#endif

static const char ksu_bl_su_path_cmp[KSU_BL_SU_PATH_WORDS * sizeof(u64)]
	__aligned(sizeof(u64)) = KSU_BL_SU_PATH;

enum ksu_bl_record_state {
	KSU_BL_RECORD_ACTIVE,
	KSU_BL_RECORD_RESTORED,
	KSU_BL_RECORD_CONFLICT,
};

struct ksu_bl_record {
	const char *name;
	unsigned long site;
	unsigned long original;
	unsigned long hook;
	u32 original_word;
	u32 replacement_word;
	u8 state;
};

enum ksu_bl_manifest_class {
	KSU_BL_SITE_OPTIONAL,
	KSU_BL_SITE_REQUIRED,
	KSU_BL_SITE_UNSUPPORTED,
};

struct ksu_bl_manifest_caller {
	const char *name;
	u8 classification;
	unsigned int min_sites;
};

/*
 * A route target is a candidate helper body. hook is the wrapper installed at
 * the caller's BL site; fn_slot is the shared function pointer the wrapper
 * uses to call the original helper, bound to the target's address only when
 * that target is selected for at least one caller.
 */
struct ksu_bl_manifest_target {
	const char *name;
	unsigned long hook;
	unsigned long *fn_slot;
};

enum ksu_bl_state {
	KSU_BL_IDLE,
	KSU_BL_INSTALLING,
	KSU_BL_ACTIVE,
	KSU_BL_RESTORE_FAILED,
};

static DEFINE_MUTEX(ksu_bl_lock);
static struct ksu_bl_record ksu_bl_records[KSU_BL_MAX_RECORDS];
static int ksu_bl_record_count;
static enum ksu_bl_state ksu_bl_state = KSU_BL_IDLE;
static bool ksu_bl_faccessat_ready;
static bool ksu_bl_readlink_ready;
static bool ksu_bl_stat_path_ready;
static bool ksu_bl_stat_fd_ready;
static bool ksu_bl_statfs_ready;
static bool ksu_bl_open_scope_ready;
static bool ksu_bl_mount_ready;
static bool ksu_bl_exec_ready;

static unsigned long ksu_bl_lookup(const char *name)
{
	unsigned long addr;

	addr = find_kernel_symbol_exact(name);
	if (!addr)
		addr = (unsigned long)ksu_resolve_symbol_for_functable_hook(name);

	pr_info("branch_link: %s=0x%lx\n", name, addr);
	return addr;
}

/*
 * Resolve the canonical address of a helper for INDIRECT calls through our
 * wrapper function-pointer slots.  Under pre-kCFI clang CFI (canonical jump
 * tables), only the .cfi_jt address is a registered valid target for typed
 * indirect calls: a kallsyms real-body address would trip the type check on
 * every wrapper invocation.  Direct BL patches must keep using
 * ksu_bl_lookup(), whose real-body address matches the branch immediates in
 * the caller's text.
 */
static unsigned long ksu_bl_lookup_canonical(const char *name)
{
	unsigned long addr;

	addr = (unsigned long)ksu_resolve_symbol_for_functable_hook(name);

	pr_info("branch_link: canonical %s=0x%lx\n", name, addr);
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
				   unsigned long replacement, u32 *before_out,
				   u32 *after_out)
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
	ret = ksu_patch_text_compare((void *)site, &raw_instruction,
				     &instruction, sizeof(instruction),
				     KSU_PATCH_TEXT_FLUSH_ICACHE);
	if (!ret) {
		if (before_out)
			*before_out = raw_instruction;
		if (after_out)
			*after_out = instruction;
	}
	pr_info("branch_link: patch site 0x%lx 0x%lx -> 0x%lx: %d\n",
		site, expected, replacement, ret);
	return ret;
}

static int ksu_arm64_bl_patch(unsigned long start, size_t width,
			      unsigned long original, unsigned long hook,
			      unsigned long *site_out, u32 *before_out,
			      u32 *after_out)
{
	unsigned long site;
	unsigned long end = start + width;
	unsigned long next_symbol;
	u32 raw_instruction;
	long offset;

	if (!start || !original || !hook)
		return -EINVAL;

	/* Bound the scan at the end of the caller's own function: syscall
	 * wrappers can be packed adjacently, and a fixed 1 KiB window from a
	 * short wrapper would otherwise swallow the next wrapper's call
	 * sites, double-claiming them and starving that later caller. */
	next_symbol = find_kernel_symbol_next_address(start);
	if (next_symbol && next_symbol > start && next_symbol < end)
		end = next_symbol;

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
		return ksu_arm64_bl_replace_at(site, original, hook, before_out,
					      after_out);
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
	u32 before_word;
	u32 replacement_word;
	int ret;

	if (ksu_bl_record_count >= ARRAY_SIZE(ksu_bl_records))
		return -ENOSPC;

	ret = ksu_arm64_bl_patch(start, KSU_BL_SCAN_WIDTH, original, hook,
				 &site, &before_word, &replacement_word);
	if (ret)
		return ret;

	record = &ksu_bl_records[ksu_bl_record_count++];
	record->name = name;
	record->site = site;
	record->original = original;
	record->hook = hook;
	record->original_word = before_word;
	record->replacement_word = replacement_word;
	record->state = KSU_BL_RECORD_ACTIVE;
	return 0;
}

static int ksu_bl_restore_record(struct ksu_bl_record *record)
{
	u32 raw_instruction;
	long offset;
	unsigned long destination;

	if (copy_from_kernel_nofault(&raw_instruction, (void *)record->site,
				     sizeof(raw_instruction)))
		return -EFAULT;
	if (!ksu_aarch64_insn_is_bl(raw_instruction))
		return -EINVAL;
	offset = ksu_aarch64_get_branch_offset(raw_instruction);
	destination = record->site + offset;
	if (raw_instruction == record->original_word) {
		record->state = KSU_BL_RECORD_RESTORED;
		return 0;
	}
	if (raw_instruction != record->replacement_word ||
	    destination != record->hook) {
		record->state = KSU_BL_RECORD_CONFLICT;
		return -EBADE;
	}
	if (ksu_patch_text_compare((void *)record->site,
				      &record->replacement_word,
				      &record->original_word,
				      sizeof(record->original_word),
				      KSU_PATCH_TEXT_FLUSH_ICACHE)) {
		record->state = KSU_BL_RECORD_CONFLICT;
		return -EIO;
	}
	record->state = KSU_BL_RECORD_RESTORED;
	return 0;
}

static int ksu_bl_restore_records_from(int first_record)
{
	int first_error = 0;
	int i;
	int write = 0;

	for (i = ksu_bl_record_count - 1; i >= first_record; i--) {
		struct ksu_bl_record *record = &ksu_bl_records[i];
		int ret = ksu_bl_restore_record(record);

		pr_info("branch_link: restore %s: %d\n", record->name, ret);
		if (ret && !first_error)
			first_error = ret;
	}

	for (i = 0; i < ksu_bl_record_count; i++) {
		if (ksu_bl_records[i].state == KSU_BL_RECORD_ACTIVE ||
		    ksu_bl_records[i].state == KSU_BL_RECORD_CONFLICT) {
			if (write != i)
				ksu_bl_records[write] = ksu_bl_records[i];
			write++;
		}
	}
	ksu_bl_record_count = write;
	return first_error;
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
		int rollback_ret = ksu_bl_restore_records_from(first_record);

		return rollback_ret ? rollback_ret : ret;
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
	int first_record = ksu_bl_record_count;
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
			if (found_callers)
				*found_callers = found;
			if (patched_callers)
				*patched_callers = patched;
			{
				int rollback_ret =
					ksu_bl_restore_records_from(first_record);

				return rollback_ret ? rollback_ret : ret;
			}
		}
	}
	if (found_callers)
		*found_callers = found;
	if (patched_callers)
		*patched_callers = patched;

	return count ? count : -ENOENT;
}

static int ksu_bl_record_patch_manifest(
	const char *name, const struct ksu_bl_manifest_caller *callers,
	size_t caller_count, unsigned long original, unsigned long hook,
	unsigned int *required_found, unsigned int *required_patched)
{
	int first_record = ksu_bl_record_count;
	unsigned int found = 0;
	unsigned int patched = 0;
	unsigned int required_total = 0;
	int count = 0;
	int failure = -ENOENT;
	size_t i;

	for (i = 0; i < caller_count; i++) {
		unsigned long caller;
		int ret;

		if (callers[i].classification == KSU_BL_SITE_UNSUPPORTED) {
			pr_info("branch_link: unsupported %s caller %s\n", name,
				callers[i].name);
			continue;
		}
		if (callers[i].classification == KSU_BL_SITE_REQUIRED)
			required_total++;
		caller = ksu_bl_lookup(callers[i].name);
		if (!caller) {
			if (callers[i].classification == KSU_BL_SITE_REQUIRED) {
				pr_info("branch_link: required %s caller %s unavailable\n",
					name, callers[i].name);
				failure = -ENOENT;
				goto failed;
			}
			pr_info("branch_link: optional %s caller %s unavailable\n",
				name, callers[i].name);
			continue;
		}
		ret = ksu_bl_record_patch_all(name, caller, original, hook);
		if (ret > 0 && (unsigned int)ret >= callers[i].min_sites) {
			count += ret;
			if (callers[i].classification == KSU_BL_SITE_REQUIRED) {
				found++;
				patched++;
			}
			continue;
		}
		if (callers[i].classification == KSU_BL_SITE_REQUIRED) {
			found++;
			failure = ret > 0 ? -ENOSPC : ret;
			pr_info("branch_link: required %s from %s: %d sites\n",
				name, callers[i].name, ret);
			goto failed;
		}
		pr_info("branch_link: optional %s from %s: %d sites\n", name,
			callers[i].name, ret);
	}
	if (found != required_total || patched != required_total) {
		failure = -ENOENT;
		goto failed;
	}

	if (required_found)
		*required_found = found;
	if (required_patched)
		*required_patched = patched;
	return count ? count : -ENOENT;

failed:
	if (required_found)
		*required_found = found;
	if (required_patched)
		*required_patched = patched;
	ksu_bl_restore_records_from(first_record);
	return failure;
}

static int ksu_bl_restore_records(void)
{
	return ksu_bl_restore_records_from(0);
}

/*
 * Manifest variant for routes whose REQUIRED callers may dispatch to one of
 * several helper bodies depending on the compiled image (inlining, LTO
 * outlining, backports). Each caller is satisfied by the FIRST target that
 * resolves AND yields the caller's minimum number of patchable BL sites;
 * selecting a target binds that target's original-function pointer slot so
 * the wrapper can call it. REQUIRED accounting matches
 * ksu_bl_record_patch_manifest(): every REQUIRED caller must resolve and be
 * satisfied or the whole route transaction rolls back; OPTIONAL failures are
 * diagnostic only; UNSUPPORTED names are explicitly logged, never silently
 * skipped.
 */
static int ksu_bl_record_patch_routes(
	const char *name, const struct ksu_bl_manifest_caller *callers,
	size_t caller_count, const struct ksu_bl_manifest_target *targets,
	size_t target_count, unsigned int *required_found,
	unsigned int *required_patched)
{
	int first_record = ksu_bl_record_count;
	unsigned int found = 0;
	unsigned int patched = 0;
	unsigned int required_total = 0;
	int count = 0;
	int failure = -ENOENT;
	size_t i;

	for (i = 0; i < caller_count; i++) {
		const struct ksu_bl_manifest_caller *caller = &callers[i];
		unsigned long caller_addr;
		int last_ret = -ENOENT;
		bool satisfied = false;
		size_t t;

		if (caller->classification == KSU_BL_SITE_UNSUPPORTED) {
			pr_info("branch_link: unsupported %s caller %s\n", name,
				caller->name);
			continue;
		}
		if (caller->classification == KSU_BL_SITE_REQUIRED)
			required_total++;
		caller_addr = ksu_bl_lookup(caller->name);
		if (!caller_addr) {
			if (caller->classification == KSU_BL_SITE_REQUIRED) {
				pr_info("branch_link: required %s caller %s unavailable\n",
					name, caller->name);
				failure = -ENOENT;
				goto failed;
			}
			pr_info("branch_link: optional %s caller %s unavailable\n",
				name, caller->name);
			continue;
		}
		for (t = 0; t < target_count; t++) {
			unsigned long target = ksu_bl_lookup(targets[t].name);
			unsigned long canonical;
			int sites;

			if (!target)
				continue;
			/* Bind the original helper slot before the first text
			 * patch: stop_machine() releases other CPUs before the
			 * patch returns, so publishing afterwards would leave a
			 * NULL-call window for in-flight callers.  The slot is
			 * invoked indirectly, so bind the canonical address
			 * (.cfi_jt under pre-kCFI CFI); `target` stays the
			 * real-body address that matches the BL immediates. */
			canonical = ksu_bl_lookup_canonical(targets[t].name);
			WRITE_ONCE(*targets[t].fn_slot,
				   canonical ? canonical : target);
#if KSU_BL_CONSERVATIVE_RUNTIME_PATCHES
			last_ret = ksu_bl_record_patch(name, caller_addr, target,
						       targets[t].hook);
			sites = last_ret ? 0 : 1;
#else
			sites = ksu_bl_record_patch_all(name, caller_addr,
							target, targets[t].hook);
			last_ret = sites;
#endif
			if (sites > 0 && (unsigned int)sites >= caller->min_sites) {
				count += sites;
				satisfied = true;
				break;
			}
		}
		if (satisfied) {
			if (caller->classification == KSU_BL_SITE_REQUIRED) {
				found++;
				patched++;
			}
			continue;
		}
		if (caller->classification == KSU_BL_SITE_REQUIRED) {
			found++;
			failure = last_ret > 0 ? -ENOSPC :
				  (last_ret < 0 ? last_ret : -ENOENT);
			pr_info("branch_link: required %s caller %s: no route (%d)\n",
				name, caller->name, last_ret);
			goto failed;
		}
		pr_info("branch_link: optional %s caller %s: no route (%d)\n",
			name, caller->name, last_ret);
	}
	if (found != required_total || patched != required_total) {
		failure = -ENOENT;
		goto failed;
	}

	if (required_found)
		*required_found = found;
	if (required_patched)
		*required_patched = patched;
	return count ? count : -ENOENT;

failed:
	if (required_found)
		*required_found = found;
	if (required_patched)
		*required_patched = patched;
	ksu_bl_restore_records_from(first_record);
	return failure;
}

/* A clean per-family rollback drops its own records; only a restore that
 * hit a third-party instruction collision is retained in CONFLICT state.
 * Such a stranded record means the affected text can no longer be trusted,
 * so it is the sole condition that must abort global activation. */
static bool ksu_bl_has_conflict(void)
{
	int i;

	for (i = 0; i < ksu_bl_record_count; i++) {
		if (ksu_bl_records[i].state == KSU_BL_RECORD_CONFLICT)
			return true;
	}
	return false;
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
		old_cred = ksu_handle_faccessat_su_path(&dfd, &filename,
							&mode, &flags);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	{
		/*
		 * READ_ONCE() + NULL-check: a failed family patch rolls the
		 * slot back to NULL after stop_machine() has released the
		 * other CPUs, so a task preempted inside this wrapper before
		 * the rollback resumes and loads the slot afterwards.  The
		 * load is a naturally aligned pointer (single-copy atomic
		 * on arm64); READ_ONCE() keeps the compiler from tearing or
		 * caching it, and the NULL check degrades the race window
		 * to the -EOPNOTSUPP fallback instead of a call through
		 * NULL.
		 */
		long (*fn)(int, const char __user *, int, int) =
			READ_ONCE(do_faccessat_fn);

		if (unlikely(!fn)) {
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
			ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
			return -EOPNOTSUPP;
		}
		ret = fn(dfd, filename, mode, flags);
	}
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
		old_cred = ksu_handle_faccessat_su_path(&dfd, &filename,
							&mode, NULL);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_enter(&lookup_scope, dfd);
#endif
	{
		long (*fn)(int, const char __user *, int) =
			READ_ONCE(do_faccessat_fn);

		if (unlikely(!fn)) {
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
			ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
			return -EOPNOTSUPP;
		}
		ret = fn(dfd, filename, mode);
	}
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_lookup_scope_exit(&lookup_scope);
#endif
	if (old_cred)
		revert_creds(old_cred);
	return ret;
}
#endif

static bool ksu_branch_link_patch_faccessat_family(void)
{
	static const struct ksu_bl_manifest_caller callers[] = {
		/* Native faccessat is present in every supported profile. */
		{ "__arm64_sys_faccessat", KSU_BL_SITE_REQUIRED, 1 },
#ifdef CONFIG_COMPAT
		/* Standard ARM64 compat access(2) uses this generated wrapper. */
		{ "__arm64_sys_access", KSU_BL_SITE_REQUIRED, 1 },
#endif
#ifdef __NR_faccessat2
		/* Require faccessat2 only when this target exposes the syscall. */
		{ "__arm64_sys_faccessat2", KSU_BL_SITE_REQUIRED, 1 },
#endif
#if defined(CONFIG_COMPAT)
		/* Vendor-specific compat wrappers are outside this profile. */
		{ "__arm64_compat_sys_faccessat", KSU_BL_SITE_UNSUPPORTED, 0 },
		{ "__arm64_compat_sys_faccessat2", KSU_BL_SITE_UNSUPPORTED, 0 },
#endif
	};
	unsigned int found = 0;
	unsigned int patched = 0;
	unsigned long target = ksu_bl_lookup("do_faccessat");
	bool ready;
	int count;

	do_faccessat_fn = (void *)ksu_bl_lookup_canonical("do_faccessat");
	count = ksu_bl_record_patch_manifest(
		"faccessat/do_faccessat", callers, ARRAY_SIZE(callers), target,
		(unsigned long)ksu_do_faccessat, &found, &patched);
	pr_info("branch_link: faccessat profile=%s family=%u/%u sites=%d\n",
		KSU_BL_FACCESSAT_PROFILE,
		patched, found, count);
	ready = target && count > 0 && found == patched;
	if (!ready)
		do_faccessat_fn = NULL;
	return ready;
}

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
	static const struct ksu_bl_manifest_caller callers[] = {
		/* Native ARM64 exposes readlinkat, not a separate readlink syscall. */
		{ "__arm64_sys_readlinkat", KSU_BL_SITE_REQUIRED, 1 },
#ifdef CONFIG_COMPAT
		/* Compat readlink uses the generated native-looking wrapper. */
		{ "__arm64_sys_readlink", KSU_BL_SITE_REQUIRED, 1 },
#else
		{ "__arm64_sys_readlink", KSU_BL_SITE_OPTIONAL, 1 },
#endif
#if defined(CONFIG_COMPAT)
		/* Vendor-specific compat wrappers are outside this profile. */
		{ "__arm64_compat_sys_readlinkat", KSU_BL_SITE_UNSUPPORTED, 0 },
		{ "__arm64_compat_sys_readlink", KSU_BL_SITE_UNSUPPORTED, 0 },
#endif
	};
	unsigned long target = ksu_bl_lookup("do_readlinkat");
	unsigned int found = 0;
	unsigned int patched = 0;
	int count;

	WRITE_ONCE(do_readlinkat_fn,
			   (void *)ksu_bl_lookup_canonical("do_readlinkat"));
	count = ksu_bl_record_patch_manifest(
		"readlink/do_readlinkat", callers, ARRAY_SIZE(callers), target,
		(unsigned long)ksu_do_readlinkat, &found, &patched);
	if (count <= 0)
		WRITE_ONCE(do_readlinkat_fn, NULL);
	pr_info("branch_link: readlink profile=%s family=%u/%u sites=%d\n",
		KSU_BL_READLINK_PROFILE,
		patched, found, count);
	return target && count > 0 && found == patched;
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
		old_cred = ksu_handle_stat_su_path(&dfd, &filename, &flags);
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
		old_cred = ksu_handle_stat_su_path(&dfd, &filename, &flags);
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

static int ksu_bl_patch_exec_route(
	const char *name, const struct ksu_bl_manifest_caller *callers,
	size_t caller_count, const char * const *targets, size_t target_count,
	unsigned long hook, unsigned long *selected_target)
{
	int first_record = ksu_bl_record_count;
	int last_error = -ENOENT;
	size_t i;

	for (i = 0; i < target_count; i++) {
		unsigned long target = ksu_bl_lookup(targets[i]);
		unsigned int found = 0;
		unsigned int patched = 0;
		int ret;

		if (!target)
			continue;
		ret = ksu_bl_record_patch_manifest(
			name, callers, caller_count, target, hook, &found, &patched);
		pr_info("branch_link: %s target=%s required=%u/%u sites=%d\n",
			name, targets[i], patched, found, ret);
		if (ret > 0 && found == patched) {
			if (selected_target)
				*selected_target = target;
			return ret;
		}
		last_error = ret;
		if (ksu_bl_record_count > first_record)
			ksu_bl_restore_records_from(first_record);
	}

	if (selected_target)
		*selected_target = 0;
	return last_error;
}

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

/*
 * Dedicated slot for the fd-stat route's vfs_getattr_nosec site.  It must not
 * alias the global vfs_getattr_nosec_fn used by the susfs helper-interior
 * route: this wrapper performs extra NoMount fd-descendant handling, so it
 * binds only when the fd route selects it, while the interior route binds
 * vfs_getattr_nosec_fn.  Sharing one slot would let either family silently
 * rebind the callee of the other's already-live wrapper.
 */
static int (*vfs_getattr_nosec_fd_fn)(const struct path *path,
				      struct kstat *stat, u32 request_mask,
				      unsigned int query_flags);

static int __nocfi ksu_vfs_getattr_nosec_fd(const struct path *path,
					    struct kstat *stat,
					    u32 request_mask,
					    unsigned int query_flags)
{
	int ret = vfs_getattr_nosec_fd_fn(path, stat, request_mask,
					  query_flags);

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
	static const struct ksu_bl_manifest_caller callers[] = {
		/* LP64 newfstatat(79). */
		{ "__arm64_sys_newfstatat", KSU_BL_SITE_REQUIRED, 1 },
#ifdef CONFIG_COMPAT
		/* AArch32 fstatat64(327) binds to the native-named
		 * __arm64_sys_fstatat64; CONFIG_COMPAT=n deletes it. */
		{ "__arm64_sys_fstatat64", KSU_BL_SITE_REQUIRED, 1 },
#endif
#ifdef __NR_statx
		/* statx(291) LP64 and AArch32 statx(397) share
		 * __arm64_sys_statx (struct statx is ABI-identical). */
		{ "__arm64_sys_statx", KSU_BL_SITE_REQUIRED, 1 },
#endif
		/* Compiled on arm64 but bound to no compat table slot;
		 * patching it buys nothing.  Explicit, not silent. */
#ifdef CONFIG_COMPAT
		{ "__arm64_compat_sys_newfstatat", KSU_BL_SITE_UNSUPPORTED, 0 },
#endif
	};
	struct ksu_bl_manifest_target targets[] = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
		{ "vfs_fstatat", (unsigned long)ksu_vfs_fstatat,
		  (unsigned long *)&vfs_fstatat_fn },
#endif
		{ "vfs_statx", (unsigned long)ksu_vfs_statx,
		  (unsigned long *)&vfs_statx_fn },
	};
	unsigned int found = 0;
	unsigned int patched = 0;
	int sites;

	/* AArch32 stat(106)/lstat(107)/stat64(195)/lstat64(196) have no
	 * stat-path BL site on legacy shapes (vfs_stat/vfs_lstat are inline
	 * and vfs_statx collapses into user_path_at_empty + vfs_getattr).
	 * Those routes stay covered by the NoMount/SUSFS vfs_getattr_nosec
	 * return probe, which remains mandatory. */
	sites = ksu_bl_record_patch_routes(
		"stat-path", callers, ARRAY_SIZE(callers), targets,
		ARRAY_SIZE(targets), &found, &patched);
	pr_info("branch_link: stat-path required=%u/%u sites=%d\n", patched,
		found, sites);
	return sites > 0 && found == patched;
}

static bool ksu_branch_link_patch_stat_fd_family(void)
{
#ifdef CONFIG_KSU_KPROBES_SUSFS
	/*
	 * fd-stat metadata is best-effort enrichment.  On legacy non-LTO
	 * images the fstat wrappers inline vfs_fstat()/vfs_statx_fd() and BL
	 * straight to vfs_getattr(); on LTO images vfs_fstat is a private
	 * helper and vfs_getattr may be inlined into vfs_statx_fd().  Which of
	 * {vfs_fstat, vfs_getattr_nosec, vfs_getattr} exists with a patchable
	 * BL therefore varies by build, not by syscall ABI.  Every caller is
	 * OPTIONAL: a covered site adds fd-descendant visible_dev handling, an
	 * uncovered one falls back to the mandatory vfs_getattr_nosec return
	 * probe (SUSFS kretprobe in non-BL mode, or NoMount's probe in BL
	 * mode), so readiness here must never veto kstat advertisement.
	 */
	static const struct ksu_bl_manifest_caller callers[] = {
		/* LP64 fstat(80). */
		{ "__arm64_sys_newfstat", KSU_BL_SITE_OPTIONAL, 1 },
#ifdef CONFIG_COMPAT
		/* AArch32 fstat64(197) binds the native-named wrapper, and
		 * fstat(108) uses a distinct COMPAT_SYSCALL_DEFINE newfstat. */
		{ "__arm64_sys_fstat64", KSU_BL_SITE_OPTIONAL, 1 },
		{ "__arm64_compat_sys_newfstat", KSU_BL_SITE_OPTIONAL, 1 },
#endif
		/* statx(fd, ..., AT_EMPTY_PATH) body; only reachable when the
		 * compiler kept vfs_statx_fd out-of-line. */
		{ "vfs_statx_fd", KSU_BL_SITE_OPTIONAL, 1 },
		/* Old-stat wrappers are not compiled on arm64
		 * (__ARCH_WANT_OLD_STAT unset).  Explicitly unsupported. */
		{ "__arm64_sys_fstat", KSU_BL_SITE_UNSUPPORTED, 0 },
		{ "__arm64_compat_sys_fstat", KSU_BL_SITE_UNSUPPORTED, 0 },
		{ "__arm64_compat_sys_fstat64", KSU_BL_SITE_UNSUPPORTED, 0 },
	};
	struct ksu_bl_manifest_target targets[] = {
		/* Prefer the most specific callee so we do not also claim the
		 * vfs_getattr->vfs_getattr_nosec interior BL used by the susfs
		 * route.  ksu_vfs_fstat is the LTO private-helper shape. */
		{ "vfs_fstat", (unsigned long)ksu_vfs_fstat,
		  (unsigned long *)&vfs_fstat_fn },
		{ "vfs_getattr_nosec", (unsigned long)ksu_vfs_getattr_nosec_fd,
		  (unsigned long *)&vfs_getattr_nosec_fd_fn },
	};
	unsigned int found = 0;
	unsigned int patched = 0;
	int sites;

	sites = ksu_bl_record_patch_routes(
		"stat-fd", callers, ARRAY_SIZE(callers), targets,
		ARRAY_SIZE(targets), &found, &patched);
	pr_info("branch_link: stat-fd required=%u/%u sites=%d\n", patched,
		found, sites);
	return sites > 0 && found == patched;
#else
	return false;
#endif
}

#ifdef CONFIG_KSU_KPROBES_SUSFS
static bool ksu_branch_link_patch_statfs_family(void)
{
	static const struct ksu_bl_manifest_caller user_statfs_callers[] = {
		/* LP64 statfs(43) dispatches to __arm64_sys_statfs, which BLs
		 * user_statfs() directly. */
		{ "__arm64_sys_statfs", KSU_BL_SITE_REQUIRED, 1 },
#ifdef CONFIG_COMPAT
		/* AArch32 statfs(99) has a distinct COMPAT_SYSCALL_DEFINE
		 * wrapper; compat does not alias to the native entry here. */
		{ "__arm64_compat_sys_statfs", KSU_BL_SITE_REQUIRED, 1 },
		/* AArch32 statfs64(266) dispatches to the arch aarch32 wrapper,
		 * whose only out-of-line hop is the global kcompat_sys_statfs64.
		 * On LTO builds that hop may instead be inlined into the live
		 * aarch32 wrapper, so both shapes are offered.  OPTIONAL because
		 * this compat-only enrichment must not veto the mandatory
		 * direct sites, and the NoMount vfs_statfs kretprobe remains
		 * authoritative whenever the family is not READY. */
		{ "kcompat_sys_statfs64", KSU_BL_SITE_OPTIONAL, 1 },
		{ "__arm64_compat_sys_aarch32_statfs64", KSU_BL_SITE_OPTIONAL, 1 },
#endif
		/* LP64 has no statfs64 syscall number: unwired dead wrapper. */
		{ "__arm64_sys_statfs64", KSU_BL_SITE_UNSUPPORTED, 0 },
		/* Unwired on arm64; the live 266 route is covered by the
		 * kcompat/aarch32 optional pair above. */
		{ "__arm64_compat_sys_statfs64", KSU_BL_SITE_UNSUPPORTED, 0 },
	};
	static const struct ksu_bl_manifest_caller fd_statfs_callers[] = {
		/* LP64 fstatfs(44) dispatches to __arm64_sys_fstatfs. */
		{ "__arm64_sys_fstatfs", KSU_BL_SITE_REQUIRED, 1 },
#ifdef CONFIG_COMPAT
		{ "__arm64_compat_sys_fstatfs", KSU_BL_SITE_REQUIRED, 1 },
		{ "kcompat_sys_fstatfs64", KSU_BL_SITE_OPTIONAL, 1 },
		{ "__arm64_compat_sys_aarch32_fstatfs64", KSU_BL_SITE_OPTIONAL, 1 },
#endif
		{ "__arm64_sys_fstatfs64", KSU_BL_SITE_UNSUPPORTED, 0 },
		{ "__arm64_compat_sys_fstatfs64", KSU_BL_SITE_UNSUPPORTED, 0 },
	};
	int first_record = ksu_bl_record_count;
	unsigned int user_found = 0, user_patched = 0;
	unsigned int fd_found = 0, fd_patched = 0;
	unsigned long target = ksu_bl_lookup("vfs_statfs");
	unsigned long user_statfs_target = ksu_bl_lookup("user_statfs");
	unsigned long fd_statfs_target = ksu_bl_lookup("fd_statfs");
	int user_sites;
	int fd_sites;

	vfs_statfs_fn = (void *)ksu_bl_lookup_canonical("vfs_statfs");
	user_sites = ksu_bl_record_patch_manifest(
		"statfs-path/user_statfs", user_statfs_callers,
		ARRAY_SIZE(user_statfs_callers), user_statfs_target,
		(unsigned long)ksu_user_statfs, &user_found, &user_patched);
	fd_sites = ksu_bl_record_patch_manifest(
		"statfs-fd/fd_statfs", fd_statfs_callers,
		ARRAY_SIZE(fd_statfs_callers), fd_statfs_target,
		(unsigned long)ksu_fd_statfs, &fd_found, &fd_patched);

	/* Optional-site outcomes are already logged per caller by the shared
	 * manifest helper; REQUIRED coverage drives the family verdict.  A
	 * failed route has already rolled back itself; if either route's
	 * required set is incomplete, undo the other route too so the family
	 * commits atomically. */
	if (!target || user_sites <= 0 || fd_sites <= 0 ||
	    user_found != user_patched || fd_found != fd_patched)
		ksu_bl_restore_records_from(first_record);
	return target && user_sites > 0 && user_found == user_patched &&
		fd_sites > 0 && fd_found == fd_patched;
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

#if KSU_BL_EXEC_COMMON_PROFILE
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
#if defined(KSU_HAS_OPENAT2)
	static const struct ksu_bl_manifest_caller do_filp_open_callers[] = {
		/* 5.6+ moved the open body into do_sys_openat2
		 * (fddb5d430ad9): do_sys_open tail-calls it and may no longer
		 * hold its own BL to do_filp_open.  The static single-caller
		 * helper can also be fully inlined into do_sys_open, hiding the
		 * do_sys_openat2 symbol while the site remains, so neither
		 * entry may be REQUIRED unconditionally. */
		{ "do_sys_openat2", KSU_BL_SITE_REQUIRED, 1 },
		{ "do_sys_open", KSU_BL_SITE_OPTIONAL, 1 },
	};
#else
	static const struct ksu_bl_manifest_caller do_filp_open_callers[] = {
		/* 4.19/5.4: every open-family syscall funnels through
		 * do_sys_open, whose interior BL to do_filp_open sits well
		 * inside the scan window (objdump-verified at +0x12c on 4.19).
		 * do_sys_openat2 does not exist on these trees; a vendor
		 * backport that adds it without openat2.h is out of profile. */
		{ "do_sys_open", KSU_BL_SITE_REQUIRED, 1 },
		{ "do_sys_openat2", KSU_BL_SITE_UNSUPPORTED, 0 },
	};
#endif
	static const struct ksu_bl_manifest_caller vfs_create_mount_callers[] = {
		{ "fc_mount", KSU_BL_SITE_REQUIRED, 1 },
		/* Upstream 5.4 has a standalone do_new_mount_fc; some vendor
		 * builds inline it into do_new_mount, hiding the symbol while
		 * its vfs_create_mount site remains inside do_new_mount.
		 * Accept either shape. */
		{ "do_new_mount_fc", KSU_BL_SITE_OPTIONAL, 1 },
		{ "do_new_mount", KSU_BL_SITE_OPTIONAL, 1 },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
		{ "__arm64_sys_fsmount", KSU_BL_SITE_REQUIRED, 1 },
		{ "__do_sys_fsmount", KSU_BL_SITE_OPTIONAL, 1 },
		{ "__se_sys_fsmount", KSU_BL_SITE_OPTIONAL, 1 },
#endif
		{ "fuse_dentry_automount", KSU_BL_SITE_OPTIONAL, 1 },
	};
	static const struct ksu_bl_manifest_caller clone_mnt_callers[] = {
		{ "mnt_clone_internal", LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) ?
			KSU_BL_SITE_REQUIRED : KSU_BL_SITE_OPTIONAL, 1 },
		{ "copy_tree", KSU_BL_SITE_REQUIRED, 2 },
		{ "clone_private_mount", KSU_BL_SITE_REQUIRED, 1 },
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
		{ "do_loopback", KSU_BL_SITE_REQUIRED, 1 },
#else
		{ "__do_loopback", KSU_BL_SITE_REQUIRED, 1 },
#endif
	};
	static const struct ksu_bl_manifest_caller cleanup_mnt_callers[] = {
		{ "__cleanup_mnt", KSU_BL_SITE_REQUIRED, 1 },
		{ "delayed_mntput", KSU_BL_SITE_REQUIRED, 1 },
		{ "mntput_no_expire", KSU_BL_SITE_REQUIRED, 1 },
	};
	unsigned long caller_addr;
	unsigned long target_addr;
	int create_count;
	int clone_count;
	int cleanup_count;
	unsigned long create_target;
	unsigned long clone_target;
	unsigned long cleanup_target;
	bool direct_getattr_ready;
	int ret;

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	{
		static const struct ksu_bl_manifest_caller
			open_scope_callers[] = {
				/* LP64 openat(56): the only native LP64
				 * open-family syscall on arm64. */
				{ "__arm64_sys_openat", KSU_BL_SITE_REQUIRED,
				  1 },
#ifdef CONFIG_COMPAT
				/* Distinct COMPAT_SYSCALL_DEFINE wrappers;
				 * compat does not alias native here. */
				{ "__arm64_compat_sys_open",
				  KSU_BL_SITE_REQUIRED, 1 },
				{ "__arm64_compat_sys_openat",
				  KSU_BL_SITE_REQUIRED, 1 },
				/* AArch32 creat(8) dispatches to the
				 * native-named __arm64_sys_creat wrapper;
				 * always AT_FDCWD, but the scope still owns
				 * the AT_FDCWD marker that blocks outer-scope
				 * inheritance for relative names. */
				{ "__arm64_sys_creat", KSU_BL_SITE_REQUIRED,
				  1 },
#endif
				/* __arm64_sys_open is compiled on arm64 but
				 * wired into no table: dead kallsyms symbol.
				 * Patching it would buy nothing and pollute
				 * the required census. */
				{ "__arm64_sys_open", KSU_BL_SITE_UNSUPPORTED,
				  0 },
			};
		struct ksu_bl_manifest_target open_scope_targets[] = {
			{ "do_sys_open", (unsigned long)ksu_do_sys_open,
			  (unsigned long *)&do_sys_open_fn },
		};
		unsigned int open_scope_found = 0;
		unsigned int open_scope_patched = 0;
		int open_scope_count;

		open_scope_count = ksu_bl_record_patch_routes(
			"open-scope/do_sys_open", open_scope_callers,
			ARRAY_SIZE(open_scope_callers), open_scope_targets,
			ARRAY_SIZE(open_scope_targets), &open_scope_found,
			&open_scope_patched);
		if (open_scope_count <= 0)
			WRITE_ONCE(do_sys_open_fn, NULL);
		ksu_bl_open_scope_ready = open_scope_count > 0 &&
			open_scope_found == open_scope_patched;
		pr_info("branch_link: open dfd scope required=%u/%u sites=%d ready=%d\n",
			open_scope_patched, open_scope_found,
			open_scope_count, ksu_bl_open_scope_ready);
	}
#endif

	{
		unsigned long open_redirect_target = ksu_bl_lookup("do_filp_open");
		unsigned int open_redirect_found = 0;
		unsigned int open_redirect_patched = 0;
		int open_count;
		bool open_ready = false;

		if (open_redirect_target) {
			/* Publish the original before the first text patch.
			 * stop_machine() releases other CPUs before the patch
			 * helper returns, so publishing afterwards would leave
			 * a small NULL-call window. */
			WRITE_ONCE(do_filp_open_fn,
				   (void *)open_redirect_target);
			open_count = ksu_bl_record_patch_manifest(
				"susfs/do_filp_open", do_filp_open_callers,
				ARRAY_SIZE(do_filp_open_callers),
				open_redirect_target,
				(unsigned long)ksu_do_filp_open,
				&open_redirect_found,
				&open_redirect_patched);
			open_ready = open_count > 0 &&
				open_redirect_found ==
					open_redirect_patched;
		} else {
			open_count = -ENOENT;
		}
		if (open_count <= 0)
			WRITE_ONCE(do_filp_open_fn, NULL);
		pr_info("branch_link: susfs/do_filp_open required=%u/%u sites=%d\n",
			open_redirect_patched, open_redirect_found,
			open_count);
		ksu_susfs_set_open_redirect_ready(open_ready);
	}

	caller_addr = ksu_bl_lookup("vfs_getattr");
	target_addr = ksu_bl_lookup("vfs_getattr_nosec");
	vfs_getattr_nosec_fn = (void *)ksu_bl_lookup_canonical("vfs_getattr_nosec");
	ret = ksu_bl_record_patch_all("susfs/vfs_getattr_nosec", caller_addr,
				      target_addr,
				      (unsigned long)ksu_vfs_getattr_nosec);
	pr_info("branch_link: susfs/vfs_getattr_nosec: %d\n", ret);
	direct_getattr_ready = ret > 0;

	create_target = ksu_bl_lookup("vfs_create_mount");
	vfs_create_mount_fn = (void *)ksu_bl_lookup_canonical("vfs_create_mount");
	{
		int mount_first_record = ksu_bl_record_count;
		unsigned int create_found = 0;
		unsigned int create_patched = 0;
		unsigned int clone_found = 0;
		unsigned int clone_patched = 0;
		unsigned int cleanup_found = 0;
		unsigned int cleanup_patched = 0;

		create_count = ksu_bl_record_patch_manifest(
		"susfs/vfs_create_mount", vfs_create_mount_callers,
		ARRAY_SIZE(vfs_create_mount_callers), create_target,
		(unsigned long)ksu_vfs_create_mount, &create_found,
		&create_patched);
	pr_info("branch_link: susfs/vfs_create_mount patched: %d\n",
		create_count);

	clone_target = ksu_bl_lookup("clone_mnt");
	clone_mnt_fn = (void *)ksu_bl_lookup_canonical("clone_mnt");
		clone_count = ksu_bl_record_patch_manifest(
		"susfs/clone_mnt", clone_mnt_callers,
		ARRAY_SIZE(clone_mnt_callers), clone_target,
		(unsigned long)ksu_clone_mnt, &clone_found, &clone_patched);
	pr_info("branch_link: susfs/clone_mnt patched: %d\n", clone_count);

	cleanup_target = ksu_bl_lookup("cleanup_mnt");
	cleanup_mnt_fn = (void *)ksu_bl_lookup_canonical("cleanup_mnt");
		cleanup_count = ksu_bl_record_patch_manifest(
		"susfs/cleanup_mnt", cleanup_mnt_callers,
		ARRAY_SIZE(cleanup_mnt_callers), cleanup_target,
		(unsigned long)ksu_cleanup_mnt, &cleanup_found,
		&cleanup_patched);
	pr_info("branch_link: susfs/cleanup_mnt patched: %d\n",
		cleanup_count);

	ksu_bl_mount_ready = create_target && clone_target && cleanup_target &&
			create_count > 0 &&
			create_found == create_patched && clone_count > 0 &&
			clone_found == clone_patched && cleanup_count > 0 &&
			cleanup_found == cleanup_patched;
	if (!ksu_bl_mount_ready)
		ksu_bl_restore_records_from(mount_first_record);
	ksu_susfs_set_mount_runtime_ready(ksu_bl_mount_ready);
	}
	return direct_getattr_ready;
}
#endif

bool ksu_branch_link_faccessat_ready(void)
{
	/* Per-family for the same reason as exec: the faccessat dispatcher must
	 * stop transforming the instant the faccessat branch sites go live, not
	 * only once every other family commits, or both providers would rewrite
	 * the same path during INSTALLING. */
	return READ_ONCE(ksu_bl_faccessat_ready) &&
		READ_ONCE(ksu_bl_state) != KSU_BL_RESTORE_FAILED;
}

bool ksu_branch_link_readlink_ready(void)
{
	return READ_ONCE(ksu_bl_state) == KSU_BL_ACTIVE &&
		READ_ONCE(ksu_bl_readlink_ready);
}

bool ksu_branch_link_stat_path_ready(void)
{
	/* Per-family for the same reason as faccessat/exec: the newfstatat
	 * dispatcher su-redirect must stop once the stat-path branch sites go
	 * live, and must stay authoritative whenever they are not READY. */
	return READ_ONCE(ksu_bl_stat_path_ready) &&
		READ_ONCE(ksu_bl_state) != KSU_BL_RESTORE_FAILED;
}

bool ksu_branch_link_exec_ready(void)
{
	/* Publish per-family, not on global ACTIVE: the exec branch sites go
	 * live the moment their transaction commits, and the execve dispatcher
	 * must stop transforming from that exact point. Gating on ACTIVE would
	 * both leave a coverage gap on late-family failure and open a double
	 * interception window while other families are still installing.
	 * RESTORE_FAILED is excluded because a conflicted site may still be
	 * live while the dispatcher is needed. */
	return READ_ONCE(ksu_bl_exec_ready) &&
		READ_ONCE(ksu_bl_state) != KSU_BL_RESTORE_FAILED;
}

int ksu_branch_link_patch_init(void)
{
	bool stat_path_ready;
	bool stat_fd_ready;
	bool nomount_getattr_ready = false;
	bool exec_ready = false;
	int ret;

	mutex_lock(&ksu_bl_lock);
	if (ksu_bl_state == KSU_BL_ACTIVE) {
		mutex_unlock(&ksu_bl_lock);
		return 0;
	}
	if (ksu_bl_state == KSU_BL_RESTORE_FAILED || ksu_bl_record_count) {
		mutex_unlock(&ksu_bl_lock);
		return -EBUSY;
	}
	ksu_bl_state = KSU_BL_INSTALLING;
	ksu_bl_faccessat_ready = false;
	ksu_bl_readlink_ready = false;
	ksu_bl_stat_path_ready = false;
	ksu_bl_stat_fd_ready = false;
	ksu_bl_statfs_ready = false;
	ksu_bl_mount_ready = false;
	ksu_bl_exec_ready = false;

	ksu_bl_faccessat_ready =
		ksu_branch_link_patch_faccessat_family();

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_bl_readlink_ready = ksu_branch_link_patch_readlink_family();
#endif

	stat_path_ready = ksu_branch_link_patch_stat_path_family();
	stat_fd_ready = ksu_branch_link_patch_stat_fd_family();
	ksu_bl_stat_path_ready = stat_path_ready;
	ksu_bl_stat_fd_ready = stat_fd_ready;

	{
		int exec_first_record = ksu_bl_record_count;

#if KSU_BL_EXEC_COMMON_PROFILE
	{
		static const struct ksu_bl_manifest_caller exec_callers[] = {
			{ "__arm64_sys_execve", KSU_BL_SITE_REQUIRED, 1 },
#ifdef __NR_execveat
			{ "__arm64_sys_execveat", KSU_BL_SITE_REQUIRED, 1 },
#endif
#ifdef CONFIG_COMPAT
			{ "__arm64_compat_sys_execve", KSU_BL_SITE_REQUIRED, 1 },
#ifdef KSU_HAS_COMPAT_EXECVEAT
			{ "__arm64_compat_sys_execveat", KSU_BL_SITE_REQUIRED, 1 },
#else
			{ "__arm64_compat_sys_execveat", KSU_BL_SITE_UNSUPPORTED, 0 },
#endif
#endif
		};
		static const char * const exec_targets[] = {
			"do_execveat_common",
		};

		do_execveat_common_fn = (void *)ksu_bl_lookup_canonical("do_execveat_common");
		ret = ksu_bl_patch_exec_route(
			"execve/do_execveat_common", exec_callers,
			ARRAY_SIZE(exec_callers), exec_targets,
			ARRAY_SIZE(exec_targets),
			(unsigned long)ksu_do_execveat_common, NULL);
		exec_ready = ret > 0;
	}
#else
	static const struct ksu_bl_manifest_caller execve_callers[] = {
		{ "__arm64_sys_execve", KSU_BL_SITE_REQUIRED, 1 },
	};
	static const char * const execve_file_targets[] = {
		"__do_execve_file",
	};
	static const char * const execve_targets[] = {
		"do_execve",
	};
	static const struct ksu_bl_manifest_caller execveat_callers[] = {
#ifdef __NR_execveat
		{ "__arm64_sys_execveat", KSU_BL_SITE_REQUIRED, 1 },
#endif
	};
	static const char * const execveat_file_targets[] = {
		"__do_execve_file",
	};
	static const char * const execveat_targets[] = {
		"do_execveat",
	};
	bool execve_ready;
	bool execveat_ready;

	/* Resolve every helper once from its own symbol. The wrappers below call
	 * these pointers without a NULL check, but a route can only install a
	 * live branch to a wrapper if that helper symbol resolved (the route
	 * skips unresolved targets), so a patched site always has a valid
	 * pointer here. Assigning from the route result instead would NULL the
	 * shared __do_execve_file_fn after a later caller's miss. */
	__do_execve_file_fn = (void *)ksu_bl_lookup_canonical("__do_execve_file");
	do_execve_fn = (void *)ksu_bl_lookup_canonical("do_execve");
	do_execveat_fn = (void *)ksu_bl_lookup_canonical("do_execveat");
#ifdef CONFIG_COMPAT
	compat_do_execve_fn = (void *)ksu_bl_lookup_canonical("compat_do_execve");
	compat_do_execveat_fn = (void *)ksu_bl_lookup_canonical("compat_do_execveat");
#endif

	ret = ksu_bl_patch_exec_route(
		"execve", execve_callers, ARRAY_SIZE(execve_callers),
		execve_file_targets, ARRAY_SIZE(execve_file_targets),
		(unsigned long)ksu_do_execve_file, NULL);
	pr_info("branch_link: execve/__do_execve_file sites=%d\n", ret);
	execve_ready = ret > 0;
	if (!execve_ready) {
		ret = ksu_bl_patch_exec_route(
			"execve/do_execve", execve_callers,
			ARRAY_SIZE(execve_callers),
			execve_targets, ARRAY_SIZE(execve_targets),
			(unsigned long)ksu_do_execve, NULL);
		pr_info("branch_link: execve/do_execve sites=%d\n", ret);
		execve_ready = ret > 0;
	}

#ifdef __NR_execveat
	ret = ksu_bl_patch_exec_route(
		"execveat", execveat_callers, ARRAY_SIZE(execveat_callers),
		execveat_file_targets, ARRAY_SIZE(execveat_file_targets),
		(unsigned long)ksu_do_execve_file, NULL);
	pr_info("branch_link: execveat/__do_execve_file sites=%d\n", ret);
	execveat_ready = ret > 0;
	if (!execveat_ready) {
		ret = ksu_bl_patch_exec_route(
			"execveat/do_execveat", execveat_callers,
			ARRAY_SIZE(execveat_callers),
			execveat_targets, ARRAY_SIZE(execveat_targets),
			(unsigned long)ksu_do_execveat, NULL);
		pr_info("branch_link: execveat/do_execveat sites=%d\n", ret);
		execveat_ready = ret > 0;
	}
#else
	execveat_ready = true;
#endif

#ifdef CONFIG_COMPAT
	static const struct ksu_bl_manifest_caller compat_execve_callers[] = {
		{ "__arm64_compat_sys_execve", KSU_BL_SITE_REQUIRED, 1 },
	};
	static const char * const compat_execve_file_targets[] = {
		"__do_execve_file",
	};
	static const char * const compat_execve_targets[] = {
		"compat_do_execve",
	};
	static const struct ksu_bl_manifest_caller compat_execveat_callers[] = {
#ifdef KSU_HAS_COMPAT_EXECVEAT
		{ "__arm64_compat_sys_execveat", KSU_BL_SITE_REQUIRED, 1 },
#endif
	};
	static const char * const compat_execveat_file_targets[] = {
		"__do_execve_file",
	};
	static const char * const compat_execveat_targets[] = {
		"compat_do_execveat",
	};
	bool compat_execve_ready;
	bool compat_execveat_ready;

	ret = ksu_bl_patch_exec_route(
		"compat_execve", compat_execve_callers,
		ARRAY_SIZE(compat_execve_callers), compat_execve_file_targets,
		ARRAY_SIZE(compat_execve_file_targets),
		(unsigned long)ksu_do_execve_file, NULL);
	pr_info("branch_link: compat_execve/__do_execve_file sites=%d\n", ret);
	compat_execve_ready = ret > 0;
	if (!compat_execve_ready) {
		ret = ksu_bl_patch_exec_route(
			"compat_execve/compat_do_execve", compat_execve_callers,
			ARRAY_SIZE(compat_execve_callers),
			compat_execve_targets, ARRAY_SIZE(compat_execve_targets),
			(unsigned long)ksu_compat_do_execve, NULL);
		pr_info("branch_link: compat_execve/compat_do_execve sites=%d\n",
			ret);
		compat_execve_ready = ret > 0;
	}

#ifdef KSU_HAS_COMPAT_EXECVEAT
	ret = ksu_bl_patch_exec_route(
		"compat_execveat", compat_execveat_callers,
		ARRAY_SIZE(compat_execveat_callers), compat_execveat_file_targets,
		ARRAY_SIZE(compat_execveat_file_targets),
		(unsigned long)ksu_do_execve_file, NULL);
	pr_info("branch_link: compat_execveat/__do_execve_file sites=%d\n", ret);
	compat_execveat_ready = ret > 0;
	if (!compat_execveat_ready) {
		ret = ksu_bl_patch_exec_route(
			"compat_execveat/compat_do_execveat",
			compat_execveat_callers,
			ARRAY_SIZE(compat_execveat_callers),
			compat_execveat_targets, ARRAY_SIZE(compat_execveat_targets),
			(unsigned long)ksu_compat_do_execveat, NULL);
		pr_info("branch_link: compat_execveat/compat_do_execveat sites=%d\n",
			ret);
		compat_execveat_ready = ret > 0;
	}
#else
	compat_execveat_ready = true;
#endif

	exec_ready = execve_ready && execveat_ready &&
		compat_execve_ready && compat_execveat_ready;
#else
		exec_ready = execve_ready && execveat_ready;
#endif
	#endif
	if (!exec_ready)
		ksu_bl_restore_records_from(exec_first_record);
	/* Publish exec readiness at this family's commit point, before later
	 * families install, so the execve dispatcher stops transforming exactly
	 * when the exec branch sites go live. */
	ksu_bl_exec_ready = exec_ready;
	}

	#ifdef CONFIG_KSU_KPROBES_SUSFS
	{
		bool direct_getattr_ready = ksu_branch_link_patch_susfs();
		bool statfs_ready = ksu_branch_link_patch_statfs_family();
		ksu_bl_statfs_ready = statfs_ready;

	#ifdef CONFIG_KSU_KPROBES_NOMOUNT
		nomount_getattr_ready = ksu_nomount_getattr_runtime_ready();
	#endif
		/* kstat metadata spoofing is only honest to advertise when the
		 * universal getattr funnel (every caller of vfs_getattr /
		 * vfs_getattr_nosec, internal included) actually has a live
		 * provider: either the helper-interior vfs_getattr->
		 * vfs_getattr_nosec branch site, or the NoMount vfs_getattr_nosec
		 * return probe that re-runs the full SUSFS layer in branch-link
		 * mode.  The stat-path and stat-fd branch sites are enrichments
		 * (dfd scope, sucompat, fd-descendant visible_dev) and alone must
		 * NOT advertise kstat: they leave internal callers spoofless.  On
		 * legacy non-LTO shapes the fd helper is inlined away, so the old
		 * formula's hard stat_fd_ready requirement permanently hid the
		 * feature even when the funnel was fully live. */
		ksu_susfs_set_getattr_ready(direct_getattr_ready ||
					    nomount_getattr_ready);
		pr_info("branch_link: completed stat-path=%d stat-fd=%d "
			"getattr-interior=%d getattr-return=%d statfs=%d\n",
			stat_path_ready, stat_fd_ready, direct_getattr_ready,
			nomount_getattr_ready, statfs_ready);
	}
	#endif
	if (ksu_bl_has_conflict())
		goto install_failed;

	ksu_bl_exec_ready = exec_ready;
	if (ksu_bl_mount_ready) {
		ksu_susfs_disable_mount_probe_fallback();
	}
	if (ksu_susfs_mntns_get_runtime_ready())
		ksu_susfs_disable_mntns_probe_fallback();
	pr_info("branch_link: readiness faccess=%d readlink=%d stat-path=%d "
		"stat-fd=%d statfs=%d exec=%d mount=%d records=%d\n",
		ksu_bl_faccessat_ready, ksu_bl_readlink_ready,
		ksu_bl_stat_path_ready, ksu_bl_stat_fd_ready,
		ksu_bl_statfs_ready, ksu_bl_exec_ready, ksu_bl_mount_ready,
		ksu_bl_record_count);
	ksu_bl_state = KSU_BL_ACTIVE;
	mutex_unlock(&ksu_bl_lock);
	return 0;

install_failed:
	ksu_bl_faccessat_ready = false;
	ksu_bl_readlink_ready = false;
	ksu_bl_stat_path_ready = false;
	ksu_bl_stat_fd_ready = false;
	ksu_bl_statfs_ready = false;
	ksu_bl_mount_ready = false;
	ksu_bl_exec_ready = false;
#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_susfs_set_open_redirect_ready(false);
	ksu_susfs_set_getattr_ready(false);
	ksu_susfs_set_mount_runtime_ready(false);
#endif
	ret = ksu_bl_restore_records();
	ksu_bl_state = ret || ksu_bl_record_count ?
		KSU_BL_RESTORE_FAILED : KSU_BL_IDLE;
	mutex_unlock(&ksu_bl_lock);
	return ret ? ret : -EIO;
}

/*
 * Module unload is irrelevant here: this kernel is built with
 * CONFIG_KSU=y, so the code is linked into vmlinux and the module exit
 * path never runs; ksu_branch_link_patch_exit() is only reachable from
 * the __exit ksu_syscall_hook_manager_exit(), which the linker discards
 * for built-in code.  ksu_bl_restore_records() therefore only ever runs
 * under ksu_bl_lock during install rollback or that exit call, never in
 * response to an unload racing live wrappers or fn slots.
 */
int ksu_branch_link_patch_exit(void)
{
	int ret;

	mutex_lock(&ksu_bl_lock);
	if (ksu_bl_state == KSU_BL_IDLE) {
		mutex_unlock(&ksu_bl_lock);
		return 0;
	}
	ksu_bl_faccessat_ready = false;
	ksu_bl_readlink_ready = false;
	ksu_bl_stat_path_ready = false;
	ksu_bl_stat_fd_ready = false;
	ksu_bl_statfs_ready = false;
	ksu_bl_mount_ready = false;
	ksu_bl_exec_ready = false;

#ifdef CONFIG_KSU_KPROBES_SUSFS
	ksu_susfs_set_open_redirect_ready(false);
	ksu_susfs_set_getattr_ready(false);
	ksu_susfs_set_mount_runtime_ready(false);
#endif
	ret = ksu_bl_restore_records();
	if (ret || ksu_bl_record_count) {
		ksu_bl_state = KSU_BL_RESTORE_FAILED;
	} else {
		ksu_bl_state = KSU_BL_IDLE;
	}
	mutex_unlock(&ksu_bl_lock);
	return ret;
}

#endif /* __aarch64__ */
