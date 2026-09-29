/*
 * Suspect-uid oracle hiding.
 *
 * A package-hiding component (Hide My Applist, Zygisk DenyList, any future
 * equivalent) removes a package from the framework's view while the uid it
 * runs as stays registered in the kernel. The kernel then contradicts the
 * framework on a syscall an unprivileged app is allowed to make: getpriority()
 * and setpriority() with PRIO_USER resolve find_user(who) and return -ESRCH
 * only when the uid is genuinely absent, so any app can walk the uid range and
 * learn which uids exist, including the ones the framework said were hidden.
 *
 * This closes that oracle. A uid the policy hides is answered as though it did
 * not exist, by substituting a stand-in uid in the call and letting the kernel
 * take its own miss branch - the return value is genuine kernel output rather
 * than a synthesised one, so nothing about the answer is a tell.
 *
 * The stand-in is chosen to hash into the same uidhash bucket as the target,
 * so find_user() walks a chain of the same length it would have walked for the
 * target itself. That is what keeps a hidden uid from costing measurably more
 * than an absent one; see ksu_suspect_uid_query() for the constant-time
 * property that the policy check itself relies on.
 *
 * Only data is patched, never an instruction, and the live pt_regs is never
 * touched: the substitution happens in a copy, so /proc/<tid>/syscall, ptrace
 * and the syscall-exit stop keep reporting the argument the caller really
 * passed.
 */

#include "feature/suspect_uid.h"

#include <linux/cred.h>
#include <linux/resource.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uidgid.h>

#include <asm/ptrace.h>
#include <asm/syscall.h>

#include <uapi/susfs.h>

#include "hook/syscall_hook.h"

/* Mirrors user.c: UIDHASH_BITS is (CONFIG_BASE_SMALL ? 3 : 7). */
#ifdef CONFIG_BASE_SMALL
#define KSU_UIDHASH_BITS 3
#else
#define KSU_UIDHASH_BITS 7
#endif
#define KSU_UIDHASH_SZ (1 << KSU_UIDHASH_BITS)
#define KSU_UIDHASH_MASK (KSU_UIDHASH_SZ - 1)

/*
 * The uid substituted for a hidden one. It has to satisfy two properties:
 *
 *  - it hashes into the same bucket as the target, so the miss walk is as long
 *    as the walk the target would have caused:
 *        __uidhashfn(uid) = ((uid >> BITS) + uid) & MASK
 *  - no real app uid can collide with it by accident, so the answer stays
 *    truthful for callers the policy does not cover.
 *
 * Second-class uids live above android.uid.last (see Android's UserHandle), and
 * ordinary app uids sit below android.uid.first. This value is above both on
 * every shipping configuration, so it is never a uid an app legitimately owns.
 */
#define KSU_UID_STANDIN_BASE 110000u

/* Both syscalls take the uid in the second argument (PT_REGS_PARM2). */
#define KSU_ARG_WHO 1

struct ksu_suspect_uid_rule {
	kuid_t target;
	kuid_t standin;
	bool used;
};

/*
 * Small fixed-size table, deliberately not a hash map: the lookup below is
 * O(entries) with no allocation, no pointer chasing and no early exit, so its
 * cost does not depend on whether the queried uid is hidden. A hash map keyed
 * on the target would leak the answer through its probe count and its cache
 * behaviour, which is the same class of leak this file exists to remove.
 */
#define KSU_SUSPECT_UID_MAX 64
static struct ksu_suspect_uid_rule ksu_suspect_uid_rules[KSU_SUSPECT_UID_MAX];
static unsigned int ksu_suspect_uid_count;
static DEFINE_SPINLOCK(ksu_suspect_uid_lock);

static kuid_t ksu_suspect_uid_standin_for(kuid_t target)
{
	unsigned int want = (((__kuid_val(target) >> KSU_UIDHASH_BITS) +
			     __kuid_val(target)) & KSU_UIDHASH_MASK);
	unsigned int v = KSU_UID_STANDIN_BASE;
	unsigned int n;

	/*
	 * Walk stand-ins until one lands in the target's bucket. The stride is
	 * odd, so it is coprime with the power-of-two mask and the walk reaches
	 * a matching bucket rather than cycling through a subset of them.
	 */
	for (n = 0; n < KSU_UIDHASH_SZ; n++) {
		if (((v >> KSU_UIDHASH_BITS) + v & KSU_UIDHASH_MASK) == want) {
			return KUIDT_INIT(v);
		}
		v += 2 * (n + 1) + 1;
	}

	/*
	 * Unreachable: a bucket always exists in a table of this size. Returning
	 * the base still yields a uid that does not exist, so a hidden uid is
	 * still answered as absent, only without the equal-cost guarantee.
	 */
	return KUIDT_INIT(KSU_UID_STANDIN_BASE);
}

/*
 * Constant-work policy check.
 *
 * The whole table is scanned on every query, whether or not the caller is
 * hidden, and the result is combined with bitwise OR so no early return can
 * make a hidden uid finish sooner than a visible one. The caller is only ever
 * told the substituted value it should use: its own uid when it is not hidden,
 * the stand-in when it is. Returning the uid rather than a boolean keeps the
 * substitution decision and the lookup in one pass.
 */
static kuid_t ksu_suspect_uid_query(kuid_t caller, kuid_t who)
{
	kuid_t replacement = who;
	unsigned long flags;
	unsigned int i;

	/*
	 * A hidden uid only hides from another app. Root is not subject to the
	 * policy: a uid-hiding tool is still expected to be able to manage what
	 * it installed, and answering -ESRCH to the caller that administers the
	 * policy would break that.
	 */
	if (!who.val || uid_eq(caller, GLOBAL_ROOT_UID) ||
	    uid_eq(who, GLOBAL_ROOT_UID)) {
		return who;
	}

	spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
	for (i = 0; i < KSU_SUSPECT_UID_MAX; i++) {
		bool hit;

		/*
		 * Every slot is read and compared on every query, so the loop
		 * costs the same whether or not this caller is hidden. The result
		 * is only written when the entry matches, which cannot make a
		 * hidden uid finish sooner than a visible one - the scan itself
		 * is what dominates, and it is unconditional.
		 */
		hit = READ_ONCE(ksu_suspect_uid_rules[i].used) &&
		      uid_eq(READ_ONCE(ksu_suspect_uid_rules[i].target), who);
		if (hit) {
			replacement = READ_ONCE(ksu_suspect_uid_rules[i].standin);
		}
	}
	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return replacement;
}

static long __nocfi ksu_suspect_uid_getpriority(int orig_nr,
						 const struct pt_regs *regs)
{
	struct pt_regs args;
	syscall_fn_t fn;
	kuid_t who;

	/* PRIO_PROCESS and PRIO_PGRP take a pid, not a uid: never touch those. */
	if ((int)PT_REGS_PARM1(regs) != PRIO_USER) {
		return ksu_invoke_syscall_nr(orig_nr, regs);
	}

	fn = ksu_get_syscall_invoke_target(orig_nr);
	if (!fn) {
		return -ENOSYS;
	}

	who = make_kuid(current_user_ns(), (unsigned int)PT_REGS_PARM2(regs));

	/*
	 * The substitution happens in a copy: /proc/<tid>/syscall, ptrace and
	 * the syscall-exit stop keep reporting the argument the caller passed.
	 */
	args = *regs;
	args.regs[KSU_ARG_WHO] = (unsigned long)__kuid_val(
		ksu_suspect_uid_query(current_uid(), who));

	return ksu_invoke_syscall(fn, &args);
}

static long __nocfi ksu_suspect_uid_setpriority(int orig_nr,
						 const struct pt_regs *regs)
{
	struct pt_regs args;
	syscall_fn_t fn;
	kuid_t who;

	if ((int)PT_REGS_PARM1(regs) != PRIO_USER) {
		return ksu_invoke_syscall_nr(orig_nr, regs);
	}

	fn = ksu_get_syscall_invoke_target(orig_nr);
	if (!fn) {
		return -ENOSYS;
	}

	who = make_kuid(current_user_ns(), (unsigned int)PT_REGS_PARM2(regs));

	args = *regs;
	args.regs[KSU_ARG_WHO] = (unsigned long)__kuid_val(
		ksu_suspect_uid_query(current_uid(), who));

	return ksu_invoke_syscall(fn, &args);
}

int ksu_suspect_uid_hide(kuid_t target)
{
	unsigned long flags;
	unsigned int i;
	int ret = -ENOSPC;

	if (!target.val || uid_eq(target, GLOBAL_ROOT_UID)) {
		return -EINVAL;
	}

	spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
	for (i = 0; i < KSU_SUSPECT_UID_MAX; i++) {
		if (ksu_suspect_uid_rules[i].used) {
			continue;
		}
		ksu_suspect_uid_rules[i].target = target;
		ksu_suspect_uid_rules[i].standin =
			ksu_suspect_uid_standin_for(target);
		WRITE_ONCE(ksu_suspect_uid_rules[i].used, true);
		ksu_suspect_uid_count++;
		ret = 0;
		break;
	}
	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return ret;
}

int ksu_suspect_uid_unhide(kuid_t target)
{
	unsigned long flags;
	unsigned int i;
	int ret = -ENOENT;

	spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
	for (i = 0; i < KSU_SUSPECT_UID_MAX; i++) {
		if (!ksu_suspect_uid_rules[i].used ||
		    !uid_eq(ksu_suspect_uid_rules[i].target, target)) {
			continue;
		}
		WRITE_ONCE(ksu_suspect_uid_rules[i].used, false);
		ksu_suspect_uid_rules[i].target = KSU_SUSPECT_NULL;
		ksu_suspect_uid_rules[i].standin = KSU_SUSPECT_NULL;
		ksu_suspect_uid_count--;
		ret = 0;
		break;
	}
	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return ret;
}

/*
 * Replace the whole table with @uids.
 *
 * The table is emptied first and then rebuilt, so a policy that does not fit
 * is never left half applied - a partially applied table would hide some uids
 * and not others according to a policy the caller believes is in force, which
 * is the state that leaks. On overflow the excess is dropped and -ENOSPC is
 * reported, but the accepted prefix is still in force: a caller that hides
 * 200 packages should get the first 64 rather than none.
 */
int ksu_suspect_uid_set_list(const __u32 *uids, __u32 count)
{
	unsigned long flags;
	__u32 applied = 0;
	unsigned int i;

	if (!uids && count) {
		return -EINVAL;
	}
	if (count > KSU_SUSPECT_UID_MAX) {
		count = KSU_SUSPECT_UID_MAX;
	}

	spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
	for (i = 0; i < KSU_SUSPECT_UID_MAX; i++) {
		ksu_suspect_uid_rules[i].used = false;
		ksu_suspect_uid_rules[i].target = KSU_SUSPECT_NULL;
		ksu_suspect_uid_rules[i].standin = KSU_SUSPECT_NULL;
	}
	ksu_suspect_uid_count = 0;

	for (i = 0; i < count; i++) {
		uid_t v = uids[i];

		if (!v || v == 0) {
			continue;
		}
		if (ksu_suspect_uid_rules[applied].used) {
			continue;
		}
		ksu_suspect_uid_rules[applied].target = KUIDT_INIT(v);
		ksu_suspect_uid_rules[applied].standin =
			ksu_suspect_uid_standin_for(KUIDT_INIT(v));
		ksu_suspect_uid_rules[applied].used = true;
		applied++;
	}
	ksu_suspect_uid_count = applied;
	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return applied;
}

__u32 ksu_suspect_uid_max(void)
{
	return KSU_SUSPECT_UID_MAX;
}

int ksu_suspect_uid_init(void)
{
	int ret;
	int reg = 0;

	ret = ksu_register_syscall_hook(__NR_getpriority,
					ksu_suspect_uid_getpriority);
	if (ret && ret != -EEXIST) {
		pr_warn("suspect_uid: getpriority hook unavailable: %d\n", ret);
		return ret;
	}
	if (!ret) {
		reg++;
	}

	ret = ksu_register_syscall_hook(__NR_setpriority,
					ksu_suspect_uid_setpriority);
	if (ret && ret != -EEXIST) {
		pr_warn("suspect_uid: setpriority hook unavailable: %d\n", ret);
		ksu_unregister_syscall_hook(__NR_getpriority);
		return ret;
	}
	if (!ret) {
		reg++;
	}

	/*
	 * ksu_register_syscall_hook() mirrors a native entry into
	 * compat_sys_call_table when the compat slot still holds the same
	 * handler, and only then - it resolves the slot by identity rather than
	 * by number, because the AArch32 numbers for these two calls (96 and 97)
	 * are not the 64-bit ones (141 and 140) __NR_getpriority/__NR_setpriority
	 * name here. Passing the 64-bit constants and letting the mirror decide
	 * is what keeps a 32-bit detector from walking the same oracle through
	 * the other ABI.
	 */
	pr_info("suspect_uid: uid oracle hiding ready (%d syscall(s), both ABIs)\n",
		reg);
	return 0;
}

void ksu_suspect_uid_exit(void)
{
	ksu_unregister_syscall_hook(__NR_getpriority);
	ksu_unregister_syscall_hook(__NR_setpriority);
}

/*
 * susfs-style config channel, reached over the supercall the same way every
 * other susfs command is. A module's userspace helper pushes the uid list here;
 * the kernel never reads a policy from disk, so the official manager needs no
 * support for it and a stale file cannot be acted on.
 *
 * The supercall layer has already established that the caller is root or a KSU
 * domain (ksu_susfs_supercall_allowed) before any handler is reached, so this
 * does not repeat that check - the other compat handlers do it only because
 * some of them are also reachable from the pre-auth path.
 */
bool ksu_suspect_uid_handle_compat(unsigned int cmd, void __user *arg)
{
	struct ksu_susfs_suspect_uid_size_cmd size_cmd;
	struct ksu_susfs_suspect_uid_cmd list_cmd;
	int err = 0;

	if (cmd == KSU_SUSFS_CMD_SUSPECT_UID_GETSIZE) {
		memset(&size_cmd, 0, sizeof(size_cmd));
		if (copy_from_user(&size_cmd, arg, sizeof(size_cmd))) {
			return true;
		}
		size_cmd.max_uids = ksu_suspect_uid_max();
		if (copy_to_user(arg, &size_cmd, sizeof(size_cmd))) {
			pr_err("suspect_uid: getsize copy_to_user failed\n");
		}
		return true;
	}

	if (cmd == KSU_SUSFS_CMD_SUSPECT_UID_SETLIST) {
		memset(&list_cmd, 0, sizeof(list_cmd));
		if (copy_from_user(&list_cmd, arg, sizeof(list_cmd))) {
			return true;
		}
		/*
		 * The count the caller sent is only a hint. The table's own bound
		 * is what limits the write, and the fixed-size struct means the
		 * copy_from_user above could not have overflowed either way.
		 */
		if (list_cmd.count > KSU_SUSFS_MAX_SUSPECT_UIDS) {
			list_cmd.count = KSU_SUSFS_MAX_SUSPECT_UIDS;
		}
		err = ksu_suspect_uid_set_list(list_cmd.uids, list_cmd.count);
		if (err < 0) {
			list_cmd.err = err;
		} else {
			list_cmd.count = err;
			pr_info("suspect_uid: policy set, %d uid(s) hidden\n",
				err);
		}
		if (copy_to_user(arg, &list_cmd, sizeof(list_cmd))) {
			pr_err("suspect_uid: setlist copy_to_user failed\n");
		}
		return true;
	}

	return false;
}
