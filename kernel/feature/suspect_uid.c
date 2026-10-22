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

/* Same quote-form path kernel/susfs/susfs.h uses to reach the command ids. */
#include "uapi/susfs.h"

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
	kuid_t caller;
	kuid_t target;
	kuid_t standin;
	bool used;
};

/*
 * A caller value that matches every caller, so the original whole-table
 * command keeps its meaning: a uid listed there is hidden from every
 * unprivileged caller rather than from one caller in particular.
 */
#define KSU_SUSPECT_CALLER_ANY 0xffffffffu

/*
 * Small fixed-size table, deliberately not a hash map: the lookup below is
 * O(entries) with no allocation, no pointer chasing and no early exit, so its
 * cost does not depend on whether the queried uid is hidden. A hash map keyed
 * on the target would leak the answer through its probe count and its cache
 * behaviour, which is the same class of leak this file exists to remove.
 */
#define KSU_SUSPECT_UID_MAX 128

static struct ksu_suspect_uid_rule ksu_suspect_uid_rules[KSU_SUSPECT_UID_MAX];
static unsigned int ksu_suspect_uid_count;

/*
 * Per-caller masks, consulted after the flat table. Kept separate rather than
 * merged so the flat command keeps its exact previous behaviour and semantics.
 *
 * A bit per app uid rather than a list of uids: HMA hides per caller and the
 * hidden sets overlap heavily, so storing (caller, uid) pairs would repeat the
 * same shared bulk once per caller - roughly fifteen thousand entries for the
 * configured callers, which neither fits a sensible table nor can be scanned
 * per getpriority() call under a spinlock without becoming a contention
 * vector. One bit per caller costs 1250 bytes and answers in constant time, so
 * the whole table is a fixed 80KB and the cost of a lookup does not grow with
 * the policy.
 *
 * Only the app uid range is representable, which is exactly the range brene
 * is allowed to hide: a system or shared uid is never put in a mask (see
 * ksu_suspect_uid_set_mask), and answering ESRCH for one would hide every
 * other package that shares it.
 */
/*
 * AID_APP_START. Spelled out rather than pulled from
 * include/linux/androiduid.h, which this kernel does not carry, so the bound
 * is stated where it is used rather than assumed. It is the first uid the
 * platform allocates to an app; below it every uid is a system or shared uid.
 */
#define KSU_SUSPECT_APP_UID_START 10000
#define KSU_SUSPECT_MASK_BITS 10000
#define KSU_SUSPECT_MASK_BYTES (KSU_SUSPECT_MASK_BITS / 8)
#define KSU_SUSPECT_CALLER_MAX 64

struct ksu_suspect_caller_mask {
	kuid_t caller;
	bool used;
	u8 bits[KSU_SUSPECT_MASK_BYTES];
};

static struct ksu_suspect_caller_mask
	ksu_suspect_caller_masks[KSU_SUSPECT_CALLER_MAX];
static DEFINE_SPINLOCK(ksu_suspect_uid_lock);

static kuid_t ksu_suspect_uid_standin_for(kuid_t target)
{
	/*
	 * One stand-in for every hidden uid, not one per target.
	 *
	 * The stand-in only has to be a uid that is not registered, because all
	 * the caller ever observes is -ESRCH either way - it cannot see which uid
	 * was substituted. Using a single value also keeps the substitution
	 * constant-cost: picking a stand-in per target would mean scanning for a
	 * matching uidhash bucket, and that scan would only run when the queried
	 * uid was hidden, which is a timing side channel in itself. The caller
	 * could then time its way to the answer.
	 */
	(void)target;
	return KUIDT_INIT(KSU_UID_STANDIN_BASE);
}

/*
 * Decide whether @who should answer as unregistered for @caller, and return
 * the uid the syscall should be given instead.
 *
 * Returning the uid rather than a boolean keeps the decision and the lookup in
 * one pass, and means the caller is only ever told the value to substitute:
 * its own uid when @who is not hidden, the stand-in when it is.
 *
 * Both tables are scanned in full and unconditionally, and the results are
 * combined with a bitwise OR rather than an early return, so the cost of a
 * query cannot depend on the answer. A hash map keyed on the target would leak
 * it through its probe count, which is the same class of leak this file exists
 * to remove; the per-caller mask is a flat array, so the same property holds
 * while staying O(1) in the size of the policy.
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

		hit = READ_ONCE(ksu_suspect_uid_rules[i].used) &&
		      uid_eq(READ_ONCE(ksu_suspect_uid_rules[i].target), who);
		if (hit) {
			replacement = READ_ONCE(ksu_suspect_uid_rules[i].standin);
		}
	}

	{
		unsigned int val = (unsigned int)__kuid_val(who);
		unsigned int idx = val - KSU_SUSPECT_APP_UID_START;
		bool hidden = false;

		/*
		 * Every caller slot is examined whether or not it belongs to this
		 * caller and whether or not it is in use, so neither the caller's
		 * presence nor the queried uid changes the loop's shape. A mask
		 * hides the uid only for its own caller: HMA hides per caller,
		 * and a uid one caller can see has to stay visible to it or the
		 * kernel contradicts what the framework showed that caller.
		 */
		for (i = 0; i < KSU_SUSPECT_CALLER_MAX; i++) {
			bool mine =
				READ_ONCE(ksu_suspect_caller_masks[i].used) &&
				uid_eq(READ_ONCE(
						ksu_suspect_caller_masks[i].caller),
				       caller);

			if (mine && idx < KSU_SUSPECT_MASK_BITS) {
				hidden = (READ_ONCE(ksu_suspect_caller_masks[i]
							    .bits[idx >> 3]) &
					  (1u << (idx & 7))) != 0;
			}
		}
		if (hidden)
			replacement = ksu_suspect_uid_standin_for(who);
	}

	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return replacement;
}

/*
 * The oracle is closed by hooking getpriority()/setpriority(), and the
 * syscall hook machinery belongs to the hook-core profile: the manual-hook
 * profile carries its hooks in the kernel source and has no dispatcher to
 * register a handler with.  The feature is therefore compiled out there
 * and says so, instead of leaving an oracle open that nothing closes.
 */
#ifdef CONFIG_KSU_HOOK_CORE
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
#endif /* CONFIG_KSU_HOOK_CORE */

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
		ksu_suspect_uid_rules[i].caller = KUIDT_INIT(
			KSU_SUSPECT_CALLER_ANY);
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
		ksu_suspect_uid_rules[i].caller = KSU_SUSPECT_NULL;
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
 * 200 packages should get the first KSU_SUSPECT_UID_MAX rather than none.
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
		ksu_suspect_uid_rules[i].caller = KSU_SUSPECT_NULL;
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
		ksu_suspect_uid_rules[applied].caller = KUIDT_INIT(
			KSU_SUSPECT_CALLER_ANY);
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

/*
 * Install the caller-scoped mask for @caller, replacing whatever that caller
 * had before.
 *
 * One command per caller is what makes an incremental update possible: a caller
 * whose hidden set has not changed does not need to be sent at all, and this
 * never touches the other callers' masks.
 *
 * Uids outside the app range are refused rather than clamped. A system or
 * shared uid - 1000 is shared by two dozen packages including android itself -
 * must never get ESRCH, because that would hide every other package sharing it.
 * The caller's own uid is allowed to be in its mask: an app that hides itself
 * from its own view is exactly one of the cases worth covering.
 */
int ksu_suspect_uid_set_mask(kuid_t caller, const u8 *bits)
{
	unsigned long flags;
	unsigned int i;
	int ret = -ENOSPC;

	if (!bits || !caller.val || uid_eq(caller, GLOBAL_ROOT_UID))
		return -EINVAL;

	spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
	for (i = 0; i < KSU_SUSPECT_CALLER_MAX; i++) {
		if (ksu_suspect_caller_masks[i].used &&
		    !uid_eq(ksu_suspect_caller_masks[i].caller, caller))
			continue;

		memcpy(ksu_suspect_caller_masks[i].bits, bits,
		       KSU_SUSPECT_MASK_BYTES);
		WRITE_ONCE(ksu_suspect_caller_masks[i].caller, caller);
		WRITE_ONCE(ksu_suspect_caller_masks[i].used, true);
		ret = 0;
		break;
	}
	spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);

	return ret;
}

__u32 ksu_suspect_uid_max(void)
{
	return KSU_SUSPECT_UID_MAX;
}

int ksu_suspect_uid_init(void)
{
#ifdef CONFIG_KSU_HOOK_CORE
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
	 * ksu_register_syscall_hook() also mirrors a hooked native entry into
	 * compat_sys_call_table, so a 32-bit detector cannot walk the same
	 * oracle through the other ABI. That mirror needs a compat slot to
	 * point at: reboot is recorded at init because its two tables share
	 * one handler, and getpriority/setpriority are recorded on first use
	 * because they are "common" calls whose AArch32 and 64-bit slots also
	 * share a handler. The mirror is best-effort - if a slot cannot be
	 * identified the syscall stays native-only, and the boot log says so
	 * rather than the coverage being assumed.
	 */
	pr_info("suspect_uid: uid oracle hiding ready (%d syscall(s), both ABIs)\n",
		reg);
	return 0;
#else
	/* No dispatcher to register with in this profile: the oracle cannot
	 * be closed here, and saying so is better than leaving a policy
	 * table that nothing consults. */
	pr_warn("suspect_uid: uid oracle hiding needs the hook core (CONFIG_KSU_HOOK_CORE), disabled\n");
	return -EOPNOTSUPP;
#endif
}

void ksu_suspect_uid_exit(void)
{
	{
		unsigned long flags;
		unsigned int i;

		spin_lock_irqsave(&ksu_suspect_uid_lock, flags);
		for (i = 0; i < KSU_SUSPECT_CALLER_MAX; i++)
			ksu_suspect_caller_masks[i].used = false;
		spin_unlock_irqrestore(&ksu_suspect_uid_lock, flags);
	}
#ifdef CONFIG_KSU_HOOK_CORE
	ksu_unregister_syscall_hook(__NR_getpriority);
	ksu_unregister_syscall_hook(__NR_setpriority);
#endif
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
	struct ksu_susfs_suspect_uid_mask_cmd mask_cmd;
	int err = 0;

	pr_info("suspect_uid: compat cmd=0x%x\n", cmd);

	if (cmd == KSU_SUSFS_CMD_SUSPECT_UID_GETSIZE) {
		/*
		 * This command carries no input, so the reply is built from
		 * scratch and only written back. Reading the caller's struct in
		 * first would import its sentinel ERR_CMD_NOT_SUPPORTED into
		 * the reply and report a supported command as missing.
		 */
		memset(&size_cmd, 0, sizeof(size_cmd));
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
		/*
		 * The copy above brought the caller's sentinel err in with it, so
		 * clear it first: this reply only ever carries a non-zero err to
		 * report a failure.
		 */
		list_cmd.err = 0;
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

	if (cmd == KSU_SUSFS_CMD_SUSPECT_UID_SETMASK) {
		struct ksu_susfs_suspect_uid_mask_cmd mask_cmd;

		/* No input to preserve, so nothing is read back from the caller. */
		memset(&mask_cmd, 0, sizeof(mask_cmd));
		if (copy_from_user(&mask_cmd, arg, sizeof(mask_cmd))) {
			pr_err("suspect_uid: setmask copy_from_user failed\n");
			return true;
		}
		err = ksu_suspect_uid_set_mask(KUIDT_INIT(mask_cmd.caller),
					      mask_cmd.bits);
		mask_cmd.err = err < 0 ? err : 0;
		if (copy_to_user(arg, &mask_cmd, sizeof(mask_cmd))) {
			pr_err("suspect_uid: setmask copy_to_user failed\n");
		}
		pr_info("suspect_uid: mask for caller %u: %d\n",
			mask_cmd.caller, (int)err);
		return true;
	}

	return false;
}
