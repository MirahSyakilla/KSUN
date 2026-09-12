#include <linux/security.h>
#include <linux/atomic.h>
#include <linux/kernel.h>
#include <linux/ratelimit.h>
#include <linux/mutex.h>
#include <linux/version.h>

#include "policy/feature.h"
#include "uapi/feature.h"
#include "klog.h"
#include "runtime/ksud.h"
#include "infra/seccomp_cache.h"

// sorry for the ifdef hell
// but im too lazy to fragment this out.
// theres only one feature so far anyway
// - xx, 20251019

static u32 ksu_spoof_sid __read_mostly;
static u32 su_spoof_sid __read_mostly;
static u32 priv_app_sid __read_mostly;
static DEFINE_MUTEX(ksu_avc_spoof_lock);

// init as disabled by default
static atomic_t disable_spoof = ATOMIC_INIT(1);

void ksu_avc_spoof_enable();
void ksu_avc_spoof_disable();
static int __ksu_avc_spoof_enable_locked(void);
static void __ksu_avc_spoof_disable_locked(void);

static bool ksu_avc_spoof_enabled __read_mostly = true;
static bool boot_completed __read_mostly;

static int avc_spoof_feature_get(u64 *value)
{
	*value = ksu_avc_spoof_enabled ? 1 : 0;
	return 0;
}

static int avc_spoof_feature_set(u64 value)
{
	bool enable = value != 0;
	int err = 0;

	if (enable == ksu_avc_spoof_enabled) {
		pr_info("avc_spoof: no need to change\n");
		return 0;
	}

	if (boot_completed) {
		if (enable) {
			mutex_lock(&ksu_avc_spoof_lock);
			err = __ksu_avc_spoof_enable_locked();
			mutex_unlock(&ksu_avc_spoof_lock);
		} else {
			mutex_lock(&ksu_avc_spoof_lock);
			__ksu_avc_spoof_disable_locked();
			mutex_unlock(&ksu_avc_spoof_lock);
		}
	}
	if (err) {
		return err;
	}

	ksu_avc_spoof_enabled = enable;

	pr_info("avc_spoof: set to %d\n", enable);

	return 0;
}

static const struct ksu_feature_handler avc_spoof_handler = {
	.feature_id = KSU_FEATURE_AVC_SPOOF,
	.name = "avc_spoof",
	.get_handler = avc_spoof_feature_get,
	.set_handler = avc_spoof_feature_set,
};

static int get_sid()
{
	/* Some trees label KSU root as ksu, while others still audit su. */
	int err = -ENOENT;
	u32 sid;

	ksu_spoof_sid = 0;
	su_spoof_sid = 0;

	err = security_secctx_to_secid("u:r:ksu:s0", strlen("u:r:ksu:s0"),
				       &sid);
	if (!err) {
		ksu_spoof_sid = sid;
		pr_info("avc_spoof/get_sid: source context u:r:ksu:s0, sid: %u\n",
			sid);
	}

	err = security_secctx_to_secid("u:r:su:s0", strlen("u:r:su:s0"),
				       &sid);
	if (!err) {
		su_spoof_sid = sid;
		pr_info("avc_spoof/get_sid: source context u:r:su:s0, sid: %u\n",
			sid);
	}

	if (!ksu_spoof_sid && !su_spoof_sid) {
		pr_info("avc_spoof/get_sid: ksu/su source sid not found\n");
		return -1;
	}

	err = security_secctx_to_secid("u:r:priv_app:s0:c512,c768", strlen("u:r:priv_app:s0:c512,c768"), &priv_app_sid);
	if (err) {
		pr_info("avc_spoof/get_sid: priv_app_sid not found!\n");
		return -1;
	}
	pr_info("avc_spoof/get_sid: priv_app_sid: %u\n", priv_app_sid);
	return 0;
}

/*
 * Spoof the audited target SID if it belongs to a KSU root domain.
 * Returns the (possibly rewritten) tsid; used by the branch-link
 * slow_avc_audit wrapper (hookless) and kept free of probe assumptions.
 */
u32 ksu_avc_spoof_tsid(u32 tsid)
{
	if (atomic_read(&disable_spoof))
		return tsid;

	// If the audited target is a KSU root domain, replace just that SID.
	if (tsid == ksu_spoof_sid || tsid == su_spoof_sid) {
		pr_info_ratelimited("avc_spoof/slow_avc_audit: replacing root sid: %u with priv_app_sid: %u\n",
				    tsid, priv_app_sid);
		tsid = priv_app_sid;
	}

	return tsid;
}
EXPORT_SYMBOL(ksu_avc_spoof_tsid);

/* Gate used by the branch-link family: spoofing is armed when the feature
 * is enabled and sids are resolved. */
bool ksu_avc_spoof_active(void)
{
	return !atomic_read(&disable_spoof) &&
	       (ksu_spoof_sid || su_spoof_sid);
}
EXPORT_SYMBOL(ksu_avc_spoof_active);

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#include <linux/slab.h>
#include "arch.h"
static struct kprobe *slow_avc_audit_kp;
static bool slow_avc_audit_hook_installed;
/*
 * DEAD on this target: CONFIG_AUDIT=n removes slow_avc_audit() from the
 * image entirely (register_kprobe fails with -ENOENT at boot).  The kprobe
 * code is retained only as a config-conditional fallback: a future
 * CONFIG_AUDIT=y build would restore the symbol and this path would work
 * unchanged.  No alternative mechanism is added for AUDIT=y -- avc log
 * spoofing is intentionally unsupported there until a hookless route
 * (e.g. an existing compiled BL site) is implemented for that profile.
 */
static int slow_avc_audit_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * LEGACY kprobe path (CONFIG_KPROBES=y profiles only).  The hookless
	 * branch-link AVC family replaces this on the target configuration.
	 * for < 4.17 int slow_avc_audit(u32 ssid, u32 tsid
	 * for >= 4.17 int slow_avc_audit(struct selinux_state *state, u32 ssid, u32 tsid
	 * for >= 6.4 int slow_avc_audit(u32 ssid, u32 tsid
	 * not to mention theres also DKSU_HAS_SELINUX_STATE
	 * since its hard to make sure this selinux state thing
	 * cross crossing with 4.17 ~ 6.4's where slow_avc_audit
	 * changes abi (tsid in arg2 vs arg3)
	 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	u32 *tsid = (u32 *)&PT_REGS_PARM2(regs);
	*tsid = ksu_avc_spoof_tsid(*tsid);
#else
	u32 *tsid = (u32 *)&PT_REGS_PARM3(regs);
	*tsid = ksu_avc_spoof_tsid(*tsid);
#endif

	return 0;
}

// copied from upstream
static struct kprobe *init_kprobe(const char *name,
				  kprobe_pre_handler_t handler)
{
	struct kprobe *kp = kzalloc(sizeof(struct kprobe), GFP_KERNEL);
	if (!kp)
		return NULL;
	kp->symbol_name = name;
	kp->pre_handler = handler;

	int ret = register_kprobe(kp);
	pr_info("sucompat: register_%s kprobe: %d\n", name, ret);
	if (ret) {
		kfree(kp);
		return NULL;
	}

	return kp;
}
static void destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;
	if (!kp)
		return;
	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}
#endif // CONFIG_KPROBES

static int __ksu_avc_spoof_enable_locked(void)
{
	int ret = get_sid();

	if (ret) {
		pr_info("avc_spoof/init: sid grab fail!\n");
		return ret;
	}

#ifdef CONFIG_KPROBES
	if (!slow_avc_audit_hook_installed) {
		pr_info("avc_spoof/init: register slow_avc_audit kprobe!\n");
		slow_avc_audit_kp = init_kprobe("slow_avc_audit",
						slow_avc_audit_pre_handler);
		if (!slow_avc_audit_kp) {
			pr_info("avc_spoof/init: slow_avc_audit symbol unavailable (CONFIG_AUDIT=n): spoofing disabled\n");
			return 0;
		}
		slow_avc_audit_hook_installed = true;
	}
	atomic_set(&disable_spoof, 0);
	pr_info("avc_spoof/init: slow_avc_audit spoofing enabled!\n");
	return 0;
#else
	/* CONFIG_KPROBES=n: interception is provided by the hookless
	 * branch-link slow_avc_audit family (see hook/arm64/branch_link_hook.c).
	 * That family registers the patch sites and advertises readiness; this
	 * function only arms the SID spoofing state. */
	atomic_set(&disable_spoof, 0);
	pr_info("avc_spoof/init: hookless slow_avc_audit spoofing armed\n");
	return 0;
#endif
}

static void __ksu_avc_spoof_disable_locked(void)
{
	/*
	 * Keep the kprobe installed and only gate the handler off. Tearing the
	 * hook down live is riskier than leaving the dormant probe in place.
	 */
	atomic_set(&disable_spoof, 1);
	pr_info("avc_spoof/exit: slow_avc_audit spoofing disabled!\n");
}

void ksu_avc_spoof_disable(void)
{
	mutex_lock(&ksu_avc_spoof_lock);
	__ksu_avc_spoof_disable_locked();
	mutex_unlock(&ksu_avc_spoof_lock);
}

void ksu_avc_spoof_enable(void)
{
	mutex_lock(&ksu_avc_spoof_lock);
	(void)__ksu_avc_spoof_enable_locked();
	mutex_unlock(&ksu_avc_spoof_lock);
}

void ksu_avc_spoof_late_init(void)
{
	boot_completed = true;
	
    if (ksu_avc_spoof_enabled) {
		ksu_avc_spoof_enable();
	}
}

void __init ksu_avc_spoof_init(void)
{
	if (ksu_register_feature_handler(&avc_spoof_handler)) {
		pr_err("Failed to register avc spoof feature handler\n");
	}
}

void __exit ksu_avc_spoof_exit(void)
{
	mutex_lock(&ksu_avc_spoof_lock);
	if (ksu_avc_spoof_enabled) {
		__ksu_avc_spoof_disable_locked();
	}
#ifdef CONFIG_KPROBES
	if (slow_avc_audit_hook_installed) {
		pr_info("avc_spoof/exit: unregister slow_avc_audit kprobe!\n");
		destroy_kprobe(&slow_avc_audit_kp);
		slow_avc_audit_hook_installed = false;
	}
#endif
	mutex_unlock(&ksu_avc_spoof_lock);
	ksu_unregister_feature_handler(KSU_FEATURE_AVC_SPOOF);
}
