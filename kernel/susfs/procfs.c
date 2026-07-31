#include <linux/cred.h>
#include <linux/version.h>
#include <linux/fdtable.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
#include <linux/filelock.h>
#endif
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/jhash.h>
#include <linux/jiffies.h>
#include <linux/jump_label.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/mnt_namespace.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif
#include <linux/proc_fs.h>
#include <linux/proc_ns.h>
#include <linux/ptrace.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/workqueue.h>

#include <asm/unistd.h>

#include "pnode.h"
#include "proc/internal.h"
#include "proc/fd.h"

#include "arch.h"
#include "compat/kernel_compat.h"
#include "hook/patch_memory.h"
#include "hook/syscall_hook.h"
#include "infra/su_mount_ns.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "selinux/selinux.h"
#include "susfs/compat.h"
#include "susfs/procfs.h"
#include "susfs/susfs.h"

#define KSU_SUSFS_MOUNT_HASH_BITS 8
#define KSU_SUSFS_CMDLINE_RETRY_DELAY_MS 1000
#define KSU_SUSFS_MOUNT_WINDOW_RETRY_DELAY_MS 1000
#define KSU_SUSFS_PROP_HYGIENE_INITIAL_DELAY_MS 1000
#define KSU_SUSFS_PROP_HYGIENE_RETRY_DELAY_MS 5000
#define KSU_SUSFS_PROP_HYGIENE_MAX_ATTEMPTS 6
#define KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS 25
#define KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS 16
#define KSU_SUSFS_ISOLATED_NS_MAX_CMDLINE 256
#define KSU_SUSFS_ISOLATED_NS_MAX_CANDIDATES 64
#define KSU_SUSFS_CMDLINE_USE_PROC_SHOW_HOOK \
	(LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

struct ksu_susfs_hidden_mount {
	struct hlist_node node;
	struct mount *mnt;
};

struct ksu_susfs_pkg_anchor {
	struct hlist_node node;
	struct task_struct *task;
	uid_t user_id;
	char pkg[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_vfs_create_mount_ctx {
	bool hide;
};

struct ksu_susfs_clone_mnt_ctx {
	struct mount *old;
	bool hide;
};

struct ksu_susfs_isolated_ns_ctx {
	struct delayed_work work;
	struct callback_head cb;
	struct task_struct *task;
	unsigned int attempts;
};

static DEFINE_HASHTABLE(ksu_susfs_hidden_mounts, KSU_SUSFS_MOUNT_HASH_BITS);
static DEFINE_SPINLOCK(ksu_susfs_hidden_mounts_lock);
static DEFINE_HASHTABLE(ksu_susfs_pkg_anchors, KSU_SUSFS_MOUNT_HASH_BITS);
static DEFINE_MUTEX(ksu_susfs_pkg_anchors_lock);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_mount_hide_enabled);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_cmdline_spoof_enabled);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_uname_spoof_enabled);
static DEFINE_SEQLOCK(ksu_susfs_uname_lock);

static char ksu_susfs_fake_cmdline[KSU_SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
static struct ksu_susfs_uname_cmd ksu_susfs_fake_uname;
static char *ksu_susfs_orig_saved_command_line;
static char *ksu_susfs_cmdline_shadow;
static const char *ksu_susfs_cmdline_active;

static int (*ksu_susfs_orig_mounts_open)(struct inode *inode, struct file *file);
static int (*ksu_susfs_orig_mountinfo_open)(struct inode *inode,
					    struct file *file);
static int (*ksu_susfs_orig_mountstats_open)(struct inode *inode,
					     struct file *file);
static int (*ksu_susfs_orig_fdinfo_open)(struct inode *inode, struct file *file);
static int (*ksu_susfs_orig_show_mounts)(struct seq_file *m,
					 struct vfsmount *mnt);
static int (*ksu_susfs_orig_show_mountinfo)(struct seq_file *m,
					    struct vfsmount *mnt);
static int (*ksu_susfs_orig_show_mountstats)(struct seq_file *m,
					     struct vfsmount *mnt);

static const struct file_operations *ksu_susfs_fdinfo_fops;
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static struct ns_common *(*ksu_susfs_orig_mntns_get)(struct task_struct *task);
#endif
static struct kretprobe *ksu_susfs_vfs_create_mount_rp;
static struct kretprobe *ksu_susfs_clone_mnt_rp;
static struct kretprobe *ksu_susfs_mntns_get_rp;
static struct kprobe *ksu_susfs_cleanup_mnt_kp;
static DEFINE_MUTEX(ksu_susfs_cmdline_patch_lock);
static bool ksu_susfs_cmdline_ready;
#if KSU_SUSFS_CMDLINE_USE_PROC_SHOW_HOOK
static bool ksu_susfs_cmdline_show_hook_ready;
static struct proc_dir_entry *ksu_susfs_cmdline_pde;
static int (*ksu_susfs_orig_cmdline_show)(struct seq_file *m, void *v);
#endif
static bool ksu_susfs_mount_runtime_ready;
static bool ksu_susfs_uname_hook_ready;
static bool ksu_susfs_mount_window_open;
static int ksu_susfs_cmdline_last_err;
static unsigned int ksu_susfs_prop_hygiene_attempts;

static void ksu_susfs_cmdline_retry_fn(struct work_struct *work);
static void ksu_susfs_mount_window_retry_fn(struct work_struct *work);
static void ksu_susfs_prop_hygiene_restore_fn(struct work_struct *work);
static bool ksu_susfs_pkg_ns_allowed_uid(uid_t uid);
static DECLARE_DELAYED_WORK(ksu_susfs_cmdline_retry_work,
			    ksu_susfs_cmdline_retry_fn);
static DECLARE_DELAYED_WORK(ksu_susfs_mount_window_retry_work,
			    ksu_susfs_mount_window_retry_fn);
static DECLARE_DELAYED_WORK(ksu_susfs_prop_hygiene_restore_work,
			    ksu_susfs_prop_hygiene_restore_fn);

static char ksu_susfs_prop_hygiene_restore_script[] =
	"RP=/data/adb/ksu/bin/resetprop; "
	"BASE=/metadata/watchdog/ksu/prop_hygiene_baseline; "
	"[ -f \"$BASE\" ] || BASE=/metadata/ksu/prop_hygiene_baseline; "
	"[ -x \"$RP\" ] && [ -f \"$BASE\" ] || exit 1; "
	"CN=`sed -n '1p' \"$BASE\"`; "
	"AB=`sed -n '2p' \"$BASE\"`; "
	"\"$RP\" -d ro.modversion >/dev/null 2>&1; "
	"if [ -n \"$CN\" ]; then "
	"\"$RP\" -n ro.build.version.known_codenames \"$CN\" >/dev/null 2>&1; "
	"else "
	"\"$RP\" -d ro.build.version.known_codenames >/dev/null 2>&1; "
	"fi; "
	"if [ -n \"$AB\" ]; then "
	"\"$RP\" -n ro.product.ab_ota_partitions \"$AB\" >/dev/null 2>&1; "
	"else "
	"\"$RP\" -d ro.product.ab_ota_partitions >/dev/null 2>&1; "
	"fi; "
	"\"$RP\" -c --force >/dev/null 2>&1; "
	"RV=`/system/bin/getprop ro.modversion`; "
	"[ -z \"$RV\" ]";

static int ksu_susfs_run_prop_hygiene_restore(void)
{
	static char *argv[] = {
		(char *)"/system/bin/sh",
		(char *)"-c",
		ksu_susfs_prop_hygiene_restore_script,
		NULL,
	};
	static char *envp[] = {
		(char *)"HOME=/",
		(char *)"PATH=/system/bin:/system/xbin:/vendor/bin:/vendor/xbin:/product/bin",
		NULL,
	};

	return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

static void ksu_susfs_prop_hygiene_restore_fn(struct work_struct *work)
{
	int err = ksu_susfs_run_prop_hygiene_restore();

	if (err) {
		if (ksu_susfs_prop_hygiene_attempts <
		    KSU_SUSFS_PROP_HYGIENE_MAX_ATTEMPTS) {
			ksu_susfs_prop_hygiene_attempts++;
			mod_delayed_work(
				system_wq, &ksu_susfs_prop_hygiene_restore_work,
				msecs_to_jiffies(
					KSU_SUSFS_PROP_HYGIENE_RETRY_DELAY_MS));
			pr_warn("susfs: prop hygiene restore retry %u/%u (err=%d)\n",
				ksu_susfs_prop_hygiene_attempts,
				KSU_SUSFS_PROP_HYGIENE_MAX_ATTEMPTS, err);
			return;
		}

		pr_warn("susfs: prop hygiene restore failed after %u attempts: %d\n",
			ksu_susfs_prop_hygiene_attempts + 1, err);
		return;
	}

	pr_info("susfs: prop hygiene restore complete\n");
}

static int ksu_susfs_get_cmdline0(struct task_struct *task, char *buf,
				       size_t buf_size)
{
	int len;
	size_t nul;

	if (!task || !buf || buf_size < 2) {
		return -EINVAL;
	}

	len = get_cmdline(task, buf, buf_size - 1);
	if (len <= 0) {
		return -ENOENT;
	}

	buf[len] = '\0';
	nul = strnlen(buf, len);
	if (!nul) {
		return -ENOENT;
	}

	return (int)nul;
}

static int ksu_susfs_match_pkg_cmdline(const char *cmdline0, const char *pkg)
{
	size_t len;

	if (!cmdline0 || !pkg) {
		return 0;
	}

	len = strlen(pkg);
	if (!len) {
		return 0;
	}

	if (!strcmp(cmdline0, pkg)) {
		return 3;
	}
	if (!strncmp(cmdline0, pkg, len) && cmdline0[len] == ':') {
		return 2;
	}

	return 0;
}

static int ksu_susfs_parse_package_name(const char *cmdline0, char *pkg,
					 size_t pkg_size)
{
	const char *sep;
	size_t len;

	if (!cmdline0 || !*cmdline0 || !pkg || pkg_size < 2) {
		return -EINVAL;
	}

	sep = strchr(cmdline0, ':');
	if (!sep) {
		sep = cmdline0 + strlen(cmdline0);
	}

	len = sep - cmdline0;
	if (!len || len >= pkg_size || !memchr(cmdline0, '.', len)) {
		return -ENOENT;
	}

	memcpy(pkg, cmdline0, len);
	pkg[len] = '\0';
	return 0;
}

static bool ksu_susfs_pkg_data_path_exists(uid_t uid, const char *pkg)
{
	char path[KSU_SUSFS_MAX_PATHNAME];
	struct path real_path;
	const struct cred *saved;
	int user_id;
	int err;

	if (!pkg || !*pkg) {
		return false;
	}

	user_id = uid / PER_USER_RANGE;
	err = scnprintf(path, sizeof(path), "/data/user/%d/%s", user_id, pkg);
	if (err <= 0 || err >= sizeof(path)) {
		return false;
	}

	saved = override_creds(ksu_cred);
	err = kern_path(path, LOOKUP_FOLLOW, &real_path);
	revert_creds(saved);
	if (err) {
		return false;
	}

	path_put(&real_path);
	return true;
}

static u32 ksu_susfs_pkg_anchor_key(const char *pkg, uid_t user_id)
{
	return jhash(pkg, strlen(pkg), user_id);
}

static struct ksu_susfs_pkg_anchor *
ksu_susfs_find_pkg_anchor_locked(const char *pkg, uid_t user_id)
{
	struct ksu_susfs_pkg_anchor *entry;
	u32 key;

	if (!pkg || !*pkg) {
		return NULL;
	}

	key = ksu_susfs_pkg_anchor_key(pkg, user_id);
	hash_for_each_possible(ksu_susfs_pkg_anchors, entry, node, key) {
		if (entry->user_id == user_id && !strcmp(entry->pkg, pkg)) {
			return entry;
		}
	}

	return NULL;
}

static bool ksu_susfs_pkg_anchor_task_dead(struct task_struct *task)
{
	return !task || !pid_alive(task) ||
	       (READ_ONCE(task->flags) & PF_EXITING);
}

static void ksu_susfs_drop_pkg_anchor_locked(struct ksu_susfs_pkg_anchor *entry)
{
	struct task_struct *task;

	if (!entry) {
		return;
	}

	hash_del(&entry->node);
	task = entry->task;
	entry->task = NULL;
	kfree(entry);
	if (task) {
		put_task_struct(task);
	}
}

static struct task_struct *ksu_susfs_get_pkg_anchor_task(const char *pkg,
							 uid_t user_id)
{
	struct ksu_susfs_pkg_anchor *entry;
	struct task_struct *task = NULL;

	mutex_lock(&ksu_susfs_pkg_anchors_lock);
	entry = ksu_susfs_find_pkg_anchor_locked(pkg, user_id);
	if (entry && !ksu_susfs_pkg_anchor_task_dead(entry->task)) {
		task = entry->task;
		get_task_struct(task);
	} else if (entry) {
		ksu_susfs_drop_pkg_anchor_locked(entry);
	}
	mutex_unlock(&ksu_susfs_pkg_anchors_lock);

	return task;
}

static void ksu_susfs_store_pkg_anchor_task(const char *pkg, uid_t user_id,
					    struct task_struct *task)
{
	struct ksu_susfs_pkg_anchor *entry;
	struct task_struct *anchor;
	struct task_struct *old_task = NULL;

	if (!pkg || !*pkg || !task) {
		return;
	}

	anchor = task->group_leader ? task->group_leader : task;
	get_task_struct(anchor);

	mutex_lock(&ksu_susfs_pkg_anchors_lock);
	entry = ksu_susfs_find_pkg_anchor_locked(pkg, user_id);
	if (entry) {
		old_task = entry->task;
		entry->task = anchor;
	} else {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry) {
			mutex_unlock(&ksu_susfs_pkg_anchors_lock);
			put_task_struct(anchor);
			return;
		}
		entry->task = anchor;
		entry->user_id = user_id;
		strscpy(entry->pkg, pkg, sizeof(entry->pkg));
		hash_add(ksu_susfs_pkg_anchors, &entry->node,
			 ksu_susfs_pkg_anchor_key(pkg, user_id));
	}
	mutex_unlock(&ksu_susfs_pkg_anchors_lock);

	if (old_task) {
		put_task_struct(old_task);
	}
}

static void ksu_susfs_clear_pkg_anchors_all(void)
{
	struct ksu_susfs_pkg_anchor *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&ksu_susfs_pkg_anchors_lock);
	hash_for_each_safe(ksu_susfs_pkg_anchors, bkt, tmp, entry, node) {
		ksu_susfs_drop_pkg_anchor_locked(entry);
	}
	mutex_unlock(&ksu_susfs_pkg_anchors_lock);
}

static struct task_struct *ksu_susfs_find_mount_donor(const char *pkg, uid_t uid)
{
	struct task_struct *candidates[KSU_SUSFS_ISOLATED_NS_MAX_CANDIDATES];
	struct task_struct *task;
	struct task_struct *best = NULL;
	char cmdline0[KSU_SUSFS_ISOLATED_NS_MAX_CMDLINE];
	uid_t user_id = uid / PER_USER_RANGE;
	int best_rank = 0;
	int nr = 0;
	int i;

	read_lock(&tasklist_lock);
	for_each_process (task) {
		uid_t task_uid_val = task_uid(task).val;

		if (task == current || nr >= ARRAY_SIZE(candidates)) {
			continue;
		}
		if (!task->mm || !is_appuid(task_uid_val)) {
			continue;
		}
		if ((task_uid_val / PER_USER_RANGE) != user_id) {
			continue;
		}

		get_task_struct(task);
		candidates[nr++] = task;
	}
	read_unlock(&tasklist_lock);

	for (i = 0; i < nr; i++) {
		struct task_struct *candidate = candidates[i];
		int len = ksu_susfs_get_cmdline0(candidate, cmdline0,
						 sizeof(cmdline0));
		int rank = 0;
		bool keep = false;

		if (len > 0) {
			rank = ksu_susfs_match_pkg_cmdline(cmdline0, pkg);
			if (rank > best_rank) {
				best = candidate;
				best_rank = rank;
				keep = true;
			} else if (candidate == best) {
				keep = true;
			}
		}

		if (!keep) {
			put_task_struct(candidate);
			candidates[i] = NULL;
		}
	}

	for (i = 0; i < nr; i++) {
		if (candidates[i] && candidates[i] != best) {
			put_task_struct(candidates[i]);
		}
	}

	return best;
}

static void ksu_susfs_free_isolated_ns_ctx(struct ksu_susfs_isolated_ns_ctx *ctx)
{
	if (ctx->task) {
		put_task_struct(ctx->task);
		ctx->task = NULL;
	}
	kfree(ctx);
}

static int ksu_susfs_queue_isolated_ns_task_work(struct ksu_susfs_isolated_ns_ctx *ctx)
{
	if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
		return -EAGAIN;
	}

	ctx->attempts++;
	return task_work_add(ctx->task, &ctx->cb, TWA_RESUME);
}

static void ksu_susfs_schedule_isolated_ns_retry(struct ksu_susfs_isolated_ns_ctx *ctx,
						 unsigned long delay_ms)
{
	if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	mod_delayed_work(system_wq, &ctx->work, msecs_to_jiffies(delay_ms));
}

static void ksu_susfs_isolated_ns_cb(struct callback_head *cb)
{
	struct ksu_susfs_isolated_ns_ctx *ctx =
		container_of(cb, struct ksu_susfs_isolated_ns_ctx, cb);
	struct task_struct *donor;
	char cmdline0[KSU_SUSFS_ISOLATED_NS_MAX_CMDLINE];
	char pkg[KSU_SUSFS_MAX_PATHNAME];
	uid_t uid;
	uid_t user_id;
	unsigned int old_ns = 0;
	unsigned int donor_ns = 0;
	bool path_ok = false;
	bool exact_pkg;
	int err;

	if (unlikely(in_interrupt() || oops_in_progress)) {
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	uid = current_uid().val;
	if (!ksu_susfs_pkg_ns_allowed_uid(uid) || !current->mm ||
	    !current->nsproxy ||
	    !current->nsproxy->mnt_ns) {
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	if (ksu_susfs_get_cmdline0(current, cmdline0, sizeof(cmdline0)) <= 0 ||
	    ksu_susfs_parse_package_name(cmdline0, pkg, sizeof(pkg))) {
		if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
			pr_warn("susfs: pkgns pid=%d uid=%u failed to resolve package cmdline after %u attempts\n",
				current->pid, uid, ctx->attempts);
			ksu_susfs_free_isolated_ns_ctx(ctx);
			return;
		}
		ksu_susfs_schedule_isolated_ns_retry(
			ctx, KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS);
		return;
	}

	user_id = uid / PER_USER_RANGE;
	exact_pkg = !strcmp(cmdline0, pkg);
	old_ns = current->nsproxy->mnt_ns->ns.inum;
	path_ok = ksu_susfs_pkg_data_path_exists(uid, pkg);

	if (exact_pkg) {
		ksu_susfs_store_pkg_anchor_task(pkg, user_id, current);
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	donor = ksu_susfs_get_pkg_anchor_task(pkg, user_id);
	if (!donor) {
		donor = ksu_susfs_find_mount_donor(pkg, uid);
	}
	if (!donor) {
		if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS &&
		    is_appuid(uid) && path_ok) {
			ksu_susfs_store_pkg_anchor_task(pkg, user_id, current);
			ksu_susfs_free_isolated_ns_ctx(ctx);
			return;
		}
		if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
			pr_warn("susfs: pkgns pid=%d uid=%u found no donor for %s after %u attempts\n",
				current->pid, uid, pkg, ctx->attempts);
			ksu_susfs_free_isolated_ns_ctx(ctx);
			return;
		}
		ksu_susfs_schedule_isolated_ns_retry(
			ctx, KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS);
		return;
	}

	if (donor->nsproxy && donor->nsproxy->mnt_ns) {
		donor_ns = donor->nsproxy->mnt_ns->ns.inum;
	}

	if (donor_ns && donor_ns == old_ns && path_ok) {
		put_task_struct(donor);
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	err = ksu_join_task_mount_ns(donor);
	put_task_struct(donor);
	path_ok = ksu_susfs_pkg_data_path_exists(uid, pkg);
	if (err || !path_ok) {
		if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
			pr_warn("susfs: pkgns pid=%d uid=%u failed to join mount ns for %s after %u attempts (err=%d current=%u donor=%u path=%d)\n",
				current->pid, uid, pkg, ctx->attempts, err,
				old_ns, donor_ns, path_ok);
			ksu_susfs_free_isolated_ns_ctx(ctx);
			return;
		}
		ksu_susfs_schedule_isolated_ns_retry(
			ctx, KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS);
		return;
	}

	ksu_susfs_free_isolated_ns_ctx(ctx);
}

static void ksu_susfs_isolated_ns_work_fn(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ksu_susfs_isolated_ns_ctx *ctx =
		container_of(dwork, struct ksu_susfs_isolated_ns_ctx, work);

	if (!ctx->task || !pid_alive(ctx->task) ||
	    (READ_ONCE(ctx->task->flags) & PF_EXITING)) {
		ksu_susfs_free_isolated_ns_ctx(ctx);
		return;
	}

	if (ksu_susfs_queue_isolated_ns_task_work(ctx)) {
		if (ctx->attempts >= KSU_SUSFS_ISOLATED_NS_MAX_ATTEMPTS) {
			pr_warn("susfs: pkgns task_work add failed for pid=%d after %u attempts\n",
				task_pid_nr(ctx->task), ctx->attempts);
			ksu_susfs_free_isolated_ns_ctx(ctx);
			return;
		}
		ksu_susfs_schedule_isolated_ns_retry(
			ctx, KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS);
	}
}

static bool ksu_susfs_compat_root_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain();
}

static bool ksu_susfs_pkg_ns_allowed_uid(uid_t uid)
{
	if (is_isolated_process(uid)) {
		return true;
	}

	return is_appuid(uid) && ksu_uid_should_umount(uid);
}

static bool ksu_susfs_mount_view_allowed_current(void)
{
	uid_t uid;

	if (unlikely(in_interrupt() || oops_in_progress)) {
		return false;
	}
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) {
		return false;
	}

	uid = current_uid().val;
	return (is_appuid(uid) || is_isolated_process(uid)) &&
	       ksu_uid_should_umount(uid);
}

static bool ksu_susfs_mntns_identity_view_enabled(void)
{
	uid_t uid;

	if (unlikely(in_interrupt() || oops_in_progress)) {
		return false;
	}
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) {
		return false;
	}

	uid = current_uid().val;
	return ksu_susfs_pkg_ns_allowed_uid(uid);
}

static bool ksu_susfs_mount_hidden_exact(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	unsigned long flags;
	bool found = false;

	if (!mnt) {
		return false;
	}

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, entry, node,
			       (unsigned long)mnt) {
		if (entry->mnt == mnt) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);

	return found;
}

static bool ksu_susfs_mount_hidden_or_ancestor(struct mount *mnt)
{
	struct mount *cursor;
	unsigned seq;
	bool hidden;

	if (!mnt) {
		return false;
	}

	do {
		seq = read_seqbegin(&mount_lock);
		cursor = mnt;
		hidden = false;

		while (cursor) {
			if (ksu_susfs_mount_hidden_exact(cursor)) {
				hidden = true;
				break;
			}
			if (!mnt_has_parent(cursor)) {
				break;
			}
			cursor = cursor->mnt_parent;
		}
	} while (read_seqretry(&mount_lock, seq));

	return hidden;
}

static int ksu_susfs_visible_mnt_id(struct mount *mnt)
{
	struct mount *cursor;
	unsigned seq;
	int mnt_id = 0;

	if (!mnt) {
		return 0;
	}

	do {
		seq = read_seqbegin(&mount_lock);
		cursor = mnt;

		while (cursor && mnt_has_parent(cursor)) {
			if (!ksu_susfs_mount_hidden_exact(cursor) &&
			    !ksu_susfs_mount_hidden_exact(cursor->mnt_parent)) {
				break;
			}
			cursor = cursor->mnt_parent;
		}

		if (cursor) {
			mnt_id = cursor->mnt_id;
		}
	} while (read_seqretry(&mount_lock, seq));

	return mnt_id;
}

static bool ksu_susfs_mount_hide_view_enabled(void)
{
	if (!static_branch_unlikely(&ksu_susfs_mount_hide_enabled)) {
		return false;
	}

	return !is_ksu_domain() && ksu_susfs_mount_view_allowed_current();
}

static void ksu_susfs_schedule_cmdline_retry(unsigned long delay)
{
	if (READ_ONCE(ksu_susfs_cmdline_ready)) {
		return;
	}

	mod_delayed_work(system_wq, &ksu_susfs_cmdline_retry_work, delay);
}

static bool ksu_susfs_sdcard_android_ready(void)
{
	struct path path;
	const struct cred *saved;
	int err;

	saved = override_creds(ksu_cred);
	err = kern_path("/sdcard/Android", LOOKUP_FOLLOW, &path);
	revert_creds(saved);
	if (err) {
		return false;
	}

	path_put(&path);
	return true;
}

static bool ksu_susfs_mount_auto_hide_window_open(void)
{
	return READ_ONCE(ksu_susfs_mount_window_open) &&
	       !READ_ONCE(ksu_boot_completed);
}

static bool ksu_susfs_mount_should_mark_current(void)
{
	if (!is_ksu_domain_fast()) {
		return false;
	}

	return ksu_susfs_mount_auto_hide_window_open();
}

static void ksu_susfs_mount_window_retry_fn(struct work_struct *work)
{
	if (READ_ONCE(ksu_boot_completed) || ksu_susfs_sdcard_android_ready()) {
		if (READ_ONCE(ksu_susfs_mount_window_open)) {
			pr_info("susfs: mount auto-hide window closed\n");
		}
		WRITE_ONCE(ksu_susfs_mount_window_open, false);
		return;
	}

	schedule_delayed_work(&ksu_susfs_mount_window_retry_work,
			      msecs_to_jiffies(
				      KSU_SUSFS_MOUNT_WINDOW_RETRY_DELAY_MS));
}

static void ksu_susfs_mount_mark_hidden(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	struct ksu_susfs_hidden_mount *existing;
	unsigned long flags;

	if (!mnt) {
		return;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		pr_err("susfs: failed to allocate hidden mount entry\n");
		return;
	}

	entry->mnt = mnt;

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, existing, node,
			       (unsigned long)mnt) {
		if (existing->mnt == mnt) {
			spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock,
					       flags);
			kfree(entry);
			return;
		}
	}
	hash_add(ksu_susfs_hidden_mounts, &entry->node, (unsigned long)mnt);
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static void ksu_susfs_mount_unmark_hidden(struct mount *mnt)
{
	struct ksu_susfs_hidden_mount *entry;
	unsigned long flags;

	if (!mnt) {
		return;
	}

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_possible(ksu_susfs_hidden_mounts, entry, node,
			       (unsigned long)mnt) {
		if (entry->mnt == mnt) {
			hash_del(&entry->node);
			kfree(entry);
			break;
		}
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static void ksu_susfs_mount_clear_hidden_all(void)
{
	struct ksu_susfs_hidden_mount *entry;
	struct hlist_node *tmp;
	int bkt;
	unsigned long flags;

	spin_lock_irqsave(&ksu_susfs_hidden_mounts_lock, flags);
	hash_for_each_safe(ksu_susfs_hidden_mounts, bkt, tmp, entry, node) {
		hash_del(&entry->node);
		kfree(entry);
	}
	spin_unlock_irqrestore(&ksu_susfs_hidden_mounts_lock, flags);
}

static int ksu_susfs_patch_fop_open(const struct file_operations *fops,
				    int (*new_open)(struct inode *,
						    struct file *),
				    int (**old_open)(struct inode *,
						    struct file *))
{
	int (*orig_open)(struct inode *inode, struct file *file);
	void *dst;

	if (!fops || !new_open) {
		return -EINVAL;
	}

	orig_open = READ_ONCE(fops->open);
	if (!orig_open) {
		return -EINVAL;
	}

	if (old_open) {
		*old_open = orig_open;
	}

	dst = (void *)&((struct file_operations *)fops)->open;
	return ksu_patch_text(dst, &new_open, sizeof(new_open),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_fop_open(const struct file_operations *fops,
				       int (**old_open)(struct inode *,
							struct file *))
{
	int (*orig_open)(struct inode *inode, struct file *file);
	void *dst;

	if (!fops || !old_open || !*old_open) {
		return;
	}

	orig_open = *old_open;
	dst = (void *)&((struct file_operations *)fops)->open;
	if (ksu_patch_text(dst, &orig_open, sizeof(orig_open),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore file_operations open\n");
	}

	*old_open = NULL;
}

static struct mnt_namespace *ksu_susfs_to_mnt_ns(struct ns_common *ns)
{
	if (!ns) {
		return NULL;
	}

	return container_of(ns, struct mnt_namespace, ns);
}

static struct mnt_namespace *ksu_susfs_get_visible_mnt_ns(void)
{
	struct mnt_namespace *mnt_ns = NULL;

	task_lock(&init_task);
	if (init_task.nsproxy && init_task.nsproxy->mnt_ns) {
		mnt_ns = init_task.nsproxy->mnt_ns;
		get_mnt_ns(mnt_ns);
	}
	task_unlock(&init_task);

	return mnt_ns;
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
struct ns_common *
#else
static struct ns_common *
#endif
ksu_susfs_handle_mntns_get(struct ns_common *orig_ns)
{
	struct mnt_namespace *visible_ns;

	if (!ksu_susfs_mntns_identity_view_enabled()) {
		return orig_ns;
	}

	if (!orig_ns) {
		return orig_ns;
	}

	visible_ns = ksu_susfs_get_visible_mnt_ns();
	if (!visible_ns) {
		return orig_ns;
	}

	if (orig_ns == &visible_ns->ns) {
		put_mnt_ns(visible_ns);
		return orig_ns;
	}

	put_mnt_ns(ksu_susfs_to_mnt_ns(orig_ns));
	return &visible_ns->ns;
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
static struct ns_common *ksu_susfs_mntns_get_fast(struct task_struct *task)
{
	struct ns_common *orig_ns;

	if (!ksu_susfs_orig_mntns_get) {
		return NULL;
	}

	orig_ns = ksu_susfs_orig_mntns_get(task);
	return ksu_susfs_handle_mntns_get(orig_ns);
}

static int ksu_susfs_patch_mntns_get(void)
{
	struct ns_common *(*new_get)(struct task_struct *task);
	void *dst;

	if (ksu_susfs_orig_mntns_get) {
		return 0;
	}

	ksu_susfs_orig_mntns_get = mntns_operations.get;
	new_get = ksu_susfs_mntns_get_fast;
	dst = (void *)&((struct proc_ns_operations *)&mntns_operations)->get;
	return ksu_patch_text(dst, &new_get, sizeof(new_get),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_mntns_get(void)
{
	struct ns_common *(*orig_get)(struct task_struct *task);
	void *dst;

	if (!ksu_susfs_orig_mntns_get) {
		return;
	}

	orig_get = ksu_susfs_orig_mntns_get;
	dst = (void *)&((struct proc_ns_operations *)&mntns_operations)->get;
	if (ksu_patch_text(dst, &orig_get, sizeof(orig_get),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore mntns get\n");
	}

	ksu_susfs_orig_mntns_get = NULL;
}

void ksu_susfs_set_mount_runtime_ready(bool ready)
{
	ksu_susfs_mount_runtime_ready = ready;
}

bool ksu_susfs_mount_runtime_available(void)
{
	return READ_ONCE(ksu_susfs_mount_runtime_ready);
}
#endif

static int ksu_susfs_mntns_get_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	PT_REGS_RC(regs) = (unsigned long)ksu_susfs_handle_mntns_get(
		(struct ns_common *)regs_return_value(regs));
	return 0;
}

static int ksu_susfs_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt)
{
	struct mount *r = real_mount(mnt);

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	if (!ksu_susfs_orig_show_mounts) {
		return -ENOSYS;
	}

	return ksu_susfs_orig_show_mounts(m, mnt);
}

static int ksu_susfs_show_mountinfo(struct seq_file *m, struct vfsmount *mnt)
{
	struct mount *r = real_mount(mnt);

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	if (!ksu_susfs_orig_show_mountinfo) {
		return -ENOSYS;
	}

	return ksu_susfs_orig_show_mountinfo(m, mnt);
}

static int ksu_susfs_show_vfsstat(struct seq_file *m, struct vfsmount *mnt)
{
	struct mount *r = real_mount(mnt);

	if (ksu_susfs_mount_hidden_or_ancestor(r)) {
		return 0;
	}

	if (!ksu_susfs_orig_show_mountstats) {
		return -ENOSYS;
	}

	return ksu_susfs_orig_show_mountstats(m, mnt);
}

static int ksu_susfs_mounts_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mounts_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mounts_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	if (!ksu_susfs_orig_show_mounts) {
		ksu_susfs_orig_show_mounts = p->show;
	}
	p->show = ksu_susfs_show_vfsmnt;
	return 0;
}

static int ksu_susfs_mountinfo_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mountinfo_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mountinfo_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	if (!ksu_susfs_orig_show_mountinfo) {
		ksu_susfs_orig_show_mountinfo = p->show;
	}
	p->show = ksu_susfs_show_mountinfo;
	return 0;
}

static int ksu_susfs_mountstats_open(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct proc_mounts *p;
	int ret;

	if (!ksu_susfs_orig_mountstats_open) {
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_mountstats_open(inode, file);
	if (ret || !ksu_susfs_mount_hide_view_enabled()) {
		return ret;
	}

	m = file->private_data;
	if (!m || !m->private) {
		return ret;
	}

	p = m->private;
	if (!ksu_susfs_orig_show_mountstats) {
		ksu_susfs_orig_show_mountstats = p->show;
	}
	p->show = ksu_susfs_show_vfsstat;
	return 0;
}

static bool ksu_susfs_fdinfo_rewrite(struct file *file, int *mnt_id,
				     unsigned long *ino)
{
	struct path path;
	struct inode *inode;
	struct mount *mnt;
	char *buf;
	char *resolved;

	if (!file || !mnt_id || !ino) {
		return false;
	}

	mnt = real_mount(file->f_path.mnt);
	if (!ksu_susfs_mount_hidden_or_ancestor(mnt)) {
		return false;
	}

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf) {
		*mnt_id = ksu_susfs_visible_mnt_id(mnt);
		*ino = file_inode(file)->i_ino;
		return true;
	}

	resolved = d_path(&file->f_path, buf, PAGE_SIZE);
	if (!IS_ERR(resolved) && !kern_path(resolved, 0, &path)) {
		inode = d_backing_inode(path.dentry);
		*mnt_id = real_mount(path.mnt)->mnt_id;
		*ino = inode ? inode->i_ino : file_inode(file)->i_ino;
		path_put(&path);
		kfree(buf);
		return true;
	}

	*mnt_id = ksu_susfs_visible_mnt_id(mnt);
	*ino = file_inode(file)->i_ino;
	kfree(buf);
	return true;
}

static int ksu_susfs_fdinfo_show(struct seq_file *m, void *v)
{
	struct files_struct *files = NULL;
	struct file *file = NULL;
	struct task_struct *task;
	int f_flags = 0;
	int ret = -ENOENT;

	task = get_proc_task(m->private);
	if (!task) {
		return -ENOENT;
	}

#ifdef KSU_SUSFS_HAS_FILES_LOOKUP_FD_LOCKED
	task_lock(task);
	files = task->files;
	if (files) {
		unsigned int fd = proc_fd(m->private);

		spin_lock(&files->file_lock);
		file = files_lookup_fd_locked(files, fd);
		if (file) {
			struct fdtable *fdt = files_fdtable(files);

			f_flags = file->f_flags;
			if (close_on_exec(fd, fdt)) {
				f_flags |= O_CLOEXEC;
			}

			get_file(file);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
	}
	task_unlock(task);
	put_task_struct(task);
#else
	files = get_files_struct(task);
	put_task_struct(task);

	if (files) {
		unsigned int fd = proc_fd(m->private);

		spin_lock(&files->file_lock);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0) &&	\
	defined(KSU_SUSFS_HAS_FILES_LOOKUP_FD_RAW)
		file = files_lookup_fd_raw(files, fd);
#else
		file = fcheck_files(files, fd);
#endif
		if (file) {
			struct fdtable *fdt = files_fdtable(files);

			f_flags = file->f_flags;
			if (close_on_exec(fd, fdt)) {
				f_flags |= O_CLOEXEC;
			}

			get_file(file);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
	}
#endif

	if (ret) {
#ifndef KSU_SUSFS_HAS_FILES_LOOKUP_FD_LOCKED
		if (files) {
			put_files_struct(files);
		}
#endif
		return ret;
	}

	if (ksu_susfs_mount_hide_view_enabled()) {
		int mnt_id = 0;
		unsigned long ino = 0;

		if (ksu_susfs_fdinfo_rewrite(file, &mnt_id, &ino)) {
			seq_printf(m,
				   "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\nino:\t%lu\n",
				   (long long)file->f_pos, f_flags, mnt_id,
				   ino);
			goto out_tail;
		}
	}

	seq_printf(m, "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\nino:\t%lu\n",
		   (long long)file->f_pos, f_flags,
		   real_mount(file->f_path.mnt)->mnt_id, file_inode(file)->i_ino);

out_tail:
	show_fd_locks(m, file, files);
	if (!seq_has_overflowed(m) && file->f_op->show_fdinfo) {
		file->f_op->show_fdinfo(m, file);
	}

#ifndef KSU_SUSFS_HAS_FILES_LOOKUP_FD_LOCKED
	if (files) {
		put_files_struct(files);
	}
#endif
	fput(file);
	return 0;
}

static int ksu_susfs_fdinfo_open(struct inode *inode, struct file *file)
{
	if (!ksu_susfs_orig_fdinfo_open) {
		return -ENOSYS;
	}

	if (!ksu_susfs_mount_hide_view_enabled()) {
		return ksu_susfs_orig_fdinfo_open(inode, file);
	}

	return single_open(file, ksu_susfs_fdinfo_show, inode);
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
bool ksu_susfs_should_hide_new_vfsmount(void)
{
	return ksu_susfs_mount_should_mark_current();
}

bool ksu_susfs_should_hide_cloned_mount(struct mount *old)
{
	return ksu_susfs_mount_hidden_or_ancestor(old) ||
	       ksu_susfs_mount_should_mark_current();
}

void ksu_susfs_mark_vfsmount_hidden(struct vfsmount *mnt, bool hide)
{
	if (!hide || IS_ERR_OR_NULL(mnt)) {
		return;
	}

	ksu_susfs_mount_mark_hidden(real_mount(mnt));
}

void ksu_susfs_mark_mount_hidden(struct mount *mnt, bool hide)
{
	if (!hide || IS_ERR_OR_NULL(mnt)) {
		return;
	}

	ksu_susfs_mount_mark_hidden(mnt);
}

void ksu_susfs_handle_cleanup_mnt(struct mount *mnt)
{
	ksu_susfs_mount_unmark_hidden(mnt);
}
#endif

static int ksu_susfs_vfs_create_mount_entry(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct ksu_susfs_vfs_create_mount_ctx *ctx =
		(struct ksu_susfs_vfs_create_mount_ctx *)ri->data;

	ctx->hide = ksu_susfs_mount_should_mark_current();
	return 0;
}

static int ksu_susfs_vfs_create_mount_handler(struct kretprobe_instance *ri,
					      struct pt_regs *regs)
{
	struct ksu_susfs_vfs_create_mount_ctx *ctx =
		(struct ksu_susfs_vfs_create_mount_ctx *)ri->data;
	struct vfsmount *vfsmnt;

	if (!ctx->hide) {
		return 0;
	}

	vfsmnt = (struct vfsmount *)regs_return_value(regs);
	if (IS_ERR_OR_NULL(vfsmnt)) {
		return 0;
	}

	ksu_susfs_mount_mark_hidden(real_mount(vfsmnt));
	return 0;
}

static int ksu_susfs_clone_mnt_entry(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct ksu_susfs_clone_mnt_ctx *ctx =
		(struct ksu_susfs_clone_mnt_ctx *)ri->data;

	ctx->old = (struct mount *)PT_REGS_PARM1(regs);
	ctx->hide = ksu_susfs_mount_hidden_or_ancestor(ctx->old) ||
		    ksu_susfs_mount_should_mark_current();
	return 0;
}

static int ksu_susfs_clone_mnt_handler(struct kretprobe_instance *ri,
				       struct pt_regs *regs)
{
	struct ksu_susfs_clone_mnt_ctx *ctx =
		(struct ksu_susfs_clone_mnt_ctx *)ri->data;
	struct mount *mnt;

	if (!ctx->hide) {
		return 0;
	}

	mnt = (struct mount *)regs_return_value(regs);
	if (IS_ERR_OR_NULL(mnt)) {
		return 0;
	}

	ksu_susfs_mount_mark_hidden(mnt);
	return 0;
}

static int ksu_susfs_cleanup_mnt_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct mount *mnt = (struct mount *)PT_REGS_PARM1(regs);

	ksu_susfs_mount_unmark_hidden(mnt);
	return 0;
}

static struct kretprobe *ksu_susfs_init_kretprobe(
	const char *name, kretprobe_handler_t entry_handler,
	kretprobe_handler_t handler, size_t data_size)
{
	struct kretprobe *rp;
	int ret;

	rp = kzalloc(sizeof(*rp), GFP_KERNEL);
	if (!rp) {
		return NULL;
	}

	rp->kp.symbol_name = name;
	rp->entry_handler = entry_handler;
	rp->handler = handler;
	rp->data_size = data_size;
	rp->maxactive = 0;

	ret = register_kretprobe(rp);
	if (ret) {
		pr_err("susfs: register_%s kretprobe failed: %d\n", name, ret);
		kfree(rp);
		return NULL;
	}

	return rp;
}

static void ksu_susfs_destroy_kretprobe(struct kretprobe **rp_ptr)
{
	struct kretprobe *rp = *rp_ptr;

	if (!rp) {
		return;
	}

	unregister_kretprobe(rp);
	synchronize_rcu();
	kfree(rp);
	*rp_ptr = NULL;
}

static struct kprobe *ksu_susfs_init_kprobe(const char *name,
					    kprobe_pre_handler_t handler)
{
	struct kprobe *kp;
	int ret;

	kp = kzalloc(sizeof(*kp), GFP_KERNEL);
	if (!kp) {
		return NULL;
	}

	kp->symbol_name = name;
	kp->pre_handler = handler;

	ret = register_kprobe(kp);
	if (ret) {
		pr_err("susfs: register_%s kprobe failed: %d\n", name, ret);
		kfree(kp);
		return NULL;
	}

	return kp;
}

static void ksu_susfs_destroy_kprobe(struct kprobe **kp_ptr)
{
	struct kprobe *kp = *kp_ptr;

	if (!kp) {
		return;
	}

	unregister_kprobe(kp);
	synchronize_rcu();
	kfree(kp);
	*kp_ptr = NULL;
}

void ksu_susfs_handle_setuid(uid_t old_uid, uid_t new_uid)
{
	struct ksu_susfs_isolated_ns_ctx *ctx;

	if (old_uid == new_uid || !ksu_susfs_pkg_ns_allowed_uid(new_uid)) {
		return;
	}
	if (unlikely(in_interrupt() || oops_in_progress)) {
		return;
	}
	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx) {
		return;
	}

	INIT_DELAYED_WORK(&ctx->work, ksu_susfs_isolated_ns_work_fn);
	ctx->cb.func = ksu_susfs_isolated_ns_cb;
	ctx->task = current;
	get_task_struct(ctx->task);
	if (ksu_susfs_queue_isolated_ns_task_work(ctx)) {
		pr_warn("susfs: pkgns immediate task_work add failed for pid=%d\n",
			current->pid);
		ksu_susfs_schedule_isolated_ns_retry(
			ctx, KSU_SUSFS_ISOLATED_NS_RETRY_DELAY_MS);
	}
}

static void ksu_susfs_mount_runtime_disable(void)
{
	ksu_susfs_restore_fop_open(&proc_mounts_operations,
				   &ksu_susfs_orig_mounts_open);
	ksu_susfs_restore_fop_open(&proc_mountinfo_operations,
				   &ksu_susfs_orig_mountinfo_open);
	ksu_susfs_restore_fop_open(&proc_mountstats_operations,
				   &ksu_susfs_orig_mountstats_open);
	if (ksu_susfs_fdinfo_fops) {
		ksu_susfs_restore_fop_open(ksu_susfs_fdinfo_fops,
					   &ksu_susfs_orig_fdinfo_open);
		ksu_susfs_fdinfo_fops = NULL;
	}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	ksu_susfs_restore_mntns_get();
#endif
	ksu_susfs_destroy_kretprobe(&ksu_susfs_vfs_create_mount_rp);
	ksu_susfs_destroy_kretprobe(&ksu_susfs_clone_mnt_rp);
	ksu_susfs_destroy_kretprobe(&ksu_susfs_mntns_get_rp);
	ksu_susfs_destroy_kprobe(&ksu_susfs_cleanup_mnt_kp);
	cancel_delayed_work_sync(&ksu_susfs_mount_window_retry_work);
	ksu_susfs_mount_clear_hidden_all();
	ksu_susfs_clear_pkg_anchors_all();
	ksu_susfs_orig_show_mounts = NULL;
	ksu_susfs_orig_show_mountinfo = NULL;
	ksu_susfs_orig_show_mountstats = NULL;
	WRITE_ONCE(ksu_susfs_mount_window_open, false);

	if (static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
		static_branch_disable(&ksu_susfs_mount_hide_enabled);
	}

	ksu_susfs_mount_runtime_ready = false;
}

static int ksu_susfs_mount_runtime_enable(void)
{
	unsigned long addr;
	int err;

	err = ksu_susfs_patch_fop_open(&proc_mounts_operations,
				       ksu_susfs_mounts_open,
				       &ksu_susfs_orig_mounts_open);
	if (err) {
		goto err_out;
	}

	err = ksu_susfs_patch_fop_open(&proc_mountinfo_operations,
				       ksu_susfs_mountinfo_open,
				       &ksu_susfs_orig_mountinfo_open);
	if (err) {
		goto err_out;
	}

	err = ksu_susfs_patch_fop_open(&proc_mountstats_operations,
				       ksu_susfs_mountstats_open,
				       &ksu_susfs_orig_mountstats_open);
	if (err) {
		goto err_out;
	}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	err = ksu_susfs_patch_mntns_get();
	if (err) {
		pr_warn("susfs: mnt namespace identity fast hook unavailable: %d\n",
			err);
	}
#else
	ksu_susfs_vfs_create_mount_rp = ksu_susfs_init_kretprobe(
		"vfs_create_mount", ksu_susfs_vfs_create_mount_entry,
		ksu_susfs_vfs_create_mount_handler,
		sizeof(struct ksu_susfs_vfs_create_mount_ctx));
	if (!ksu_susfs_vfs_create_mount_rp) {
		err = -ENOENT;
		goto err_out;
	}

	ksu_susfs_clone_mnt_rp = ksu_susfs_init_kretprobe(
		"clone_mnt", ksu_susfs_clone_mnt_entry,
		ksu_susfs_clone_mnt_handler,
		sizeof(struct ksu_susfs_clone_mnt_ctx));
	if (!ksu_susfs_clone_mnt_rp) {
		err = -ENOENT;
		goto err_out;
	}

	ksu_susfs_cleanup_mnt_kp = ksu_susfs_init_kprobe(
		"cleanup_mnt", ksu_susfs_cleanup_mnt_pre);
	if (!ksu_susfs_cleanup_mnt_kp) {
		err = -ENOENT;
		goto err_out;
	}

	ksu_susfs_mntns_get_rp =
		ksu_susfs_init_kretprobe("mntns_get", NULL,
					 ksu_susfs_mntns_get_handler, 0);
	if (!ksu_susfs_mntns_get_rp) {
		pr_warn("susfs: mnt namespace identity hook unavailable\n");
	}
#endif

	addr = find_kernel_symbol_exact("proc_fdinfo_file_operations");
	if (addr) {
		ksu_susfs_fdinfo_fops =
			(const struct file_operations *)addr;
		err = ksu_susfs_patch_fop_open(ksu_susfs_fdinfo_fops,
					       ksu_susfs_fdinfo_open,
					       &ksu_susfs_orig_fdinfo_open);
		if (err) {
			pr_warn("susfs: fdinfo wrapper unavailable: %d\n", err);
			ksu_susfs_fdinfo_fops = NULL;
		}
	}

	WRITE_ONCE(ksu_susfs_mount_window_open,
		   !READ_ONCE(ksu_boot_completed));
	if (ksu_susfs_mount_auto_hide_window_open()) {
		schedule_delayed_work(
			&ksu_susfs_mount_window_retry_work,
			msecs_to_jiffies(
				KSU_SUSFS_MOUNT_WINDOW_RETRY_DELAY_MS));
	}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	ksu_susfs_mount_runtime_ready = false;
#else
	ksu_susfs_mount_runtime_ready = true;
#endif
	return 0;

err_out:
	ksu_susfs_mount_runtime_disable();
	return err;
}

#if KSU_SUSFS_CMDLINE_USE_PROC_SHOW_HOOK
static struct proc_dir_entry *
ksu_susfs_find_proc_root_entry(const char *name, unsigned int len)
{
	struct rb_node *node = proc_root.subdir.rb_node;

	while (node) {
		struct proc_dir_entry *de =
			rb_entry(node, struct proc_dir_entry, subdir_node);
		int result;

		if (len < de->namelen) {
			result = -1;
		} else if (len > de->namelen) {
			result = 1;
		} else {
			result = memcmp(name, de->name, len);
		}

		if (result < 0) {
			node = node->rb_left;
		} else if (result > 0) {
			node = node->rb_right;
		} else {
			return de;
		}
	}

	return NULL;
}

static int ksu_susfs_cmdline_show(struct seq_file *m, void *v)
{
	const char *cmdline = READ_ONCE(ksu_susfs_cmdline_active);

	if (!cmdline) {
		cmdline = READ_ONCE(ksu_susfs_orig_saved_command_line);
	}
	if (!cmdline) {
		cmdline = READ_ONCE(saved_command_line);
	}

	if (cmdline) {
		seq_puts(m, cmdline);
	}
	seq_putc(m, '\n');
	return 0;
}

static int ksu_susfs_cmdline_show_hook_enable(void)
{
	struct proc_dir_entry *de;
	int (*show)(struct seq_file *m, void *v);

	if (READ_ONCE(ksu_susfs_cmdline_show_hook_ready)) {
		return 0;
	}

	de = ksu_susfs_find_proc_root_entry("cmdline",
					    sizeof("cmdline") - 1);
	if (!de) {
		return -ENOENT;
	}

	show = READ_ONCE(de->single_show);
	if (!show) {
		return -ENOENT;
	}
	if (show == ksu_susfs_cmdline_show) {
		WRITE_ONCE(ksu_susfs_cmdline_show_hook_ready, true);
		return 0;
	}

	if (!ksu_susfs_orig_cmdline_show) {
		ksu_susfs_orig_cmdline_show = show;
	}
	WRITE_ONCE(de->single_show, ksu_susfs_cmdline_show);
	WRITE_ONCE(ksu_susfs_cmdline_pde, de);
	WRITE_ONCE(ksu_susfs_cmdline_show_hook_ready, true);
	return 0;
}

static void ksu_susfs_cmdline_show_hook_disable(void)
{
	struct proc_dir_entry *de = READ_ONCE(ksu_susfs_cmdline_pde);
	int (*show)(struct seq_file *m, void *v) =
		READ_ONCE(ksu_susfs_orig_cmdline_show);

	if (de && show &&
	    READ_ONCE(de->single_show) == ksu_susfs_cmdline_show) {
		WRITE_ONCE(de->single_show, show);
	}

	WRITE_ONCE(ksu_susfs_cmdline_show_hook_ready, false);
	WRITE_ONCE(ksu_susfs_cmdline_pde, NULL);
	WRITE_ONCE(ksu_susfs_orig_cmdline_show, NULL);
}
#else
static inline int ksu_susfs_cmdline_show_hook_enable(void)
{
	return 0;
}

static inline void ksu_susfs_cmdline_show_hook_disable(void)
{
}
#endif

static int __ksu_susfs_cmdline_runtime_enable_locked(void)
{
	const char *cmdline;
	int err;

	if (!READ_ONCE(saved_command_line)) {
		return -ENOENT;
	}

	if (!ksu_susfs_cmdline_shadow) {
		ksu_susfs_cmdline_shadow =
			kzalloc(sizeof(ksu_susfs_fake_cmdline), GFP_KERNEL);
		if (!ksu_susfs_cmdline_shadow) {
			return -ENOMEM;
		}
	}

	if (!ksu_susfs_orig_saved_command_line) {
		ksu_susfs_orig_saved_command_line =
			READ_ONCE(saved_command_line);
	}

	if (static_key_enabled(&ksu_susfs_cmdline_spoof_enabled) &&
	    ksu_susfs_fake_cmdline[0]) {
		strscpy(ksu_susfs_cmdline_shadow, ksu_susfs_fake_cmdline,
			sizeof(ksu_susfs_fake_cmdline));
		cmdline = ksu_susfs_cmdline_shadow;
	} else {
		cmdline = ksu_susfs_orig_saved_command_line;
	}

	err = ksu_susfs_cmdline_show_hook_enable();
	if (err) {
		return err;
	}

	WRITE_ONCE(ksu_susfs_cmdline_active, cmdline);
#if !KSU_SUSFS_CMDLINE_USE_PROC_SHOW_HOOK
	WRITE_ONCE(saved_command_line, (char *)cmdline);
#endif
	ksu_susfs_cmdline_ready = true;
	return 0;
}

static int ksu_susfs_cmdline_runtime_enable(void)
{
	int err;

	mutex_lock(&ksu_susfs_cmdline_patch_lock);
	err = __ksu_susfs_cmdline_runtime_enable_locked();
	ksu_susfs_cmdline_last_err = err;
	mutex_unlock(&ksu_susfs_cmdline_patch_lock);

	return err;
}

static void ksu_susfs_cmdline_retry_fn(struct work_struct *work)
{
	if (!ksu_susfs_cmdline_runtime_enable()) {
		return;
	}

	if (!READ_ONCE(ksu_boot_completed)) {
		ksu_susfs_schedule_cmdline_retry(
			msecs_to_jiffies(KSU_SUSFS_CMDLINE_RETRY_DELAY_MS));
	}
}

static void ksu_susfs_cmdline_runtime_disable(void)
{
	cancel_delayed_work_sync(&ksu_susfs_cmdline_retry_work);
	mutex_lock(&ksu_susfs_cmdline_patch_lock);
	WRITE_ONCE(ksu_susfs_cmdline_active,
		   ksu_susfs_orig_saved_command_line);
#if !KSU_SUSFS_CMDLINE_USE_PROC_SHOW_HOOK
	if (ksu_susfs_orig_saved_command_line) {
		WRITE_ONCE(saved_command_line,
			   ksu_susfs_orig_saved_command_line);
	}
#else
	ksu_susfs_cmdline_show_hook_disable();
#endif
	kfree(ksu_susfs_cmdline_shadow);
	ksu_susfs_cmdline_shadow = NULL;
	ksu_susfs_orig_saved_command_line = NULL;
	ksu_susfs_cmdline_active = NULL;
	ksu_susfs_cmdline_ready = false;
	ksu_susfs_cmdline_last_err = 0;
	mutex_unlock(&ksu_susfs_cmdline_patch_lock);
}

void ksu_susfs_handle_boot_completed(void)
{
	/*
	 * Some product/vendor paths are not mounted yet during early
	 * KernelSU init, so retry built-in hide rules once Android has
	 * finished booting.
	 */
	ksu_susfs_apply_default_rules();
	ksu_susfs_prop_hygiene_attempts = 0;
	mod_delayed_work(system_wq, &ksu_susfs_prop_hygiene_restore_work,
			 msecs_to_jiffies(
				 KSU_SUSFS_PROP_HYGIENE_INITIAL_DELAY_MS));
}

static long __nocfi ksu_susfs_hook_uname(int orig_nr, const struct pt_regs *regs)
{
	struct new_utsname __user *name =
		(struct new_utsname __user *)PT_REGS_PARM1(regs);
	long ret;

	ret = ksu_invoke_syscall_nr(orig_nr, regs);
	if (ret || !static_branch_unlikely(&ksu_susfs_uname_spoof_enabled)) {
		return ret;
	}

	if (name) {
		struct new_utsname tmp;
		unsigned seq;

		if (copy_from_user(&tmp, name, sizeof(tmp))) {
			return ret;
		}

		do {
			seq = read_seqbegin(&ksu_susfs_uname_lock);
			strscpy(tmp.release, ksu_susfs_fake_uname.release,
				sizeof(tmp.release));
			strscpy(tmp.version, ksu_susfs_fake_uname.version,
				sizeof(tmp.version));
		} while (read_seqretry(&ksu_susfs_uname_lock, seq));

		if (copy_to_user(name, &tmp, sizeof(tmp))) {
			return -EFAULT;
		}
	}

	return ret;
}

bool ksu_susfs_handle_mount_compat(void __user *arg)
{
	struct ksu_susfs_hide_mounts_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_mount_runtime_ready) {
		cmd.err = -EOPNOTSUPP;
		goto out;
	}

	if (cmd.enabled) {
		if (!static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
			static_branch_enable(&ksu_susfs_mount_hide_enabled);
		}
	} else if (static_key_enabled(&ksu_susfs_mount_hide_enabled)) {
		static_branch_disable(&ksu_susfs_mount_hide_enabled);
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: mount compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_cmdline_compat(void __user *arg)
{
	struct ksu_susfs_cmdline_cmd *cmd;
	int patch_err = 0;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		return true;
	}

	if (copy_from_user(cmd, arg, sizeof(*cmd))) {
		cmd->err = -EFAULT;
		goto out;
	}

	cmd->fake_cmdline_or_bootconfig
		[sizeof(cmd->fake_cmdline_or_bootconfig) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd->err = -EPERM;
		goto out;
	}

	if (!strcmp(cmd->fake_cmdline_or_bootconfig, "default")) {
		if (static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
			static_branch_disable(&ksu_susfs_cmdline_spoof_enabled);
		}
		memset(ksu_susfs_fake_cmdline, 0, sizeof(ksu_susfs_fake_cmdline));
		patch_err = ksu_susfs_cmdline_runtime_enable();
		if (patch_err && !READ_ONCE(ksu_boot_completed)) {
			ksu_susfs_schedule_cmdline_retry(
				msecs_to_jiffies(
					KSU_SUSFS_CMDLINE_RETRY_DELAY_MS));
		}
		cmd->err = 0;
		goto out;
	}

	if (!cmd->fake_cmdline_or_bootconfig[0]) {
		cmd->err = -EINVAL;
		goto out;
	}

	strscpy(ksu_susfs_fake_cmdline, cmd->fake_cmdline_or_bootconfig,
		sizeof(ksu_susfs_fake_cmdline));

	if (!static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
		static_branch_enable(&ksu_susfs_cmdline_spoof_enabled);
	}

	patch_err = ksu_susfs_cmdline_runtime_enable();
	if (!ksu_susfs_cmdline_ready) {
		if (!READ_ONCE(ksu_boot_completed)) {
			ksu_susfs_schedule_cmdline_retry(
				msecs_to_jiffies(
					KSU_SUSFS_CMDLINE_RETRY_DELAY_MS));
			cmd->err = 0;
			goto out;
		}

		cmd->err = patch_err ? patch_err :
			   (ksu_susfs_cmdline_last_err ?
				    ksu_susfs_cmdline_last_err :
				    -EOPNOTSUPP);
		goto out;
	}

	cmd->err = 0;

out:
	if (copy_to_user(arg, cmd, sizeof(*cmd))) {
		pr_err("susfs: cmdline compat copy_to_user failed\n");
	}
	kfree(cmd);
	return true;
}

bool ksu_susfs_handle_uname_compat(void __user *arg)
{
	struct ksu_susfs_uname_cmd cmd;
	char release[sizeof(ksu_susfs_fake_uname.release)];
	char version[sizeof(ksu_susfs_fake_uname.version)];

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.release[sizeof(cmd.release) - 1] = '\0';
	cmd.version[sizeof(cmd.version) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_uname_hook_ready) {
		cmd.err = -EOPNOTSUPP;
		goto out;
	}

	if (!cmd.release[0] || !cmd.version[0]) {
		cmd.err = -EINVAL;
		goto out;
	}

	if (!strcmp(cmd.release, "default")) {
		down_read(&uts_sem);
		strscpy(release, utsname()->release, sizeof(release));
		up_read(&uts_sem);
	} else {
		strscpy(release, cmd.release, sizeof(release));
	}

	if (!strcmp(cmd.version, "default")) {
		down_read(&uts_sem);
		strscpy(version, utsname()->version, sizeof(version));
		up_read(&uts_sem);
	} else {
		strscpy(version, cmd.version, sizeof(version));
	}

	write_seqlock(&ksu_susfs_uname_lock);
	strscpy(ksu_susfs_fake_uname.release, release,
		sizeof(ksu_susfs_fake_uname.release));
	strscpy(ksu_susfs_fake_uname.version, version,
		sizeof(ksu_susfs_fake_uname.version));
	write_sequnlock(&ksu_susfs_uname_lock);

	if (!static_key_enabled(&ksu_susfs_uname_spoof_enabled)) {
		static_branch_enable(&ksu_susfs_uname_spoof_enabled);
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: uname compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_avc_compat(void __user *arg)
{
	struct ksu_susfs_avc_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = ksu_set_feature(KSU_FEATURE_AVC_SPOOF, cmd.enabled ? 1 : 0);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: avc compat copy_to_user failed\n");
	}
	return true;
}

int ksu_susfs_procfs_init(void)
{
	int ret;

	hash_init(ksu_susfs_hidden_mounts);
	memset(&ksu_susfs_fake_uname, 0, sizeof(ksu_susfs_fake_uname));
	memset(ksu_susfs_fake_cmdline, 0, sizeof(ksu_susfs_fake_cmdline));

	ret = ksu_susfs_cmdline_runtime_enable();
	if (ret) {
		pr_info("susfs: /proc/cmdline not ready yet: %d\n", ret);
		ksu_susfs_schedule_cmdline_retry(
			msecs_to_jiffies(KSU_SUSFS_CMDLINE_RETRY_DELAY_MS));
	}

	ret = ksu_susfs_mount_runtime_enable();
	if (ret) {
		pr_warn("susfs: mount runtime unavailable: %d\n", ret);
	}

#ifdef __NR_uname
	ret = ksu_register_syscall_hook(__NR_uname, ksu_susfs_hook_uname);
	if (ret && ret != -EEXIST) {
		pr_warn("susfs: uname hook unavailable: %d\n", ret);
	} else {
		ksu_susfs_uname_hook_ready = true;
	}
#endif

	return 0;
}

void ksu_susfs_procfs_exit(void)
{
	if (ksu_susfs_uname_hook_ready) {
#ifdef __NR_uname
		ksu_unregister_syscall_hook(__NR_uname);
#endif
		ksu_susfs_uname_hook_ready = false;
	}

	if (static_key_enabled(&ksu_susfs_uname_spoof_enabled)) {
		static_branch_disable(&ksu_susfs_uname_spoof_enabled);
	}

	ksu_susfs_cmdline_runtime_disable();
	ksu_susfs_cmdline_ready = false;
	cancel_delayed_work_sync(&ksu_susfs_prop_hygiene_restore_work);

	if (static_key_enabled(&ksu_susfs_cmdline_spoof_enabled)) {
		static_branch_disable(&ksu_susfs_cmdline_spoof_enabled);
	}

	ksu_susfs_mount_runtime_disable();
}
