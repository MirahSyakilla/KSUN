#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/jhash.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "compat/kernel_compat.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "susfs/compat.h"
#include "susfs/kstat.h"
#include "susfs/procfs.h"
#include "susfs/susfs.h"

#define KSU_SUSFS_HASH_BITS 8
#define KSU_SUSFS_SB_HASH_BITS 4
#define KSU_SUSFS_SIGNATURE 0x53555346534b5355ULL
#define KSU_SUSFS_VERSION "v2.2.0"
#define KSU_SUSFS_VARIANT "hookless-v0.3"
#define KSU_SUSFS_AS_OPEN_REDIRECT 36

#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC 0x65735546
#endif

static const char *const ksu_susfs_default_hide_paths[] = {
	"/product/overlay/LineageSDKOverlaySM8350.apk",
};

enum ksu_susfs_rule_type {
	KSU_SUSFS_RULE_HIDE = 0,
	KSU_SUSFS_RULE_REDIRECT = 1,
};

struct ksu_susfs_rule {
	struct hlist_node path_node;
	struct hlist_node name_node;
	struct hlist_node redirect_target_node;
	struct hlist_node redirect_backend_node;
	struct list_head parent_list;
	struct list_head free_list;
	struct rcu_head rcu;
	u32 path_hash;
	u32 name_hash;
	unsigned long target_ino;
	unsigned long backend_ino;
	dev_t target_dev;
	dev_t backend_dev;
	s8 uid_scheme;
	u8 type;
	bool has_visible_stat;
	struct kstat visible_stat;
	struct kstatfs visible_statfs;
	struct inode *target_inode;
	struct inode *backend_inode;
	char name[KSU_SUSFS_MAX_PATHNAME];
	char visible_path[KSU_SUSFS_MAX_PATHNAME];
	char backend_path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_parent {
	struct hlist_node node;
	struct list_head all_list;
	struct list_head rules;
	struct inode *dir_inode;
	char path[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_iop {
	struct inode_operations fake_iop;
	const struct inode_operations *orig_iop;
	u64 signature;
	struct ksu_susfs_parent *parent;
	bool had_private_flag;
	struct rcu_head rcu;
};

struct ksu_susfs_fop {
	struct file_operations fake_fop;
	const struct file_operations *orig_fop;
	u64 signature;
	struct ksu_susfs_parent *parent;
	struct rcu_head rcu;
};

struct ksu_susfs_sop {
	struct super_operations fake_sop;
	const struct super_operations *orig_sop;
	u64 signature;
	struct super_block *sb;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct ksu_susfs_proxy_ctx {
	struct dir_context ctx;
	struct dir_context *orig_ctx;
	struct ksu_susfs_parent *parent;
};

static DEFINE_HASHTABLE(ksu_susfs_rules_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_names_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_redirect_targets_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_redirect_backends_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_parents_ht, KSU_SUSFS_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_sb_ht, KSU_SUSFS_SB_HASH_BITS);
static LIST_HEAD(ksu_susfs_parent_list);
static DEFINE_MUTEX(ksu_susfs_lock);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_active);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_redirect_active);
static atomic_t ksu_susfs_rule_count = ATOMIC_INIT(0);
static atomic_t ksu_susfs_redirect_count = ATOMIC_INIT(0);
static bool ksu_susfs_open_redirect_ready __read_mostly;

#define __ksu_susfs_get(ptr, type, member)                                   \
	({                                                                    \
		type *__target = NULL;                                        \
		u64 __sig = 0;                                                \
		if (likely(ptr)) {                                            \
			type *__outer = container_of(ptr, type, member);      \
			if (copy_from_kernel_nofault(&__sig,                  \
					     &__outer->signature,         \
					     sizeof(__sig)) == 0 &&       \
			    __sig == KSU_SUSFS_SIGNATURE) {                 \
				__target = __outer;                         \
			}                                                     \
		}                                                             \
		__target;                                                     \
	})

static u32 ksu_susfs_hash_path_len(const char *path, size_t len)
{
	return jhash(path, len, 0);
}

static u32 ksu_susfs_hash_path(const char *path)
{
	return ksu_susfs_hash_path_len(path, strlen(path));
}

static bool ksu_susfs_should_skip(void)
{
	if (!static_branch_unlikely(&ksu_susfs_active)) {
		return true;
	}
	if (unlikely(in_interrupt() || oops_in_progress)) {
		return true;
	}
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING))) {
		return true;
	}
	return false;
}

static bool ksu_susfs_should_hide_current(void)
{
	uid_t uid;

	if (ksu_susfs_should_skip()) {
		return false;
	}

	uid = current_uid().val;
	if (!is_appuid(uid) && !is_isolated_process(uid)) {
		return false;
	}

	return ksu_uid_should_umount(uid);
}

bool ksu_susfs_path_filter_active(void)
{
	return ksu_susfs_should_hide_current();
}

bool ksu_susfs_should_hide_path(const char *path, size_t len)
{
	struct ksu_susfs_rule *rule;
	u32 hash;
	bool hidden = false;

	if (!path || !len || len >= KSU_SUSFS_MAX_PATHNAME ||
	    !ksu_susfs_path_filter_active()) {
		return false;
	}
	while (len > 1 && path[len - 1] == '/')
		len--;

	hash = ksu_susfs_hash_path_len(path, len);
	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_susfs_rules_ht, rule, path_node, hash) {
		if (rule->path_hash == hash &&
		    rule->type == KSU_SUSFS_RULE_HIDE &&
		    rule->visible_path[len] == '\0' &&
		    !memcmp(rule->visible_path, path, len)) {
			hidden = true;
			break;
		}
	}
	rcu_read_unlock();

	return hidden;
}

/* The caller has already established that the current task is filtered. */
bool ksu_susfs_relative_hide_rule_may_match(const char *path, size_t len)
{
	const char *name;
	struct ksu_susfs_rule *rule;
	size_t name_len;
	u32 hash;
	bool found = false;

	if (!path || !len || path[0] == '/' || len >= KSU_SUSFS_MAX_PATHNAME)
		return false;
	while (len && path[len - 1] == '/')
		len--;
	if (!len)
		return false;
	name = path + len;
	while (name > path && name[-1] != '/')
		name--;
	name_len = path + len - name;
	if (!name_len)
		return false;
	hash = ksu_susfs_hash_path_len(name, name_len);
	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_susfs_names_ht, rule, name_node, hash) {
		if (rule->name_hash == hash &&
		    rule->type == KSU_SUSFS_RULE_HIDE &&
		    rule->name[name_len] == '\0' &&
		    !memcmp(rule->name, name, name_len)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static bool ksu_susfs_uid_scheme_matches(int uid_scheme)
{
	uid_t uid;

	if (ksu_susfs_should_skip()) {
		return false;
	}

	uid = current_uid().val;

	switch (uid_scheme) {
	case KSU_SUSFS_UID_NON_APP_PROC:
		return (uid % PER_USER_RANGE) < FIRST_APPLICATION_UID;
	case KSU_SUSFS_UID_ROOT_PROC_EXCEPT_SU_PROC:
		return uid == 0 && !is_ksu_domain();
	case KSU_SUSFS_UID_NON_SU_PROC:
		return !is_ksu_domain();
	case KSU_SUSFS_UID_UMOUNTED_APP_PROC:
		return (is_appuid(uid) || is_isolated_process(uid)) &&
		       ksu_uid_should_umount(uid);
	case KSU_SUSFS_UID_UMOUNTED_PROC:
		return (uid == 0 && !is_ksu_domain()) ||
		       ksu_uid_should_umount(uid);
	default:
		return false;
	}
}

static int ksu_susfs_normalize_path(char *dst, size_t dst_size, const char *src)
{
	size_t len;

	if (!src || !*src || src[0] != '/') {
		return -EINVAL;
	}

	if (strscpy(dst, src, dst_size) < 0) {
		return -ENAMETOOLONG;
	}

	len = strlen(dst);
	while (len > 1 && dst[len - 1] == '/') {
		dst[len - 1] = '\0';
		len--;
	}

	return 0;
}

static int ksu_susfs_split_path(const char *path, char *parent, size_t parent_size,
				char *name, size_t name_size)
{
	const char *slash;
	size_t parent_len;

	if (!path || path[0] != '/' || path[1] == '\0') {
		return -EINVAL;
	}

	slash = strrchr(path, '/');
	if (!slash || slash[1] == '\0') {
		return -EINVAL;
	}

	if (strscpy(name, slash + 1, name_size) < 0) {
		return -ENAMETOOLONG;
	}

	if (slash == path) {
		return strscpy(parent, "/", parent_size) < 0 ? -ENAMETOOLONG : 0;
	}

	parent_len = slash - path;
	if (parent_len >= parent_size) {
		return -ENAMETOOLONG;
	}

	memcpy(parent, path, parent_len);
	parent[parent_len] = '\0';
	return 0;
}

static int ksu_susfs_resolve_path(const char *path, struct path *out)
{
	const struct cred *saved;
	int err;

	saved = override_creds(ksu_cred);
	err = kern_path(path, 0, out);
	revert_creds(saved);
	return err;
}

static struct ksu_susfs_parent *ksu_susfs_find_parent_locked(const char *path)
{
	struct ksu_susfs_parent *parent;
	u32 hash = ksu_susfs_hash_path(path);

	hash_for_each_possible(ksu_susfs_parents_ht, parent, node, hash) {
		if (!strcmp(parent->path, path)) {
			return parent;
		}
	}

	return NULL;
}

static struct ksu_susfs_rule *ksu_susfs_find_rule_locked(const char *path)
{
	struct ksu_susfs_rule *rule;
	u32 hash = ksu_susfs_hash_path(path);

	hash_for_each_possible(ksu_susfs_rules_ht, rule, path_node, hash) {
		if (!strcmp(rule->visible_path, path)) {
			return rule;
		}
	}

	return NULL;
}

static struct ksu_susfs_rule *
ksu_susfs_lookup_rule_rcu(struct ksu_susfs_parent *parent, const char *name,
			  size_t len)
{
	struct ksu_susfs_rule *rule;

	list_for_each_entry_rcu(rule, &parent->rules, parent_list) {
		if (rule->name[len] == '\0' &&
		    !memcmp(rule->name, name, len)) {
			return rule;
		}
	}

	return NULL;
}

static bool ksu_susfs_parent_has_hide_rules_rcu(struct ksu_susfs_parent *parent)
{
	struct ksu_susfs_rule *rule;

	list_for_each_entry_rcu(rule, &parent->rules, parent_list) {
		if (rule->type == KSU_SUSFS_RULE_HIDE) {
			return true;
		}
	}

	return false;
}

static void ksu_susfs_invalidate_path(const char *path, const char *parent_path)
{
	struct path resolved;

	if (!ksu_susfs_resolve_path(path, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		d_drop(resolved.dentry);
		path_put(&resolved);
		return;
	}

	if (!ksu_susfs_resolve_path(parent_path, &resolved)) {
		shrink_dcache_parent(resolved.dentry);
		path_put(&resolved);
	}
}

static struct ksu_susfs_rule *
ksu_susfs_lookup_redirect_target_rcu(struct inode *inode)
{
	struct ksu_susfs_rule *rule;

	hash_for_each_possible_rcu(ksu_susfs_redirect_targets_ht, rule,
				   redirect_target_node, inode->i_ino) {
		if (rule->type == KSU_SUSFS_RULE_REDIRECT &&
		    rule->target_ino == inode->i_ino &&
		    rule->target_dev == inode->i_sb->s_dev &&
		    ksu_susfs_uid_scheme_matches(rule->uid_scheme))
			return rule;
	}

	return NULL;
}

static struct ksu_susfs_rule *
ksu_susfs_lookup_redirect_backend_rcu(struct inode *inode)
{
	struct ksu_susfs_rule *rule;

	hash_for_each_possible_rcu(ksu_susfs_redirect_backends_ht, rule,
				   redirect_backend_node, inode->i_ino) {
		if (rule->type == KSU_SUSFS_RULE_REDIRECT &&
		    rule->backend_ino == inode->i_ino &&
		    rule->backend_dev == inode->i_sb->s_dev &&
		    ksu_susfs_uid_scheme_matches(rule->uid_scheme))
			return rule;
	}

	return NULL;
}

bool ksu_susfs_open_redirect_active(void)
{
	return READ_ONCE(ksu_susfs_open_redirect_ready) &&
	       static_branch_unlikely(&ksu_susfs_redirect_active);
}

bool ksu_susfs_open_redirect_runtime_ready(void)
{
	return READ_ONCE(ksu_susfs_open_redirect_ready);
}

void ksu_susfs_set_open_redirect_ready(bool ready)
{
	WRITE_ONCE(ksu_susfs_open_redirect_ready, ready);
	pr_info("susfs: open_redirect runtime hook %s\n",
		ready ? "ready" : "unavailable");
}

struct filename *ksu_susfs_open_redirect_getname(struct inode *inode)
{
	struct ksu_susfs_rule *rule;
	char backend_path[KSU_SUSFS_MAX_PATHNAME] = { };
	bool matched = false;

	if (!inode || !inode->i_mapping || !ksu_susfs_open_redirect_active() ||
	    !test_bit(KSU_SUSFS_AS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return NULL;

	rcu_read_lock();
	rule = ksu_susfs_lookup_redirect_target_rcu(inode);
	if (rule &&
	    strscpy(backend_path, rule->backend_path,
		    sizeof(backend_path)) >= 0)
		matched = true;
	rcu_read_unlock();

	return matched ? getname_kernel(backend_path) : NULL;
}

bool ksu_susfs_open_redirect_apply_kstat(struct inode *inode,
					struct kstat *stat)
{
	struct ksu_susfs_rule *rule;
	bool applied = false;

	if (!inode || !inode->i_mapping || !stat ||
	    !ksu_susfs_open_redirect_active() ||
	    !test_bit(KSU_SUSFS_AS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return false;

	rcu_read_lock();
	rule = ksu_susfs_lookup_redirect_backend_rcu(inode);
	if (rule && rule->has_visible_stat) {
		*stat = rule->visible_stat;
		applied = true;
	}
	rcu_read_unlock();

	return applied;
}

bool ksu_susfs_open_redirect_apply_kstat_identity(struct kstat *stat)
{
	struct ksu_susfs_rule *rule;
	bool applied = false;
	unsigned long ino;
	dev_t dev;

	if (!stat || !ksu_susfs_open_redirect_active())
		return false;

	ino = stat->ino;
	dev = stat->dev;
	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_susfs_redirect_backends_ht, rule,
				   redirect_backend_node, ino) {
		if (rule->type != KSU_SUSFS_RULE_REDIRECT ||
		    rule->backend_ino != ino || rule->backend_dev != dev ||
		    !rule->has_visible_stat ||
		    !ksu_susfs_uid_scheme_matches(rule->uid_scheme))
			continue;
		*stat = rule->visible_stat;
		applied = true;
		break;
	}
	rcu_read_unlock();

	return applied;
}

bool ksu_susfs_open_redirect_spoof_inode_identity(struct inode *inode,
						  dev_t *dev,
						  unsigned long *ino)
{
	struct ksu_susfs_rule *rule;
	bool applied = false;

	if (!inode || !inode->i_mapping || !dev || !ino ||
	    !ksu_susfs_open_redirect_active() ||
	    !test_bit(KSU_SUSFS_AS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return false;

	rcu_read_lock();
	rule = ksu_susfs_lookup_redirect_backend_rcu(inode);
	if (rule && rule->has_visible_stat) {
		*dev = rule->visible_stat.dev;
		*ino = rule->visible_stat.ino;
		applied = true;
	}
	rcu_read_unlock();

	return applied;
}

bool ksu_susfs_open_redirect_apply_statfs(struct inode *inode,
					 struct kstatfs *statfs)
{
	struct ksu_susfs_rule *rule;
	bool applied = false;

	if (!inode || !inode->i_mapping || !statfs ||
	    !ksu_susfs_open_redirect_active() ||
	    !test_bit(KSU_SUSFS_AS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return false;

	rcu_read_lock();
	rule = ksu_susfs_lookup_redirect_backend_rcu(inode);
	if (rule) {
		*statfs = rule->visible_statfs;
		applied = true;
	}
	rcu_read_unlock();

	return applied;
}

char *ksu_susfs_open_redirect_dpath(const struct path *path, char *buf,
				    int buflen)
{
	struct ksu_susfs_rule *rule;
	struct inode *inode;
	char *result = NULL;
	size_t len;

	if (!path || !path->dentry || !buf || buflen <= 0 ||
	    !ksu_susfs_open_redirect_active())
		return NULL;

	inode = d_backing_inode(path->dentry);
	if (!inode || !inode->i_mapping ||
	    !test_bit(KSU_SUSFS_AS_OPEN_REDIRECT, &inode->i_mapping->flags))
		return NULL;

	rcu_read_lock();
	rule = ksu_susfs_lookup_redirect_backend_rcu(inode);
	if (rule) {
		len = strlen(rule->visible_path);
		if (len < buflen) {
			result = buf + buflen - len - 1;
			memcpy(result, rule->visible_path, len + 1);
		}
	}
	rcu_read_unlock();

	return result;
}

static int ksu_susfs_call_iterate(const struct file_operations *fops,
				  struct file *file, struct dir_context *ctx)
{
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
	if (fops->iterate_shared)
		return fops->iterate_shared(file, ctx);
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
	if (fops->iterate)
		return fops->iterate(file, ctx);
#endif
	return -ENOTDIR;
}

static KSU_SUSFS_ACTOR_RET
ksu_susfs_actor_proxy(struct dir_context *ctx, const char *name, int namelen,
			      loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksu_susfs_proxy_ctx *proxy =
		container_of(ctx, struct ksu_susfs_proxy_ctx, ctx);
	struct ksu_susfs_rule *rule;
	KSU_SUSFS_ACTOR_RET ret;

	rcu_read_lock();
	rule = ksu_susfs_lookup_rule_rcu(proxy->parent, name, namelen);
	if (rule && rule->type == KSU_SUSFS_RULE_HIDE &&
	    ksu_susfs_should_hide_current()) {
		rcu_read_unlock();
		return KSU_SUSFS_ACTOR_CONTINUE;
	}
	rcu_read_unlock();

	proxy->orig_ctx->pos = proxy->ctx.pos;
	ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset, ino,
				     d_type);
	proxy->ctx.pos = proxy->orig_ctx->pos;
	return ret;
}

static int ksu_susfs_hijacked_iterate_shared(struct file *file,
						     struct dir_context *ctx)
{
	struct ksu_susfs_fop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&file->f_op),
				struct ksu_susfs_fop, fake_fop);
	struct ksu_susfs_proxy_ctx proxy_ctx;
	bool susfs_active;
	int ret;

	if (!wrapped || !wrapped->orig_fop) {
		return -ENOTDIR;
	}

	susfs_active = false;
	if (ksu_susfs_should_hide_current()) {
		rcu_read_lock();
		susfs_active =
			ksu_susfs_parent_has_hide_rules_rcu(wrapped->parent);
		rcu_read_unlock();
	}
	if (!susfs_active) {
		goto do_real_iterate;
	}

	memset(&proxy_ctx, 0, sizeof(proxy_ctx));
	proxy_ctx.ctx.actor = ksu_susfs_actor_proxy;
	proxy_ctx.ctx.pos = ctx->pos;
	proxy_ctx.orig_ctx = ctx;
	proxy_ctx.parent = wrapped->parent;

	ret = ksu_susfs_call_iterate(wrapped->orig_fop, file, &proxy_ctx.ctx);
	ctx->pos = proxy_ctx.ctx.pos;
	return ret;

do_real_iterate:
	return ksu_susfs_call_iterate(wrapped->orig_fop, file, ctx);
}

#ifdef KSU_SUSFS_HAS_ITERATE
static int ksu_susfs_hijacked_iterate(struct file *file, struct dir_context *ctx)
{
	return ksu_susfs_hijacked_iterate_shared(file, ctx);
}
#endif

static struct dentry *ksu_susfs_hijacked_lookup(struct inode *dir,
						struct dentry *dentry,
						unsigned int flags)
{
	struct ksu_susfs_iop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&dir->i_op),
				struct ksu_susfs_iop, fake_iop);
	struct ksu_susfs_rule *rule;

	if (!wrapped || !wrapped->orig_iop)
		return ERR_PTR(-EOPNOTSUPP);

	if (!ksu_susfs_should_skip()) {
		rcu_read_lock();
		rule = ksu_susfs_lookup_rule_rcu(wrapped->parent,
						 dentry->d_name.name,
						 dentry->d_name.len);
		if (rule && rule->type == KSU_SUSFS_RULE_HIDE &&
		    ksu_susfs_should_hide_current()) {
			rcu_read_unlock();
			/* Do not install a global negative dentry for a per-task
			 * policy decision; that would leak the hidden result to
			 * unrelated UIDs through the shared dcache. */
			return ERR_PTR(-ENOENT);
		}
		rcu_read_unlock();
	}

	if (wrapped->orig_iop->lookup)
		return wrapped->orig_iop->lookup(dir, dentry, flags);

	return ERR_PTR(-EOPNOTSUPP);
}

static void ksu_susfs_hijacked_destroy_inode(struct inode *inode)
{
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;
	struct ksu_susfs_sop *wrapped_sop;

	wrapped_iop = __ksu_susfs_get(smp_load_acquire(&inode->i_op),
				      struct ksu_susfs_iop, fake_iop);
	if (wrapped_iop) {
		if (wrapped_iop->parent) {
			wrapped_iop->parent->dir_inode = NULL;
		}
		inode->i_op = wrapped_iop->orig_iop;
		if (!wrapped_iop->had_private_flag) {
			inode->i_flags &= ~S_PRIVATE;
		}
		kfree_rcu(wrapped_iop, rcu);
	}

	wrapped_fop = __ksu_susfs_get(smp_load_acquire(&inode->i_fop),
				      struct ksu_susfs_fop, fake_fop);
	if (wrapped_fop) {
		if (wrapped_fop->parent) {
			wrapped_fop->parent->dir_inode = NULL;
		}
		inode->i_fop = wrapped_fop->orig_fop;
		kfree_rcu(wrapped_fop, rcu);
	}

	wrapped_sop = __ksu_susfs_get(smp_load_acquire(&inode->i_sb->s_op),
				      struct ksu_susfs_sop, fake_sop);
	if (wrapped_sop && wrapped_sop->orig_sop &&
	    wrapped_sop->orig_sop->destroy_inode) {
		wrapped_sop->orig_sop->destroy_inode(inode);
	}
}

static void ksu_susfs_hijacked_put_super(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped =
		__ksu_susfs_get(smp_load_acquire(&sb->s_op),
				struct ksu_susfs_sop, fake_sop);
	void (*orig_put_super)(struct super_block *);

	if (!wrapped) {
		return;
	}

	orig_put_super = wrapped->orig_sop->put_super;
	hash_del_rcu(&wrapped->node);
	smp_store_release(&sb->s_op, wrapped->orig_sop);

	kfree_rcu(wrapped, rcu);

	if (orig_put_super) {
		orig_put_super(sb);
	}
}

static void ksu_susfs_restore_superblock_one(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped;

	if (!sb) {
		return;
	}

	wrapped = __ksu_susfs_get(smp_load_acquire(&sb->s_op),
				  struct ksu_susfs_sop, fake_sop);
	if (!wrapped) {
		return;
	}

	hash_del_rcu(&wrapped->node);
	smp_store_release(&sb->s_op, wrapped->orig_sop);

	kfree_rcu(wrapped, rcu);
}

static int ksu_susfs_hijack_superblock(struct super_block *sb)
{
	struct ksu_susfs_sop *wrapped;

	if (!sb || !sb->s_op) {
		return -EINVAL;
	}

	if (__ksu_susfs_get(smp_load_acquire(&sb->s_op),
			    struct ksu_susfs_sop, fake_sop)) {
		return 0;
	}

	wrapped = kzalloc(sizeof(*wrapped), GFP_KERNEL);
	if (!wrapped) {
		return -ENOMEM;
	}

	memcpy(&wrapped->fake_sop, sb->s_op, sizeof(struct super_operations));
	wrapped->orig_sop = sb->s_op;
	wrapped->signature = KSU_SUSFS_SIGNATURE;
	wrapped->sb = sb;
	wrapped->fake_sop.destroy_inode = ksu_susfs_hijacked_destroy_inode;
	wrapped->fake_sop.put_super = ksu_susfs_hijacked_put_super;

	hash_add_rcu(ksu_susfs_sb_ht, &wrapped->node, (unsigned long)sb);
	smp_store_release(&sb->s_op, &wrapped->fake_sop);
	return 1;
}

static int ksu_susfs_hijack_parent_inode(struct ksu_susfs_parent *parent,
					 struct inode *inode)
{
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;

	if (!inode->i_op || !inode->i_op->lookup) {
		return -EOPNOTSUPP;
	}

	if (!__ksu_susfs_get(smp_load_acquire(&inode->i_op),
			     struct ksu_susfs_iop, fake_iop)) {
		wrapped_iop = kzalloc(sizeof(*wrapped_iop), GFP_KERNEL);
		if (!wrapped_iop) {
			return -ENOMEM;
		}

		memcpy(&wrapped_iop->fake_iop, inode->i_op,
		       sizeof(struct inode_operations));
		wrapped_iop->orig_iop = inode->i_op;
		wrapped_iop->signature = KSU_SUSFS_SIGNATURE;
		wrapped_iop->parent = parent;
		wrapped_iop->had_private_flag =
			(inode->i_flags & S_PRIVATE) != 0;
		wrapped_iop->fake_iop.lookup = ksu_susfs_hijacked_lookup;
		smp_store_release(&inode->i_op, &wrapped_iop->fake_iop);
		inode->i_flags |= S_PRIVATE;
	}

	if (inode->i_fop &&
	    !__ksu_susfs_get(smp_load_acquire(&inode->i_fop),
			     struct ksu_susfs_fop, fake_fop)) {
		wrapped_fop = kzalloc(sizeof(*wrapped_fop), GFP_KERNEL);
		if (!wrapped_fop) {
			return -ENOMEM;
		}

		memcpy(&wrapped_fop->fake_fop, inode->i_fop,
		       sizeof(struct file_operations));
		wrapped_fop->orig_fop = inode->i_fop;
		wrapped_fop->signature = KSU_SUSFS_SIGNATURE;
		wrapped_fop->parent = parent;

#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
		if (wrapped_fop->fake_fop.iterate_shared) {
			wrapped_fop->fake_fop.iterate_shared =
				ksu_susfs_hijacked_iterate_shared;
		}
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
		else if (wrapped_fop->fake_fop.iterate) {
#else
		if (wrapped_fop->fake_fop.iterate) {
#endif
			wrapped_fop->fake_fop.iterate =
				ksu_susfs_hijacked_iterate;
		}
#endif
		smp_store_release(&inode->i_fop, &wrapped_fop->fake_fop);
	}

	return 0;
}

static void ksu_susfs_unhijack_parent_inode(struct ksu_susfs_parent *parent,
					    struct inode *inode)
{
	struct ksu_susfs_iop *wrapped_iop;
	struct ksu_susfs_fop *wrapped_fop;

	if (!inode) {
		parent->dir_inode = NULL;
		return;
	}

	spin_lock(&inode->i_lock);
	wrapped_iop = __ksu_susfs_get(smp_load_acquire(&inode->i_op),
				      struct ksu_susfs_iop, fake_iop);
	if (wrapped_iop && wrapped_iop->parent == parent) {
		smp_store_release(&inode->i_op, wrapped_iop->orig_iop);
		if (!wrapped_iop->had_private_flag) {
			inode->i_flags &= ~S_PRIVATE;
		}
		kfree_rcu(wrapped_iop, rcu);
	}

	wrapped_fop = __ksu_susfs_get(smp_load_acquire(&inode->i_fop),
				      struct ksu_susfs_fop, fake_fop);
	if (wrapped_fop && wrapped_fop->parent == parent) {
		smp_store_release(&inode->i_fop, wrapped_fop->orig_fop);
		kfree_rcu(wrapped_fop, rcu);
	}
	spin_unlock(&inode->i_lock);

	parent->dir_inode = NULL;
}

static void ksu_susfs_restore_parent(struct ksu_susfs_parent *parent)
{
	struct inode *inode = parent->dir_inode;
	struct dentry *alias;

	if (!inode) {
		return;
	}

	if (!igrab(inode)) {
		parent->dir_inode = NULL;
		return;
	}

	ksu_susfs_unhijack_parent_inode(parent, inode);

	alias = d_find_alias(inode);
	if (alias) {
		shrink_dcache_parent(alias);
		d_drop(alias);
		dput(alias);
	}

	iput(inode);
	parent->dir_inode = NULL;
}

static void ksu_susfs_restore_superblocks(void)
{
	struct ksu_susfs_sop *wrapped;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(ksu_susfs_sb_ht, bkt, tmp, wrapped, node) {
		ksu_susfs_restore_superblock_one(wrapped->sb);
	}
}

static int ksu_susfs_attach_parent_locked(struct ksu_susfs_parent *parent)
{
	struct path resolved;
	struct inode *inode;
	int sb_hijacked;
	int err;

	if (parent->dir_inode) {
		return 0;
	}

	err = ksu_susfs_resolve_path(parent->path, &resolved);
	if (err) {
		return err;
	}

	inode = d_backing_inode(resolved.dentry);
	if (!inode || !S_ISDIR(inode->i_mode)) {
		path_put(&resolved);
		return -ENOTDIR;
	}

	sb_hijacked = ksu_susfs_hijack_superblock(inode->i_sb);
	if (sb_hijacked < 0) {
		path_put(&resolved);
		return sb_hijacked;
	}

	err = ksu_susfs_hijack_parent_inode(parent, inode);
	if (err) {
		ksu_susfs_unhijack_parent_inode(parent, inode);
		if (sb_hijacked > 0) {
			ksu_susfs_restore_superblock_one(inode->i_sb);
		}
		path_put(&resolved);
		return err;
	}

	parent->dir_inode = inode;
	path_put(&resolved);
	return 0;
}

static int ksu_susfs_validate_redirect(const char *visible_path,
				       const char *backend_path,
				       struct kstat *visible_stat,
				       struct kstatfs *visible_statfs,
				       struct inode **target_inode_out,
				       struct inode **backend_inode_out)
{
	struct path visible;
	struct path backend;
	struct inode *visible_inode;
	struct inode *backend_inode;
	int err;

	*target_inode_out = NULL;
	*backend_inode_out = NULL;

	err = ksu_susfs_resolve_path(visible_path, &visible);
	if (err) {
		return err;
	}

	err = ksu_susfs_resolve_path(backend_path, &backend);
	if (err) {
		path_put(&visible);
		return err;
	}

	visible_inode = d_backing_inode(visible.dentry);
	backend_inode = d_backing_inode(backend.dentry);

	if (!visible_inode || !visible_inode->i_mapping || !backend_inode ||
	    !backend_inode->i_mapping) {
		err = -ENOENT;
		goto out;
	}

	if (visible_inode->i_sb->s_magic == FUSE_SUPER_MAGIC ||
	    backend_inode->i_sb->s_magic == FUSE_SUPER_MAGIC) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if ((!S_ISREG(visible_inode->i_mode) && !S_ISDIR(visible_inode->i_mode)) ||
	    (!S_ISREG(backend_inode->i_mode) && !S_ISDIR(backend_inode->i_mode))) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (!!S_ISDIR(visible_inode->i_mode) != !!S_ISDIR(backend_inode->i_mode)) {
		err = -EINVAL;
		goto out;
	}

	if (visible_stat) {
#ifdef STATX_BASIC_STATS
		err = vfs_getattr(&visible, visible_stat,
				  STATX_BASIC_STATS | STATX_BTIME,
				  AT_STATX_SYNC_AS_STAT);
#else
		err = vfs_getattr(&visible, visible_stat);
#endif
		if (err)
			goto out;
		if (!visible_stat->ino)
			visible_stat->ino = visible_inode->i_ino;
	}
	if (visible_statfs) {
		err = vfs_statfs(&visible, visible_statfs);
		if (err)
			goto out;
	}

	*target_inode_out = igrab(visible_inode);
	*backend_inode_out = igrab(backend_inode);
	if (!*target_inode_out || !*backend_inode_out) {
		if (*target_inode_out) {
			iput(*target_inode_out);
			*target_inode_out = NULL;
		}
		if (*backend_inode_out) {
			iput(*backend_inode_out);
			*backend_inode_out = NULL;
		}
		err = -ESTALE;
		goto out;
	}

	err = 0;

out:
	path_put(&backend);
	path_put(&visible);
	return err;
}

static int ksu_susfs_add_rule(const char *visible_path, const char *backend_path,
			      int uid_scheme, bool allow_missing_target)
{
	struct ksu_susfs_parent *parent;
	struct ksu_susfs_rule *rule;
	char normalized_visible[KSU_SUSFS_MAX_PATHNAME];
	char normalized_backend[KSU_SUSFS_MAX_PATHNAME];
	char parent_path[KSU_SUSFS_MAX_PATHNAME];
	char name[KSU_SUSFS_MAX_PATHNAME];
	struct kstat visible_stat = { };
	struct kstatfs visible_statfs = { };
	struct inode *target_inode = NULL;
	struct inode *redirected_inode = NULL;
	int err;
	bool has_visible_stat = false;
	bool new_parent = false;

	err = ksu_susfs_normalize_path(normalized_visible,
				       sizeof(normalized_visible), visible_path);
	if (err) {
		return err;
	}

	err = ksu_susfs_split_path(normalized_visible, parent_path,
				   sizeof(parent_path), name, sizeof(name));
	if (err) {
		return err;
	}

	if (!allow_missing_target) {
		struct path resolved;

		err = ksu_susfs_resolve_path(normalized_visible, &resolved);
		if (err) {
			return err;
		}
		path_put(&resolved);
	}

	if (!backend_path) {
		normalized_backend[0] = '\0';
	} else {
		if (!READ_ONCE(ksu_susfs_open_redirect_ready))
			return -EOPNOTSUPP;
		err = ksu_susfs_normalize_path(normalized_backend,
					       sizeof(normalized_backend),
					       backend_path);
		if (err) {
			return err;
		}

		err = ksu_susfs_validate_redirect(normalized_visible,
						  normalized_backend,
						  &visible_stat,
						  &visible_statfs,
						  &target_inode,
						  &redirected_inode);
		if (err) {
			return err;
		}
		has_visible_stat = true;
	}

	mutex_lock(&ksu_susfs_lock);

	if (ksu_susfs_find_rule_locked(normalized_visible)) {
		err = -EEXIST;
		goto out_unlock;
	}

	parent = ksu_susfs_find_parent_locked(parent_path);
	if (!parent) {
		parent = kzalloc(sizeof(*parent), GFP_KERNEL);
		if (!parent) {
			err = -ENOMEM;
			goto out_unlock;
		}

		INIT_LIST_HEAD(&parent->all_list);
		INIT_LIST_HEAD(&parent->rules);
		if (strscpy(parent->path, parent_path, sizeof(parent->path)) < 0) {
			kfree(parent);
			err = -ENAMETOOLONG;
			goto out_unlock;
		}

		hash_add(ksu_susfs_parents_ht, &parent->node,
			 ksu_susfs_hash_path(parent->path));
		list_add_tail(&parent->all_list, &ksu_susfs_parent_list);
		new_parent = true;
	}

	if (!backend_path) {
		err = ksu_susfs_attach_parent_locked(parent);
		if (err) {
			if (new_parent) {
				hash_del(&parent->node);
				list_del(&parent->all_list);
				kfree(parent);
			}
			goto out_unlock;
		}
	}

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule) {
		err = -ENOMEM;
		goto out_unwind_parent;
	}

	rule->path_hash = ksu_susfs_hash_path(normalized_visible);
	rule->name_hash = ksu_susfs_hash_path(name);
	rule->uid_scheme = uid_scheme;
	rule->type = backend_path ? KSU_SUSFS_RULE_REDIRECT :
				    KSU_SUSFS_RULE_HIDE;
	if (has_visible_stat) {
		rule->has_visible_stat = true;
		rule->visible_stat = visible_stat;
		rule->visible_statfs = visible_statfs;
	}
	INIT_LIST_HEAD(&rule->free_list);
	if (strscpy(rule->name, name, sizeof(rule->name)) < 0 ||
	    strscpy(rule->visible_path, normalized_visible,
		    sizeof(rule->visible_path)) < 0 ||
	    (backend_path &&
	     strscpy(rule->backend_path, normalized_backend,
		     sizeof(rule->backend_path)) < 0)) {
		kfree(rule);
		err = -ENAMETOOLONG;
		goto out_unwind_parent;
	}
	if (backend_path) {
		rule->target_inode = target_inode;
		rule->backend_inode = redirected_inode;
		target_inode = NULL;
		redirected_inode = NULL;
		rule->target_ino = rule->target_inode->i_ino;
		rule->target_dev = rule->target_inode->i_sb->s_dev;
		rule->backend_ino = rule->backend_inode->i_ino;
		rule->backend_dev = rule->backend_inode->i_sb->s_dev;
	}

	hash_add_rcu(ksu_susfs_rules_ht, &rule->path_node, rule->path_hash);
	hash_add_rcu(ksu_susfs_names_ht, &rule->name_node, rule->name_hash);
	list_add_tail_rcu(&rule->parent_list, &parent->rules);
	if (backend_path) {
		hash_add_rcu(ksu_susfs_redirect_targets_ht,
			     &rule->redirect_target_node, rule->target_ino);
		hash_add_rcu(ksu_susfs_redirect_backends_ht,
			     &rule->redirect_backend_node, rule->backend_ino);
		set_bit(KSU_SUSFS_AS_OPEN_REDIRECT,
			&rule->target_inode->i_mapping->flags);
		set_bit(KSU_SUSFS_AS_OPEN_REDIRECT,
			&rule->backend_inode->i_mapping->flags);
		if (atomic_inc_return(&ksu_susfs_redirect_count) == 1)
			static_branch_enable(&ksu_susfs_redirect_active);
	}
	if (atomic_inc_return(&ksu_susfs_rule_count) == 1) {
		static_branch_enable(&ksu_susfs_active);
	}

	err = 0;

out_unwind_parent:
	if (err && new_parent) {
		ksu_susfs_restore_parent(parent);
		hash_del(&parent->node);
		list_del(&parent->all_list);
		kfree(parent);
	}

out_unlock:
	mutex_unlock(&ksu_susfs_lock);
	if (target_inode)
		iput(target_inode);
	if (redirected_inode)
		iput(redirected_inode);
	if (!err && !backend_path) {
		ksu_susfs_invalidate_path(normalized_visible, parent_path);
	}
	return err;
}

static void ksu_susfs_clear_all(void)
{
	struct ksu_susfs_rule *rule;
	struct ksu_susfs_rule *rule_tmp;
	struct hlist_node *rule_hnode_tmp;
	struct ksu_susfs_parent *parent, *parent_tmp;
	LIST_HEAD(free_rules);
	LIST_HEAD(free_parents);
	int bkt;

	mutex_lock(&ksu_susfs_lock);

	hash_for_each_safe(ksu_susfs_rules_ht, bkt, rule_hnode_tmp, rule,
			   path_node) {
		hash_del_rcu(&rule->path_node);
		if (!hlist_unhashed(&rule->name_node)) {
			hash_del_rcu(&rule->name_node);
		}
		if (!hlist_unhashed(&rule->redirect_target_node))
			hash_del_rcu(&rule->redirect_target_node);
		if (!hlist_unhashed(&rule->redirect_backend_node))
			hash_del_rcu(&rule->redirect_backend_node);
		if (rule->target_inode && rule->target_inode->i_mapping)
			clear_bit(KSU_SUSFS_AS_OPEN_REDIRECT,
				  &rule->target_inode->i_mapping->flags);
		if (rule->backend_inode && rule->backend_inode->i_mapping)
			clear_bit(KSU_SUSFS_AS_OPEN_REDIRECT,
				  &rule->backend_inode->i_mapping->flags);
		list_del_rcu(&rule->parent_list);
		list_add_tail(&rule->free_list, &free_rules);
	}

	list_for_each_entry(parent, &ksu_susfs_parent_list, all_list) {
		ksu_susfs_restore_parent(parent);
	}
	ksu_susfs_restore_superblocks();

	list_for_each_entry_safe(parent, parent_tmp, &ksu_susfs_parent_list,
				 all_list) {
		hash_del(&parent->node);
		list_del(&parent->all_list);
		list_add_tail(&parent->all_list, &free_parents);
	}

	if (atomic_read(&ksu_susfs_rule_count) > 0) {
		atomic_set(&ksu_susfs_rule_count, 0);
		static_branch_disable(&ksu_susfs_active);
	}
	if (atomic_read(&ksu_susfs_redirect_count) > 0) {
		atomic_set(&ksu_susfs_redirect_count, 0);
		static_branch_disable(&ksu_susfs_redirect_active);
	}

	mutex_unlock(&ksu_susfs_lock);

	synchronize_rcu();

	list_for_each_entry_safe(rule, rule_tmp, &free_rules, free_list) {
		list_del(&rule->free_list);
		if (rule->target_inode)
			iput(rule->target_inode);
		if (rule->backend_inode)
			iput(rule->backend_inode);
		kfree(rule);
	}

	list_for_each_entry_safe(parent, parent_tmp, &free_parents, all_list) {
		list_del(&parent->all_list);
		kfree(parent);
	}
}

static bool ksu_susfs_compat_root_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain();
}

static bool ksu_susfs_handle_path_compat(void __user *arg, bool allow_missing)
{
	struct ksu_susfs_path_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.target_pathname[sizeof(cmd.target_pathname) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = ksu_susfs_add_rule(cmd.target_pathname, NULL, 0,
				     allow_missing);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: path compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_redirect_compat(void __user *arg)
{
	struct ksu_susfs_open_redirect_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	cmd.target_pathname[sizeof(cmd.target_pathname) - 1] = '\0';
	cmd.redirected_pathname[sizeof(cmd.redirected_pathname) - 1] = '\0';

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	if (cmd.uid_scheme < KSU_SUSFS_UID_NON_APP_PROC ||
	    cmd.uid_scheme > KSU_SUSFS_UID_UMOUNTED_PROC) {
		cmd.err = -EINVAL;
		goto out;
	}

	cmd.err = ksu_susfs_add_rule(cmd.target_pathname,
				     cmd.redirected_pathname,
				     cmd.uid_scheme, false);

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: redirect compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_version_compat(void __user *arg)
{
	struct ksu_susfs_version_cmd cmd = { .err = 0 };

	strscpy(cmd.susfs_version, KSU_SUSFS_VERSION,
		sizeof(cmd.susfs_version));
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: version compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_variant_compat(void __user *arg)
{
	struct ksu_susfs_variant_cmd cmd = { .err = 0 };

	strscpy(cmd.susfs_variant, KSU_SUSFS_VARIANT, sizeof(cmd.susfs_variant));
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: variant compat copy_to_user failed\n");
	}
	return true;
}

static bool ksu_susfs_handle_features_compat(void __user *arg)
{
	struct ksu_susfs_enabled_features_cmd *cmd;
	size_t len = 0;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		return true;
	}

	len += scnprintf(cmd->enabled_features + len,
			 sizeof(cmd->enabled_features) - len,
			 "hookless_vfs\nhookless_procfs\nsus_path\nsus_path_loop\n");
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	if (ksu_susfs_open_redirect_runtime_ready())
		len += scnprintf(cmd->enabled_features + len,
				 sizeof(cmd->enabled_features) - len,
				 "open_redirect\n");
	if (ksu_susfs_mount_runtime_available())
		len += scnprintf(cmd->enabled_features + len,
				 sizeof(cmd->enabled_features) - len,
				 "sus_mount\n");
	if (ksu_susfs_kstat_runtime_ready())
		len += scnprintf(cmd->enabled_features + len,
				 sizeof(cmd->enabled_features) - len,
				 "sus_kstat\n");
#else
	len += scnprintf(cmd->enabled_features + len,
			 sizeof(cmd->enabled_features) - len, "open_redirect\n"
			 "sus_mount\nsus_kstat\n");
#endif
	len += scnprintf(cmd->enabled_features + len,
			 sizeof(cmd->enabled_features) - len,
			 "sus_map\nspoof_cmdline_or_bootconfig\nspoof_uname\n"
			 "avc_log_spoofing\nproc_maps_kstat\nproc_smaps_kstat\n"
			 "proc_maps_hide\nproc_smaps_hide\nproc_fd_hide\n"
			 "proc_map_files_hide\n");
	if (copy_to_user(arg, cmd, sizeof(*cmd))) {
		pr_err("susfs: feature compat copy_to_user failed\n");
	}
	kfree(cmd);
	return true;
}

static bool ksu_susfs_handle_log_compat(void __user *arg)
{
	struct ksu_susfs_log_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return true;
	}

	if (!ksu_susfs_compat_root_allowed()) {
		cmd.err = -EPERM;
		goto out;
	}

	cmd.err = 0;

out:
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("susfs: log compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_compat(unsigned int cmd, void __user *arg)
{
	switch (cmd) {
	case KSU_SUSFS_CMD_ADD_SUS_PATH:
		return ksu_susfs_handle_path_compat(arg, false);
	case KSU_SUSFS_CMD_ADD_SUS_PATH_LOOP:
		return ksu_susfs_handle_path_compat(arg, true);
	case KSU_SUSFS_CMD_HIDE_SUS_MNTS_FOR_NON_SU_PROCS:
		return ksu_susfs_handle_mount_compat(arg);
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT:
	case KSU_SUSFS_CMD_UPDATE_SUS_KSTAT:
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT_STATICALLY:
		return ksu_susfs_handle_kstat_compat(cmd, arg);
	case KSU_SUSFS_CMD_ADD_SUS_MAP:
		return ksu_susfs_handle_sus_map_compat(arg);
	case KSU_SUSFS_CMD_ADD_OPEN_REDIRECT:
		return ksu_susfs_handle_redirect_compat(arg);
	case KSU_SUSFS_CMD_SET_UNAME:
		return ksu_susfs_handle_uname_compat(arg);
	case KSU_SUSFS_CMD_ENABLE_LOG:
		return ksu_susfs_handle_log_compat(arg);
	case KSU_SUSFS_CMD_SET_CMDLINE_OR_BOOTCONFIG:
		return ksu_susfs_handle_cmdline_compat(arg);
	case KSU_SUSFS_CMD_SHOW_VERSION:
		return ksu_susfs_handle_version_compat(arg);
	case KSU_SUSFS_CMD_SHOW_VARIANT:
		return ksu_susfs_handle_variant_compat(arg);
	case KSU_SUSFS_CMD_SHOW_ENABLED_FEATURES:
		return ksu_susfs_handle_features_compat(arg);
	case KSU_SUSFS_CMD_ENABLE_AVC_LOG_SPOOFING:
		return ksu_susfs_handle_avc_compat(arg);
	default:
		return false;
	}
}

void ksu_susfs_apply_default_rules(void)
{
	size_t i;
	int err;

	for (i = 0; i < ARRAY_SIZE(ksu_susfs_default_hide_paths); i++) {
		err = ksu_susfs_add_rule(ksu_susfs_default_hide_paths[i], NULL,
					 0, false);
		if (!err) {
			pr_info("susfs: default hide rule enabled for %s\n",
				ksu_susfs_default_hide_paths[i]);
			continue;
		}

		if (err == -ENOENT || err == -EEXIST) {
			continue;
		}

		pr_warn("susfs: failed to install default hide rule for %s: %d\n",
			ksu_susfs_default_hide_paths[i], err);
	}
}

void ksu_susfs_init(void)
{
	hash_init(ksu_susfs_rules_ht);
	hash_init(ksu_susfs_names_ht);
	hash_init(ksu_susfs_redirect_targets_ht);
	hash_init(ksu_susfs_redirect_backends_ht);
	hash_init(ksu_susfs_parents_ht);
	hash_init(ksu_susfs_sb_ht);
	atomic_set(&ksu_susfs_rule_count, 0);
	atomic_set(&ksu_susfs_redirect_count, 0);
	ksu_susfs_apply_default_rules();
	if (ksu_susfs_procfs_init()) {
		pr_warn("susfs: procfs runtime init returned non-zero\n");
	}
	if (ksu_susfs_kstat_init()) {
		pr_warn("susfs: kstat runtime init returned non-zero\n");
	}
	pr_info("susfs: hookless core initialized\n");
}

void ksu_susfs_exit(void)
{
	ksu_susfs_kstat_exit();
	ksu_susfs_procfs_exit();
	ksu_susfs_clear_all();
	pr_info("susfs: hookless core exited\n");
}
