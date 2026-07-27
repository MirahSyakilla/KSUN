#include <linux/atomic.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/hashtable.h>
#include <linux/interrupt.h>
#include <linux/jhash.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/overflow.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/task_work.h>

#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "nomount/nomount.h"
#include "susfs/compat.h"
#include "susfs/susfs.h"

#define KSU_NOMOUNT_MAGIC_POS ((loff_t)0x7000000000000000LL)
#define KSU_NOMOUNT_COMPAT_MAGIC_POS ((loff_t)0x7e000000)
#define KSU_NOMOUNT_MAGIC_WINDOW 100000
#define KSU_NOMOUNT_MAX_ANCESTORS 64
#define KSU_NOMOUNT_EMBEDDED_NAME_MAX \
	(KSU_NOMOUNT_MAX_PATH - offsetof(struct filename, iname))
#define KSU_NOMOUNT_CHILD_NATIVE (1U << 0)
#define KSU_NOMOUNT_CHILD_DELETED (1U << 7)
/* kern_path() leaves the terminal symlink unresolved when LOOKUP_FOLLOW is
 * absent.  Linux has no portable LOOKUP_NOFOLLOW flag, including this 5.4
 * tree, so give the zero-flags form an explicit local name. */
#define KSU_NOMOUNT_LOOKUP_NOFOLLOW 0

struct ksu_nomount_child {
	unsigned long ino;
	u32 name_offset;
	u32 name_hash;
	u16 name_len;
	u8 d_type;
	u8 flags;
};

struct ksu_nomount_child_array {
	atomic_t refcnt;
	u32 num_children;
	u32 live_children;
	u32 child_capacity;
	u32 heap_size;
	u32 heap_capacity;
	struct rcu_head rcu;
	struct ksu_nomount_child entries[];
};

struct ksu_nomount_inode_identity {
	unsigned long ino;
	dev_t dev;
};

struct ksu_nomount_parent {
	struct hlist_node path_node;
	struct hlist_node inode_node;
	struct list_head all_node;
	struct ksu_nomount_child_array __rcu *children;
	unsigned long ino;
	unsigned long visible_ino;
	dev_t dev;
	dev_t visible_dev;
	u32 fs_type;
	bool inode_hashed;
	bool internal;
	char *path;
};

struct ksu_nomount_parent_identity {
	unsigned long ino;
	unsigned long visible_ino;
	dev_t dev;
	dev_t visible_dev;
	u32 fs_type;
	bool inode_hashed;
	bool internal;
};

struct ksu_nomount_private_path {
	struct list_head node;
	struct hlist_node hash_node;
	unsigned long ino;
	dev_t dev;
	u16 len;
	u32 hash;
	char *path;
};

struct ksu_nomount_rule {
	struct hlist_node path_node;
	struct hlist_node real_node;
	struct hlist_node real_path_node;
	struct hlist_node basename_node;
	struct list_head gc_node;
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_inode_identity *ancestors;
	struct ksu_nomount_private_path *private_paths;
	u16 ancestor_count;
	u16 private_count;
	u16 virtual_len;
	u16 real_len;
	u16 basename_len;
	u32 child_index;
	u32 hash;
	u32 real_hash;
	u32 basename_hash;
	u32 flags;
	unsigned long visible_ino;
	unsigned long real_ino;
	dev_t visible_dev;
	dev_t real_dev;
	u32 fs_type;
	struct kstatfs visible_statfs;
	u8 d_type;
	bool visible_exists;
	bool has_visible_statfs;
	char *virtual_path;
	char *real_path;
	const char *name;
};

struct ksu_nomount_uid {
	struct hlist_node node;
	struct list_head gc_node;
	uid_t uid;
};

/* Stack-owned marker used while policy management resolves physical paths. */
struct ksu_nomount_bypass {
	struct hlist_node node;
	struct task_struct *task;
};

/*
 * Permission bridging is only valid while a task is resolving a pathname
 * that NoMount actually redirected.  Each scope carries only the redirected
 * backend inode and its ancestors, so one virtual pathname cannot authorize
 * a different private backend through a second pathname in the same syscall.
 */
struct ksu_nomount_access_scope {
	struct hlist_node node;
	struct callback_head task_work;
	struct task_struct *task;
	unsigned long real_ino;
	unsigned long visible_ino;
	dev_t real_dev;
	dev_t visible_dev;
	u16 ancestor_count;
	bool preserve_real_ino;
	bool permission_consumed;
	struct ksu_nomount_inode_identity ancestors[];
};

struct ksu_nomount_iter_ctx {
	struct dir_context ctx;
	struct dir_context *orig_ctx;
	struct ksu_nomount_child_array *children;
	unsigned long parent_ino;
	unsigned long visible_ino;
	unsigned long parent_visible_ino;
	dev_t parent_dev;
};

static DEFINE_HASHTABLE(ksu_nomount_rules, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_real_inodes, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_real_paths, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_basenames, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_private_paths_hash, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_parents, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_parent_inodes, KSU_NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_uids, KSU_NOMOUNT_UID_HASH_BITS);
static DEFINE_HASHTABLE(ksu_nomount_bypasses, 4);
static DEFINE_HASHTABLE(ksu_nomount_access_scopes, 4);
static DEFINE_HASHTABLE(ksu_nomount_lookup_scopes, 4);
static LIST_HEAD(ksu_nomount_parent_list);
static LIST_HEAD(ksu_nomount_private_paths);
static DEFINE_MUTEX(ksu_nomount_lock);
static DEFINE_SPINLOCK(ksu_nomount_bypass_lock);
static DEFINE_SPINLOCK(ksu_nomount_access_scope_lock);
static DEFINE_SPINLOCK(ksu_nomount_lookup_scope_lock);
static atomic_t ksu_nomount_rule_count = ATOMIC_INIT(0);
static atomic_t ksu_nomount_uid_count = ATOMIC_INIT(0);
static atomic_t ksu_nomount_bypass_count = ATOMIC_INIT(0);
static atomic_t ksu_nomount_access_scope_count = ATOMIC_INIT(0);
static DEFINE_STATIC_KEY_FALSE(ksu_nomount_active_rules);
static DEFINE_STATIC_KEY_FALSE(ksu_nomount_active_uids);

static u32 ksu_nomount_hash_path_len(const char *path, size_t len)
{
	return jhash(path, len, 0);
}

static u32 ksu_nomount_hash_path(const char *path)
{
	return ksu_nomount_hash_path_len(path, strlen(path));
}

static void ksu_nomount_bypass_enter(struct ksu_nomount_bypass *bypass)
{
	unsigned long irq_flags;

	bypass->task = current;
	spin_lock_irqsave(&ksu_nomount_bypass_lock, irq_flags);
	hash_add(ksu_nomount_bypasses, &bypass->node,
		 (unsigned long)bypass->task);
	atomic_inc(&ksu_nomount_bypass_count);
	spin_unlock_irqrestore(&ksu_nomount_bypass_lock, irq_flags);
}

static void ksu_nomount_bypass_exit(struct ksu_nomount_bypass *bypass)
{
	unsigned long irq_flags;

	spin_lock_irqsave(&ksu_nomount_bypass_lock, irq_flags);
	hash_del(&bypass->node);
	atomic_dec(&ksu_nomount_bypass_count);
	spin_unlock_irqrestore(&ksu_nomount_bypass_lock, irq_flags);
}

static bool ksu_nomount_current_bypassed(void)
{
	struct ksu_nomount_bypass *bypass;
	unsigned long irq_flags;
	bool found = false;

	if (!atomic_read(&ksu_nomount_bypass_count))
		return false;
	spin_lock_irqsave(&ksu_nomount_bypass_lock, irq_flags);
	hash_for_each_possible(ksu_nomount_bypasses, bypass, node,
			       (unsigned long)current) {
		if (bypass->task == current) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&ksu_nomount_bypass_lock, irq_flags);
	return found;
}

bool ksu_nomount_bypass_active(void)
{
	return ksu_nomount_current_bypassed();
}

void ksu_nomount_lookup_scope_enter(struct ksu_nomount_lookup_scope *scope,
				    int dfd)
{
	unsigned long irq_flags;

	if (!scope)
		return;
	INIT_HLIST_NODE(&scope->node);
	scope->task = current;
	scope->dfd = dfd;
	scope->active = false;
	/* A scope is only needed while either pathname policy can consume it.
	 * Avoid a spinlock in the normal no-rule fast path. */
	if (!static_branch_unlikely(&ksu_nomount_active_rules) &&
	    !ksu_susfs_path_filter_active())
		return;

	/* Keep an AT_FDCWD marker too.  A signal or nested syscall may construct a
	 * relative pathname while an outer non-CWD *at() scope is active; omitting
	 * this marker would incorrectly inherit that outer directory fd. */
	spin_lock_irqsave(&ksu_nomount_lookup_scope_lock, irq_flags);
	hash_add(ksu_nomount_lookup_scopes, &scope->node,
		 (unsigned long)scope->task);
	scope->active = true;
	spin_unlock_irqrestore(&ksu_nomount_lookup_scope_lock, irq_flags);
}

void ksu_nomount_lookup_scope_exit(struct ksu_nomount_lookup_scope *scope)
{
	unsigned long irq_flags;

	if (!scope || !scope->active)
		return;
	spin_lock_irqsave(&ksu_nomount_lookup_scope_lock, irq_flags);
	if (!hlist_unhashed(&scope->node))
		hash_del(&scope->node);
	scope->active = false;
	spin_unlock_irqrestore(&ksu_nomount_lookup_scope_lock, irq_flags);
}

static int ksu_nomount_current_lookup_dfd(void)
{
	struct ksu_nomount_lookup_scope *scope;
	unsigned long irq_flags;
	int dfd = AT_FDCWD;

	spin_lock_irqsave(&ksu_nomount_lookup_scope_lock, irq_flags);
	hash_for_each_possible(ksu_nomount_lookup_scopes, scope, node,
			       (unsigned long)current) {
		if (scope->task != current)
			continue;
		dfd = scope->dfd;
		break;
	}
	spin_unlock_irqrestore(&ksu_nomount_lookup_scope_lock, irq_flags);
	return dfd;
}

bool ksu_nomount_lookup_scope_matches(int dfd)
{
	struct ksu_nomount_lookup_scope *scope;
	unsigned long irq_flags;
	bool matches = false;

	spin_lock_irqsave(&ksu_nomount_lookup_scope_lock, irq_flags);
	hash_for_each_possible(ksu_nomount_lookup_scopes, scope, node,
			       (unsigned long)current) {
		if (scope->task != current)
			continue;
		matches = scope->dfd == dfd;
		break;
	}
	spin_unlock_irqrestore(&ksu_nomount_lookup_scope_lock, irq_flags);
	return matches;
}

static void ksu_nomount_access_scope_exit(struct callback_head *work)
{
	struct ksu_nomount_access_scope *scope = container_of(
		work, struct ksu_nomount_access_scope, task_work);
	unsigned long irq_flags;

	spin_lock_irqsave(&ksu_nomount_access_scope_lock, irq_flags);
	if (!hlist_unhashed(&scope->node)) {
		hash_del(&scope->node);
		atomic_dec(&ksu_nomount_access_scope_count);
	}
	spin_unlock_irqrestore(&ksu_nomount_access_scope_lock, irq_flags);
	kfree(scope);
}

static int ksu_nomount_access_scope_enter(
	unsigned long real_ino, dev_t real_dev, unsigned long visible_ino,
	dev_t visible_dev, bool preserve_real_ino,
	const struct ksu_nomount_inode_identity *ancestors, u16 ancestor_count)
{
	struct ksu_nomount_access_scope *scope;
	unsigned long irq_flags;
	int err;

	if (ancestor_count > KSU_NOMOUNT_MAX_ANCESTORS)
		return -E2BIG;
	scope = kzalloc(sizeof(*scope) +
			ancestor_count * sizeof(*scope->ancestors), GFP_KERNEL);
	if (!scope)
		return -ENOMEM;
	scope->task = current;
	scope->real_ino = real_ino;
	scope->real_dev = real_dev;
	scope->visible_ino = visible_ino;
	scope->visible_dev = visible_dev;
	scope->preserve_real_ino = preserve_real_ino;
	scope->ancestor_count = ancestor_count;
	if (ancestor_count)
		memcpy(scope->ancestors, ancestors,
		       ancestor_count * sizeof(*scope->ancestors));
	scope->task_work.func = ksu_nomount_access_scope_exit;

	spin_lock_irqsave(&ksu_nomount_access_scope_lock, irq_flags);
	hash_add(ksu_nomount_access_scopes, &scope->node,
		 (unsigned long)scope->task);
	atomic_inc(&ksu_nomount_access_scope_count);
	spin_unlock_irqrestore(&ksu_nomount_access_scope_lock, irq_flags);

	err = task_work_add(current, &scope->task_work, true);
	if (!err)
		return 0;

	spin_lock_irqsave(&ksu_nomount_access_scope_lock, irq_flags);
	if (!hlist_unhashed(&scope->node)) {
		hash_del(&scope->node);
		atomic_dec(&ksu_nomount_access_scope_count);
	}
	spin_unlock_irqrestore(&ksu_nomount_access_scope_lock, irq_flags);
	kfree(scope);
	return err;
}

static bool ksu_nomount_uid_blocked(uid_t uid)
{
	struct ksu_nomount_uid *entry;

	if (!static_branch_unlikely(&ksu_nomount_active_uids))
		return false;

	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_nomount_uids, entry, node, uid) {
		if (entry->uid == uid) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static bool ksu_nomount_should_skip(void)
{
	if (!static_branch_unlikely(&ksu_nomount_active_rules))
		return true;
	if (unlikely(in_interrupt() || oops_in_progress))
		return true;
	if (unlikely(current->flags & (PF_KTHREAD | PF_EXITING)))
		return true;
	if (unlikely(ksu_nomount_current_bypassed()))
		return true;
	return ksu_nomount_uid_blocked(current_uid().val);
}

bool ksu_nomount_active_for_current(void)
{
	return !ksu_nomount_should_skip();
}

static int ksu_nomount_resolve_path_flags(const char *path, unsigned int flags,
					  struct path *out)
{
	struct ksu_nomount_bypass bypass;
	const struct cred *saved = NULL;
	int err;

	ksu_nomount_bypass_enter(&bypass);
	if (ksu_cred)
		saved = override_creds(ksu_cred);
	err = kern_path(path, flags, out);
	if (saved)
		revert_creds(saved);
	ksu_nomount_bypass_exit(&bypass);
	return err;
}

static size_t ksu_nomount_collapse_slashes(char *path)
{
	size_t input_len = strlen(path);
	bool trailing = input_len > 1 && path[input_len - 1] == '/';
	char *read = path;
	char *write = path;

	if (*read == '/')
		*write++ = '/';
	while (*read == '/')
		read++;
	while (*read) {
		char *component = read;
		size_t component_len;

		while (*read && *read != '/')
			read++;
		component_len = read - component;
		while (*read == '/')
			read++;
		if (!component_len ||
		    (component_len == 1 && component[0] == '.'))
			continue;
		if (component_len == 2 && component[0] == '.' &&
		    component[1] == '.') {
			char *slash;

			/* Rules are absolute.  Clamp attempts to walk above root. */
			if (write <= path + 1)
				continue;
			slash = write - 1;
			while (slash > path && *slash != '/')
				slash--;
			/* Remove the separator together with the component.  Keeping it
			 * here would leave a trailing slash for paths ending in ".."
			 * (for example /a/b/..), which then misses the canonical rule. */
			write = slash == path ? path + 1 : slash;
			continue;
		}
		if (write > path && write[-1] != '/')
			*write++ = '/';
		memmove(write, component, component_len);
		write += component_len;
	}
	if (trailing && write > path + 1 && write[-1] != '/')
		*write++ = '/';
	*write = '\0';
	return write - path;
}

static bool ksu_nomount_path_needs_canonicalize(const char *path, size_t len)
{
	size_t i = path[0] == '/' ? 1 : 0;

	if (len > 1 && path[len - 1] == '/')
		return true;
	while (i < len) {
		size_t start = i;

		while (i < len && path[i] != '/')
			i++;
		if (i == start || (i - start == 1 && path[start] == '.') ||
		    (i - start == 2 && path[start] == '.' &&
		     path[start + 1] == '.'))
			return true;
		if (i < len && path[i] == '/') {
			size_t slash_start = i;

			while (i < len && path[i] == '/')
				i++;
			if (i - slash_start > 1)
				return true;
		}
	}
	return false;
}

static int ksu_nomount_normalize_path(char *dst, size_t dst_size,
				      const char *src)
{
	size_t len;

	if (!src || !*src || src[0] != '/')
		return -EINVAL;
	if (strscpy(dst, src, dst_size) < 0)
		return -ENAMETOOLONG;
	len = ksu_nomount_collapse_slashes(dst);
	while (len > 1 && dst[len - 1] == '/')
		dst[--len] = '\0';
	return 0;
}

static int ksu_nomount_split_path(const char *path, char *parent,
				  size_t parent_size, const char **name)
{
	const char *slash;
	size_t parent_len;

	if (!path || path[0] != '/' || path[1] == '\0')
		return -EINVAL;
	slash = strrchr(path, '/');
	if (!slash || slash[1] == '\0')
		return -EINVAL;

	*name = slash + 1;
	if (slash == path)
		return strscpy(parent, "/", parent_size) < 0 ?
			       -ENAMETOOLONG : 0;

	parent_len = slash - path;
	if (parent_len >= parent_size)
		return -ENAMETOOLONG;
	memcpy(parent, path, parent_len);
	parent[parent_len] = '\0';
	return 0;
}

static unsigned int ksu_nomount_count_components(const char *path)
{
	unsigned int count = 0;
	const char *p;

	if (!path || path[0] != '/')
		return 0;
	p = path + 1;
	while (*p) {
		count++;
		p = strchr(p, '/');
		if (!p)
			break;
		p++;
	}
	return count;
}

static int ksu_nomount_prefix_components(const char *path, unsigned int count,
					 char *out, size_t out_size)
{
	const char *p;
	size_t len = 1;
	unsigned int seen = 0;

	if (!path || path[0] != '/' || !count)
		return strscpy(out, "/", out_size) < 0 ? -ENAMETOOLONG : 0;

	p = path + 1;
	while (*p && seen < count) {
		const char *slash = strchr(p, '/');
		size_t component_len = slash ? (size_t)(slash - p) : strlen(p);

		len = (p - path) + component_len;
		seen++;
		if (!slash)
			break;
		p = slash + 1;
	}
	if (seen != count || len >= out_size)
		return -ENAMETOOLONG;
	memcpy(out, path, len);
	out[len] = '\0';
	return 0;
}

static int ksu_nomount_trim_components(const char *path, unsigned int count,
				       char *out, size_t out_size)
{
	int err = ksu_nomount_normalize_path(out, out_size, path);

	if (err)
		return err;
	while (count-- && strcmp(out, "/")) {
		char *slash = strrchr(out, '/');

		if (!slash || slash == out) {
			out[1] = '\0';
			break;
		}
		*slash = '\0';
	}
	return 0;
}

static int ksu_nomount_real_dir_status(const char *path)
{
	struct path resolved;
	struct inode *inode;
	int err = ksu_nomount_resolve_path_flags(path, LOOKUP_FOLLOW, &resolved);

	if (err)
		return err;
	inode = d_backing_inode(resolved.dentry);
	err = inode && S_ISDIR(inode->i_mode) ? 0 : -ENOTDIR;
	path_put(&resolved);
	return err;
}

static u32 ksu_nomount_path_fs_type(const struct path *path)
{
	struct ksu_nomount_bypass bypass;
	struct kstatfs statfs;
	struct inode *inode;
	int err;

	if (!path || !path->dentry)
		return 0;
	ksu_nomount_bypass_enter(&bypass);
	err = vfs_statfs(path, &statfs);
	ksu_nomount_bypass_exit(&bypass);
	if (!err)
		return (u32)statfs.f_type;
	inode = d_backing_inode(path->dentry);
	return inode && inode->i_sb ? (u32)inode->i_sb->s_magic : 0;
}

/*
 * Capture the filesystem view that a virtual pathname should expose.  A
 * missing virtual object may have several missing ancestors, so walk toward
 * the nearest native directory instead of falling back to the backend's
 * filesystem.  This is done only while publishing a rule; the hot path just
 * copies the saved kstatfs structure.
 */
static int ksu_nomount_capture_visible_statfs(const char *path,
						struct kstatfs *out)
{
	struct ksu_nomount_bypass bypass;
	char *cursor;
	struct path resolved;
	int err = -ENOENT;

	if (!path || !out || path[0] != '/')
		return -EINVAL;
	cursor = __getname();
	if (!cursor || strscpy(cursor, path, KSU_NOMOUNT_MAX_PATH) < 0) {
		if (cursor)
			__putname(cursor);
		return -ENAMETOOLONG;
	}

	for (;;) {
		err = ksu_nomount_resolve_path_flags(cursor, LOOKUP_FOLLOW,
						      &resolved);
		if (!err) {
			ksu_nomount_bypass_enter(&bypass);
			err = vfs_statfs(&resolved, out);
			ksu_nomount_bypass_exit(&bypass);
			path_put(&resolved);
			if (!err)
				break;
		}
		if (!strcmp(cursor, "/"))
			break;
		{
			char *slash = strrchr(cursor, '/');

			if (!slash || slash == cursor)
				strscpy(cursor, "/", KSU_NOMOUNT_MAX_PATH);
			else
				*slash = '\0';
		}
	}
	__putname(cursor);
	return err;
}

static struct ksu_nomount_rule *
ksu_nomount_find_rule_locked_len(const char *path, size_t len)
{
	struct ksu_nomount_rule *rule;
	u32 hash = ksu_nomount_hash_path_len(path, len);

	hash_for_each_possible(ksu_nomount_rules, rule, path_node, hash) {
		if (rule->hash == hash && rule->virtual_len == len &&
		    !memcmp(rule->virtual_path, path, len))
			return rule;
	}
	return NULL;
}

static struct ksu_nomount_rule *ksu_nomount_find_rule_locked(const char *path)
{
	return ksu_nomount_find_rule_locked_len(path, strlen(path));
}

/*
 * Relative names need a cwd d_path() reconstruction before their full path
 * can be matched.  That is materially more expensive than a normal negative
 * pathname lookup, so first reject names whose basename is not present in any
 * rule.  The final full-path lookup still decides the policy.
 */
bool ksu_nomount_relative_rule_may_match(const char *path, size_t len)
{
	const char *name;
	struct ksu_nomount_rule *rule;
	size_t name_len;
	u32 hash;
	bool found = false;

	if (!path || !len || path[0] == '/')
		return false;
	name = strrchr(path, '/');
	name = name ? name + 1 : path;
	name_len = len - (name - path);
	if (!name_len)
		return false;
	hash = ksu_nomount_hash_path_len(name, name_len);
	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_nomount_basenames, rule, basename_node,
				   hash) {
		if (rule->basename_hash == hash &&
		    rule->basename_len == name_len &&
		    !memcmp(rule->name, name, name_len)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

static bool
ksu_nomount_private_path_exists_rcu(const char *path, size_t len)
{
	struct ksu_nomount_private_path *private;
	const char *private_path;
	u32 hash = ksu_nomount_hash_path_len(path, len);

	hash_for_each_possible_rcu(ksu_nomount_private_paths_hash, private,
				   hash_node, hash) {
		private_path = READ_ONCE(private->path);
		if (READ_ONCE(private->hash) == hash &&
		    READ_ONCE(private->len) == len &&
		    !memcmp(private_path, path, len))
			return true;
	}

	return false;
}

static bool ksu_nomount_path_is_private_rcu(const char *path, size_t len)
{
	size_t end = len;

	if (!path || !len)
		return false;

	if (ksu_nomount_private_path_exists_rcu(path, len))
		return true;

	while (end > 1) {
		while (end > 1 && path[end - 1] != '/')
			end--;
		if (end <= 1)
			break;
		end--;
		if (ksu_nomount_private_path_exists_rcu(path, end))
			return true;
	}

	return false;
}

static unsigned long ksu_nomount_synthetic_ino(const char *path, size_t len)
{
	unsigned long ino = ksu_nomount_hash_path_len(path, len);

#if BITS_PER_LONG > 32
	ino |= (unsigned long)jhash(path, len, 0x4e4d4f55U) << 32;
#endif
	/* Zero has special meaning in several VFS metadata paths. */
	return ino ?: 1;
}

static struct ksu_nomount_rule *
ksu_nomount_find_rule_rcu_len(const char *path, size_t len)
{
	struct ksu_nomount_rule *rule;
	const char *name;
	const char *end = path + len;
	size_t name_len;
	u32 hash;

	if (!path || !len)
		return NULL;
	name = end;
	while (name > path && name[-1] != '/')
		name--;
	if (name == path || name == end)
		return NULL;
	name_len = end - name;
	hash = ksu_nomount_hash_path_len(name, name_len);

	/*
	 * The basename index is already maintained for relative lookups and
	 * readdir suppression.  Use it as the runtime path index too: a full
	 * pathname hash is unnecessary when the basename bucket has no candidate.
	 */
	hash_for_each_possible_rcu(ksu_nomount_basenames, rule, basename_node,
				   hash) {
		if (rule->basename_hash == hash &&
		    rule->basename_len == name_len &&
		    rule->virtual_len == len &&
		    !memcmp(rule->virtual_path, path, len))
			return rule;
	}
	return NULL;
}

static struct ksu_nomount_rule *
ksu_nomount_find_dir_prefix_rule_rcu(const char *path, size_t len,
					    size_t *prefix_len)
{
	size_t end = len;

	while (end > 1) {
		struct ksu_nomount_rule *rule;

		while (end > 1 && path[end - 1] != '/')
			end--;
		if (end <= 1)
			break;
		end--;
		rule = ksu_nomount_find_rule_rcu_len(path, end);
		if (rule && rule->d_type == DT_DIR &&
		    !(READ_ONCE(rule->flags) & KSU_NOMOUNT_FLAG_WHITEOUT)) {
			if (prefix_len)
				*prefix_len = end;
			return rule;
		}
	}
	return NULL;
}

static struct ksu_nomount_rule *
ksu_nomount_find_real_rule_identity_rcu(unsigned long ino, dev_t dev)
{
	struct ksu_nomount_rule *rule;

	hash_for_each_possible_rcu(ksu_nomount_real_inodes, rule, real_node,
				   ino) {
		if (rule->real_ino == ino && rule->real_dev == dev)
			return rule;
	}
	return NULL;
}

static struct ksu_nomount_rule *
ksu_nomount_find_real_rule_rcu_len(const char *path, size_t len)
{
	struct ksu_nomount_rule *rule;
	u32 hash = ksu_nomount_hash_path_len(path, len);

	hash_for_each_possible_rcu(ksu_nomount_real_paths, rule,
				   real_path_node, hash) {
		if (rule->real_hash == hash && rule->real_len == len &&
		    !memcmp(rule->real_path, path, len))
			return rule;
	}
	return NULL;
}

static struct ksu_nomount_rule *
ksu_nomount_find_real_dir_prefix_rule_rcu(const char *path, size_t len,
					  size_t *prefix_len)
{
	size_t end = len;

	while (end > 1) {
		struct ksu_nomount_rule *rule;

		while (end > 1 && path[end - 1] != '/')
			end--;
		if (end <= 1)
			break;
		end--;
		rule = ksu_nomount_find_real_rule_rcu_len(path, end);
		if (rule && rule->d_type == DT_DIR &&
		    !(READ_ONCE(rule->flags) & KSU_NOMOUNT_FLAG_WHITEOUT)) {
			if (prefix_len)
				*prefix_len = end;
			return rule;
		}
	}
	return NULL;
}

static struct ksu_nomount_rule *
ksu_nomount_find_real_rule_rcu(struct inode *inode)
{
	if (!inode || !inode->i_sb)
		return NULL;
	return ksu_nomount_find_real_rule_identity_rcu(inode->i_ino,
						       inode->i_sb->s_dev);
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_locked(const char *path)
{
	struct ksu_nomount_parent *parent;
	u32 hash = ksu_nomount_hash_path(path);

	hash_for_each_possible(ksu_nomount_parents, parent, path_node, hash) {
		if (!strcmp(parent->path, path))
			return parent;
	}
	return NULL;
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_for_path_locked(const char *path);
static int ksu_nomount_parent_identity_locked(
	const char *path, const struct ksu_nomount_rule *prospective,
	unsigned long *ino, dev_t *dev, unsigned long *visible_ino,
	dev_t *visible_dev, u32 *fs_type, bool *internal);

static bool ksu_nomount_path_has_children_locked(const char *path)
{
	struct ksu_nomount_parent *parent =
		ksu_nomount_find_parent_for_path_locked(path);
	struct ksu_nomount_child_array *children;

	if (!parent)
		return false;
	children = rcu_dereference_protected(
		parent->children, lockdep_is_held(&ksu_nomount_lock));
	return children && children->live_children;
}

static const char *
ksu_nomount_child_name(const struct ksu_nomount_child_array *array,
		       const struct ksu_nomount_child *child)
{
	return (const char *)&array->entries[array->child_capacity] +
	       READ_ONCE(child->name_offset);
}

static __always_inline u32
ksu_nomount_child_count(const struct ksu_nomount_child_array *array)
{
	return smp_load_acquire(&array->num_children);
}

static __always_inline u8
ksu_nomount_child_flags_rcu(const struct ksu_nomount_child *child)
{
	return smp_load_acquire(&child->flags);
}

static struct ksu_nomount_child_array *
ksu_nomount_alloc_child_array(u32 child_capacity, u32 heap_capacity)
{
	struct ksu_nomount_child_array *array;
	size_t entries_size;
	size_t total;

	if (check_mul_overflow((size_t)child_capacity,
			       sizeof(struct ksu_nomount_child),
			       &entries_size))
		return NULL;
	if (check_add_overflow(sizeof(*array), entries_size, &total))
		return NULL;
	if (check_add_overflow(total, (size_t)heap_capacity, &total))
		return NULL;
	array = kvzalloc(total, GFP_KERNEL);
	if (!array)
		return NULL;
	atomic_set(&array->refcnt, 1);
	array->child_capacity = child_capacity;
	array->heap_capacity = heap_capacity;
	return array;
}

static u32 ksu_nomount_next_child_capacity(u32 need)
{
	u32 cap = 8;

	while (cap < need && cap < KSU_NOMOUNT_MAGIC_WINDOW)
		cap <<= 1;
	if (cap < need)
		cap = need;
	return cap;
}

static u32 ksu_nomount_next_heap_capacity(u32 need)
{
	u32 cap = 256;

	while (cap < need && cap <= (U32_MAX >> 1))
		cap <<= 1;
	if (cap < need)
		cap = need;
	return cap;
}

static u8 ksu_nomount_child_flags(u32 flags, bool visible_exists)
{
	u8 child_flags = flags & (KSU_NOMOUNT_FLAG_IS_DIR |
					 KSU_NOMOUNT_FLAG_WHITEOUT);

	if (visible_exists)
		child_flags |= KSU_NOMOUNT_CHILD_NATIVE;
	return child_flags;
}

static void
ksu_nomount_child_array_rcu_free(struct rcu_head *rcu)
{
	struct ksu_nomount_child_array *array =
		container_of(rcu, struct ksu_nomount_child_array, rcu);

	kvfree(array);
}

static void ksu_nomount_child_array_put(struct ksu_nomount_child_array *array)
{
	if (array && atomic_dec_and_test(&array->refcnt))
		call_rcu(&array->rcu, ksu_nomount_child_array_rcu_free);
}

static int
ksu_nomount_replace_child_array_locked(struct ksu_nomount_parent *parent,
				       struct ksu_nomount_rule *rule,
				       const struct ksu_nomount_rule *known_child)
{
	struct ksu_nomount_child_array *old_array;
	struct ksu_nomount_child_array *new_array;
	const char *old_heap = NULL;
	char *new_heap;
	u32 old_num = 0, old_live = 0, old_heap_size = 0;
	u32 new_num, new_live, new_heap_size;
	int replace_idx = -1;
	int free_idx = -1;
	size_t name_len = rule->basename_len;
	u32 i;

	old_array = rcu_dereference_protected(
		parent->children, lockdep_is_held(&ksu_nomount_lock));
	if (old_array) {
		old_num = READ_ONCE(old_array->num_children);
		old_live = READ_ONCE(old_array->live_children);
		old_heap_size = READ_ONCE(old_array->heap_size);
		old_heap = (const char *)&old_array->entries[old_array->child_capacity];
		if (known_child && known_child->parent == parent) {
			u32 idx = READ_ONCE(known_child->child_index);

			if (idx < old_num) {
				const struct ksu_nomount_child *entry =
					&old_array->entries[idx];
				u8 flags = READ_ONCE(entry->flags);

				if (!(flags & KSU_NOMOUNT_CHILD_DELETED) &&
				    READ_ONCE(entry->name_hash) ==
					    rule->basename_hash &&
				    READ_ONCE(entry->name_len) == name_len &&
				    !memcmp(ksu_nomount_child_name(old_array,
								   entry),
					    rule->name, name_len))
					replace_idx = idx;
			}
		}
		for (i = 0;
		     replace_idx < 0 && old_live < old_num && i < old_num;
		     i++) {
			const struct ksu_nomount_child *entry =
				&old_array->entries[i];
			u8 flags = READ_ONCE(entry->flags);

			if (flags & KSU_NOMOUNT_CHILD_DELETED) {
				if (free_idx < 0)
					free_idx = i;
				continue;
			}
			if (READ_ONCE(entry->name_hash) !=
			    rule->basename_hash)
				continue;
			if (READ_ONCE(entry->name_len) != name_len)
				continue;
			if (!memcmp(ksu_nomount_child_name(old_array, entry),
				    rule->name, name_len)) {
				replace_idx = i;
				break;
			}
		}
	}

	new_num = old_num;
	new_live = old_live;
	if (replace_idx < 0) {
		if (name_len > U16_MAX)
			return -E2BIG;
		if (free_idx < 0)
			new_num++;
		new_live++;
	}
	if (new_num >= KSU_NOMOUNT_MAGIC_WINDOW)
		return -E2BIG;
	new_heap_size = old_heap_size;
	if (replace_idx < 0) {
		if (old_heap_size > U32_MAX - name_len - 1)
			return -EOVERFLOW;
		new_heap_size += name_len + 1;
	}
	if (old_array && replace_idx < 0 && free_idx >= 0) {
		if (old_heap_size + name_len + 1 > old_array->heap_capacity) {
			free_idx = -1;
			new_num = old_num + 1;
		}
	}
	if (old_array && replace_idx < 0 && free_idx >= 0) {
		new_array = old_array;
		new_heap = (char *)&new_array->entries[new_array->child_capacity];
		rule->child_index = free_idx;
		WRITE_ONCE(new_array->entries[free_idx].ino,
			   rule->visible_ino);
		WRITE_ONCE(new_array->entries[free_idx].name_len,
			   (u16)name_len);
		WRITE_ONCE(new_array->entries[free_idx].name_hash,
			   rule->basename_hash);
		WRITE_ONCE(new_array->entries[free_idx].d_type, rule->d_type);
		WRITE_ONCE(new_array->entries[free_idx].name_offset,
			   old_heap_size);
		memcpy(new_heap + old_heap_size, rule->name, name_len + 1);
		WRITE_ONCE(new_array->heap_size, old_heap_size + name_len + 1);
		WRITE_ONCE(new_array->live_children, new_live);
		smp_store_release(&new_array->entries[free_idx].flags,
				  ksu_nomount_child_flags(rule->flags,
							  rule->visible_exists));
		return 0;
	}
	if (old_array && replace_idx < 0 && old_num < old_array->child_capacity &&
	    old_heap_size + name_len + 1 <= old_array->heap_capacity) {
		new_array = old_array;
		new_heap = (char *)&new_array->entries[new_array->child_capacity];
		rule->child_index = old_num;
		WRITE_ONCE(new_array->entries[old_num].ino,
			   rule->visible_ino);
		WRITE_ONCE(new_array->entries[old_num].name_len,
			   (u16)name_len);
		WRITE_ONCE(new_array->entries[old_num].name_hash,
			   rule->basename_hash);
		WRITE_ONCE(new_array->entries[old_num].d_type, rule->d_type);
		WRITE_ONCE(new_array->entries[old_num].name_offset,
			   old_heap_size);
		memcpy(new_heap + old_heap_size, rule->name, name_len + 1);
		WRITE_ONCE(new_array->entries[old_num].flags,
			   ksu_nomount_child_flags(rule->flags,
						   rule->visible_exists));
		WRITE_ONCE(new_array->heap_size, old_heap_size + name_len + 1);
		WRITE_ONCE(new_array->live_children, new_live);
		smp_store_release(&new_array->num_children, old_num + 1);
		return 0;
	}
	new_array = ksu_nomount_alloc_child_array(
		ksu_nomount_next_child_capacity(new_num),
		ksu_nomount_next_heap_capacity(new_heap_size));
	if (!new_array)
		return -ENOMEM;
	new_array->num_children = new_num;
	new_array->live_children = new_live;
	new_array->heap_size = new_heap_size;
	new_heap = (char *)&new_array->entries[new_array->child_capacity];
	if (old_array && old_num) {
		memcpy(new_array->entries, old_array->entries,
		       old_num * sizeof(struct ksu_nomount_child));
		if (old_heap_size)
			memcpy(new_heap, old_heap, old_heap_size);
	}
	if (replace_idx >= 0) {
		new_array->entries[replace_idx].ino = rule->visible_ino;
		new_array->entries[replace_idx].name_len = (u16)name_len;
		new_array->entries[replace_idx].name_hash =
			rule->basename_hash;
		new_array->entries[replace_idx].d_type = rule->d_type;
		new_array->entries[replace_idx].flags =
			ksu_nomount_child_flags(rule->flags, rule->visible_exists);
		rule->child_index = replace_idx;
	} else if (free_idx >= 0 && old_array) {
		struct ksu_nomount_child *child = &new_array->entries[free_idx];

		child->ino = rule->visible_ino;
		child->name_len = (u16)name_len;
		child->name_hash = rule->basename_hash;
		child->name_offset = old_heap_size;
		child->d_type = rule->d_type;
		child->flags = ksu_nomount_child_flags(rule->flags,
						      rule->visible_exists);
		memcpy(new_heap + old_heap_size, rule->name, name_len + 1);
		rule->child_index = free_idx;
	} else {
		struct ksu_nomount_child *child = &new_array->entries[old_num];

		child->ino = rule->visible_ino;
		child->name_len = (u16)name_len;
		child->name_hash = rule->basename_hash;
		child->name_offset = old_heap_size;
		child->d_type = rule->d_type;
		child->flags = ksu_nomount_child_flags(rule->flags,
						      rule->visible_exists);
		memcpy(new_heap + old_heap_size, rule->name, name_len + 1);
		rule->child_index = old_num;
	}
	rcu_assign_pointer(parent->children, new_array);
	ksu_nomount_child_array_put(old_array);
	return 0;
}

static int
ksu_nomount_delete_child_locked(struct ksu_nomount_parent *parent,
				const struct ksu_nomount_rule *rule)
{
	struct ksu_nomount_child_array *old_array;
	struct ksu_nomount_child *entry;
	u32 idx;
	u32 live_children;
	u8 flags;

	old_array = rcu_dereference_protected(
		parent->children, lockdep_is_held(&ksu_nomount_lock));
	if (!old_array)
		return 0;
	idx = READ_ONCE(rule->child_index);
	if (idx >= old_array->num_children)
		return 0;
	entry = &old_array->entries[idx];
	flags = READ_ONCE(entry->flags);
	if (flags & KSU_NOMOUNT_CHILD_DELETED)
		return 0;
	if (READ_ONCE(entry->name_hash) != rule->basename_hash ||
	    READ_ONCE(entry->name_len) != rule->basename_len ||
	    memcmp(ksu_nomount_child_name(old_array, entry), rule->name,
		   rule->basename_len))
		return 0;
	live_children = old_array->live_children;
	if (live_children <= 1) {
		rcu_assign_pointer(parent->children, NULL);
		ksu_nomount_child_array_put(old_array);
		return 0;
	}
	smp_store_release(&entry->flags, flags | KSU_NOMOUNT_CHILD_DELETED);
	WRITE_ONCE(old_array->live_children, live_children - 1);
	return 0;
}

static int ksu_nomount_collect_ancestors(const struct path *backend,
					struct ksu_nomount_rule *rule)
{
	struct ksu_nomount_inode_identity *keys;
	struct ksu_nomount_private_path *private_paths;
	struct ksu_nomount_bypass bypass;
	struct path resolved;
	struct inode *backend_inode;
	char *canonical;
	char *path;
	char *resolved_path;
	unsigned int count = 0;
	unsigned int private_count = 0;
	int err = 0;

	if (!backend || !backend->dentry)
		return -EINVAL;

	path = __getname();
	canonical = __getname();
	if (!path || !canonical) {
		if (path)
			__putname(path);
		if (canonical)
			__putname(canonical);
		return -ENOMEM;
	}
	ksu_nomount_bypass_enter(&bypass);
	resolved_path = d_path(backend, path, KSU_NOMOUNT_MAX_PATH);
	ksu_nomount_bypass_exit(&bypass);
	if (IS_ERR(resolved_path)) {
		err = PTR_ERR(resolved_path);
		goto out_path;
	}
	if (resolved_path != path)
		memmove(path, resolved_path, strlen(resolved_path) + 1);
	if (path[0] != '/' ||
	    strscpy(canonical, path, KSU_NOMOUNT_MAX_PATH) < 0) {
		err = -EINVAL;
		goto out_path;
	}

	backend_inode = d_backing_inode(backend->dentry);
	if (!backend_inode) {
		err = -ENOENT;
		goto out_path;
	}
	if (!S_ISDIR(backend_inode->i_mode) && strcmp(canonical, "/")) {
		char *slash = strrchr(canonical, '/');

		if (!slash || slash == canonical)
			canonical[1] = '\0';
		else
			*slash = '\0';
	}

	if (strscpy(path, canonical, KSU_NOMOUNT_MAX_PATH) < 0) {
		err = -ENAMETOOLONG;
		goto out_path;
	}
	while (strcmp(path, "/")) {
		err = ksu_nomount_resolve_path_flags(path, LOOKUP_FOLLOW,
						     &resolved);
		if (err)
			goto out_path;
		backend_inode = d_backing_inode(resolved.dentry);
		if (!backend_inode || !S_ISDIR(backend_inode->i_mode)) {
			path_put(&resolved);
			err = -ENOTDIR;
			goto out_path;
		}
		path_put(&resolved);
		if (++count > KSU_NOMOUNT_MAX_ANCESTORS) {
			err = -E2BIG;
			goto out_path;
		}
		{
			char *slash = strrchr(path, '/');

			if (!slash || slash == path)
				path[1] = '\0';
			else
				*slash = '\0';
		}
	}
	if (!count)
		goto out_path;

	keys = kcalloc(count, sizeof(*keys), GFP_KERNEL);
	private_paths = kcalloc(count, sizeof(*private_paths), GFP_KERNEL);
	if (!keys || !private_paths) {
		kfree(keys);
		kfree(private_paths);
		err = -ENOMEM;
		goto out_path;
	}
	rule->ancestors = keys;
	rule->private_paths = private_paths;
	if (strscpy(path, canonical, KSU_NOMOUNT_MAX_PATH) < 0) {
		err = -ENAMETOOLONG;
		goto out_path;
	}
	while (rule->ancestor_count < count) {
		struct inode *inode;
		u16 index = rule->ancestor_count;

		err = ksu_nomount_resolve_path_flags(path, LOOKUP_FOLLOW,
						     &resolved);
		if (err)
			goto out_path;
		inode = d_backing_inode(resolved.dentry);
		if (!inode || !S_ISDIR(inode->i_mode)) {
			path_put(&resolved);
			err = -ENOTDIR;
			goto out_path;
		}
		keys[index].ino = inode->i_ino;
		keys[index].dev = inode->i_sb->s_dev;
		rule->ancestor_count++;
		if (!(inode->i_mode & 0001)) {
			struct ksu_nomount_private_path *private =
				&private_paths[private_count];

			private->ino = inode->i_ino;
			private->dev = inode->i_sb->s_dev;
			private->len = strlen(path);
			private->hash = ksu_nomount_hash_path_len(path,
								   private->len);
			private->path = kstrdup(path, GFP_KERNEL);
			if (!private->path) {
				path_put(&resolved);
				err = -ENOMEM;
				goto out_path;
			}
			INIT_LIST_HEAD(&private->node);
			INIT_HLIST_NODE(&private->hash_node);
			private_count++;
			rule->private_count = private_count;
		}
		path_put(&resolved);
		{
			char *slash = strrchr(path, '/');

			if (!slash || slash == path)
				path[1] = '\0';
			else
				*slash = '\0';
		}
	}
out_path:
	__putname(canonical);
	__putname(path);
	return err;
}

static void ksu_nomount_rule_free(struct ksu_nomount_rule *rule)
{
	if (!rule)
		return;
	while (rule->private_count) {
		struct ksu_nomount_private_path *private =
			&rule->private_paths[--rule->private_count];

		kfree(private->path);
	}
	kfree(rule->private_paths);
	kfree(rule->ancestors);
	kfree(rule->virtual_path);
	kfree(rule->real_path);
	kfree(rule);
}

static struct ksu_nomount_rule *
ksu_nomount_alloc_rule(const char *virtual_path, const char *real_path,
		       u32 flags, u8 d_type, const struct path *backend,
		       bool visible_exists, unsigned long visible_ino,
		       dev_t visible_dev,
		       const struct kstatfs *visible_statfs)
{
	struct ksu_nomount_rule *rule;
	const char *name;
	size_t virtual_len = strlen(virtual_path);
	size_t real_len = real_path ? strlen(real_path) : 0;
	int err;

	if (virtual_len >= KSU_NOMOUNT_MAX_PATH ||
	    real_len >= KSU_NOMOUNT_EMBEDDED_NAME_MAX ||
	    virtual_len > U16_MAX || real_len > U16_MAX)
		return ERR_PTR(-ENAMETOOLONG);
	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);
	rule->virtual_path = kstrdup(virtual_path, GFP_KERNEL);
	rule->real_path = kstrdup(real_path ?: "", GFP_KERNEL);
	if (!rule->virtual_path || !rule->real_path) {
		ksu_nomount_rule_free(rule);
		return ERR_PTR(-ENOMEM);
	}
	name = strrchr(rule->virtual_path, '/');
	if (!name || !name[1]) {
		ksu_nomount_rule_free(rule);
		return ERR_PTR(-EINVAL);
	}
	name++;

	INIT_LIST_HEAD(&rule->gc_node);
	rule->name = name;
	rule->virtual_len = virtual_len;
	rule->real_len = real_len;
	rule->basename_len = strlen(name);
	rule->hash = ksu_nomount_hash_path_len(virtual_path, virtual_len);
	if (real_len)
		rule->real_hash = ksu_nomount_hash_path_len(real_path,
							    real_len);
	rule->basename_hash = ksu_nomount_hash_path_len(
		name, rule->basename_len);
	rule->flags = flags;
	rule->d_type = d_type;
	rule->visible_exists = visible_exists &&
		!(flags & KSU_NOMOUNT_FLAG_WHITEOUT);
	rule->visible_ino = visible_ino ?:
		ksu_nomount_synthetic_ino(virtual_path, virtual_len);
	rule->visible_dev = visible_dev;
	if (visible_statfs) {
		rule->visible_statfs = *visible_statfs;
		rule->fs_type = visible_statfs->f_type;
		rule->has_visible_statfs = true;
	}
	if (d_type == DT_DIR)
		rule->flags |= KSU_NOMOUNT_FLAG_IS_DIR;
	else
		rule->flags &= ~KSU_NOMOUNT_FLAG_IS_DIR;

	if (!(flags & KSU_NOMOUNT_FLAG_WHITEOUT)) {
		struct inode *inode;

		if (!backend || !backend->dentry) {
			ksu_nomount_rule_free(rule);
			return ERR_PTR(-ENOENT);
		}
		inode = d_backing_inode(backend->dentry);
		if (!inode) {
			ksu_nomount_rule_free(rule);
			return ERR_PTR(-ENOENT);
		}
		rule->real_ino = inode->i_ino;
		rule->real_dev = inode->i_sb->s_dev;
		err = ksu_nomount_collect_ancestors(backend, rule);
		if (err) {
			ksu_nomount_rule_free(rule);
			return ERR_PTR(err);
		}
	}
	return rule;
}

static int ksu_nomount_parent_identity_locked(
	const char *path, const struct ksu_nomount_rule *prospective,
	unsigned long *ino, dev_t *dev, unsigned long *visible_ino,
	dev_t *visible_dev, u32 *fs_type, bool *internal)
{
	const struct ksu_nomount_rule *rule = prospective;
	const char *backend_path = path;
	struct path resolved;
	struct inode *inode;
	int err;

	if (!rule)
		rule = ksu_nomount_find_rule_locked(path);
	if (rule) {
		if (rule->d_type != DT_DIR ||
		    (rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT))
			return -ENOTDIR;
		backend_path = rule->real_path;
	}
	err = ksu_nomount_resolve_path_flags(backend_path, LOOKUP_FOLLOW,
					     &resolved);
	if (err)
		return err;
	inode = d_backing_inode(resolved.dentry);
	if (!inode || !S_ISDIR(inode->i_mode)) {
		path_put(&resolved);
		return -ENOTDIR;
	}
	*ino = inode->i_ino;
	*dev = inode->i_sb->s_dev;
	*visible_ino = rule ? rule->visible_ino : inode->i_ino;
	*visible_dev = rule && rule->visible_dev ?
			       rule->visible_dev : inode->i_sb->s_dev;
	*fs_type = rule && rule->fs_type ? rule->fs_type :
						ksu_nomount_path_fs_type(&resolved);
	*internal = rule && (rule->flags & KSU_NOMOUNT_FLAG_INTERNAL);
	path_put(&resolved);
	return 0;
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_inode_locked(unsigned long ino, dev_t dev)
{
	struct ksu_nomount_parent *parent;

	hash_for_each_possible(ksu_nomount_parent_inodes, parent, inode_node,
				       ino) {
		if (parent->ino == ino && parent->dev == dev)
			return parent;
	}
	return NULL;
}

static struct ksu_nomount_parent *
ksu_nomount_find_parent_for_path_locked(const char *path)
{
	struct ksu_nomount_parent *parent;
	unsigned long ino;
	unsigned long visible_ino;
	dev_t dev;
	dev_t visible_dev;
	u32 fs_type;
	bool internal;

	parent = ksu_nomount_find_parent_locked(path);
	if (parent)
		return parent;
	if (ksu_nomount_parent_identity_locked(
		    path, NULL, &ino, &dev, &visible_ino, &visible_dev,
		    &fs_type, &internal))
		return NULL;
	(void)visible_ino;
	(void)visible_dev;
	(void)fs_type;
	(void)internal;
	return ksu_nomount_find_parent_inode_locked(ino, dev);
}

static void ksu_nomount_snapshot_parent_identity(
	const struct ksu_nomount_parent *parent,
	struct ksu_nomount_parent_identity *identity)
{
	identity->ino = parent->ino;
	identity->dev = parent->dev;
	identity->visible_ino = parent->visible_ino;
	identity->visible_dev = parent->visible_dev;
	identity->fs_type = parent->fs_type;
	identity->inode_hashed = parent->inode_hashed;
	identity->internal = parent->internal;
}

static int ksu_nomount_apply_parent_identity_locked(
	struct ksu_nomount_parent *parent,
	const struct ksu_nomount_parent_identity *identity)
{
	struct ksu_nomount_parent *same_parent = NULL;

	if (identity->inode_hashed) {
		same_parent = ksu_nomount_find_parent_inode_locked(
			identity->ino, identity->dev);
		if (same_parent && same_parent != parent)
			return -EEXIST;
	}
	if (parent->inode_hashed && identity->inode_hashed &&
	    parent->ino == identity->ino && parent->dev == identity->dev) {
		WRITE_ONCE(parent->visible_ino, identity->visible_ino);
		WRITE_ONCE(parent->visible_dev, identity->visible_dev);
		WRITE_ONCE(parent->fs_type, identity->fs_type);
		WRITE_ONCE(parent->internal, identity->internal);
		return 0;
	}
	if (parent->inode_hashed) {
		hash_del_rcu(&parent->inode_node);
		parent->inode_hashed = false;
		/* Do not reuse an embedded RCU hlist node before old readers exit. */
		synchronize_rcu();
	}
	WRITE_ONCE(parent->ino, identity->ino);
	WRITE_ONCE(parent->dev, identity->dev);
	WRITE_ONCE(parent->visible_ino, identity->visible_ino);
	WRITE_ONCE(parent->visible_dev, identity->visible_dev);
	WRITE_ONCE(parent->fs_type, identity->fs_type);
	WRITE_ONCE(parent->internal, identity->internal);
	if (identity->inode_hashed) {
		hash_add_rcu(ksu_nomount_parent_inodes, &parent->inode_node,
			     identity->ino);
		parent->inode_hashed = true;
	}
	return 0;
}

static int ksu_nomount_update_parent_identity_locked(
	const char *path, const struct ksu_nomount_rule *prospective)
{
	struct ksu_nomount_parent *parent =
		ksu_nomount_find_parent_for_path_locked(path);
	struct ksu_nomount_parent_identity identity;
	int err;

	if (!parent)
		return 0;
	err = ksu_nomount_parent_identity_locked(
		path, prospective, &identity.ino, &identity.dev,
		&identity.visible_ino, &identity.visible_dev,
		&identity.fs_type, &identity.internal);
	if (err)
		return err;
	identity.inode_hashed = true;
	return ksu_nomount_apply_parent_identity_locked(parent, &identity);
}

static struct ksu_nomount_parent *
ksu_nomount_get_or_create_parent_locked(const char *path, bool *created)
{
	struct ksu_nomount_parent *parent;
	unsigned long ino;
	unsigned long visible_ino;
	dev_t dev;
	dev_t visible_dev;
	u32 fs_type;
	bool internal;
	int err;

	*created = false;
	parent = ksu_nomount_find_parent_locked(path);
	if (parent)
		return parent;
	err = ksu_nomount_parent_identity_locked(
		path, NULL, &ino, &dev, &visible_ino, &visible_dev, &fs_type,
		&internal);
	if (err)
		return ERR_PTR(err);
	parent = ksu_nomount_find_parent_inode_locked(ino, dev);
	if (parent) {
		/* Native aliases such as /vendor and /system/vendor share state. */
		if (parent->visible_ino != visible_ino ||
		    parent->visible_dev != visible_dev ||
		    parent->fs_type != fs_type || parent->internal != internal)
			return ERR_PTR(-EEXIST);
		return parent;
	}
	parent = kzalloc(sizeof(*parent), GFP_KERNEL);
	if (!parent)
		return ERR_PTR(-ENOMEM);
	parent->path = kstrdup(path, GFP_KERNEL);
	if (!parent->path) {
		kfree(parent);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&parent->all_node);
	RCU_INIT_POINTER(parent->children, NULL);
	parent->ino = ino;
	parent->dev = dev;
	parent->visible_ino = visible_ino;
	parent->visible_dev = visible_dev;
	parent->fs_type = fs_type;
	parent->internal = internal;
	hash_add_rcu(ksu_nomount_parents, &parent->path_node,
		     ksu_nomount_hash_path(path));
	hash_add_rcu(ksu_nomount_parent_inodes, &parent->inode_node, ino);
	parent->inode_hashed = true;
	list_add_tail(&parent->all_node, &ksu_nomount_parent_list);
	*created = true;
	return parent;
}

static struct ksu_nomount_rule *
ksu_nomount_find_parent_child_rule_locked(
	const struct ksu_nomount_parent *parent, const char *name,
	const struct ksu_nomount_rule *exclude)
{
	struct ksu_nomount_rule *existing;
	size_t name_len = strlen(name);
	u32 hash = ksu_nomount_hash_path_len(name, name_len);

	hash_for_each_possible(ksu_nomount_basenames, existing, basename_node,
			       hash) {
		if (existing != exclude && existing->parent == parent &&
		    existing->basename_hash == hash &&
		    existing->basename_len == name_len &&
		    !memcmp(existing->name, name, name_len))
			return existing;
	}
	return NULL;
}

static bool ksu_nomount_rules_share_child(
	const struct ksu_nomount_rule *rule,
	const struct ksu_nomount_rule *existing)
{
	bool whiteout = rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT;
	bool existing_whiteout =
		existing->flags & KSU_NOMOUNT_FLAG_WHITEOUT;

	if (whiteout != existing_whiteout ||
	    !!(rule->flags & KSU_NOMOUNT_FLAG_INTERNAL) !=
		!!(existing->flags & KSU_NOMOUNT_FLAG_INTERNAL) ||
	    rule->d_type != existing->d_type)
		return false;
	if (whiteout)
		return true;
	return rule->real_ino == existing->real_ino &&
	       rule->real_dev == existing->real_dev;
}

static bool ksu_nomount_adopt_shared_child_identity(
	struct ksu_nomount_rule *rule,
	const struct ksu_nomount_rule *existing)
{
	if (rule->visible_exists && existing->visible_exists &&
	    (rule->visible_ino != existing->visible_ino ||
	     rule->visible_dev != existing->visible_dev))
		return false;
	rule->visible_exists = existing->visible_exists;
	rule->visible_ino = existing->visible_ino;
	rule->visible_dev = existing->visible_dev;
	rule->fs_type = existing->fs_type;
	rule->has_visible_statfs = existing->has_visible_statfs;
	if (existing->has_visible_statfs)
		rule->visible_statfs = existing->visible_statfs;
	return true;
}

static bool ksu_nomount_real_inode_conflicts_locked(
	const struct ksu_nomount_rule *rule,
	const struct ksu_nomount_rule *replacement,
	const struct ksu_nomount_rule *shared_child)
{
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_rule *existing;

	if (rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT)
		return false;
	parent = ksu_nomount_find_parent_inode_locked(rule->real_ino,
						      rule->real_dev);
	if (parent &&
	    ksu_nomount_find_parent_for_path_locked(rule->virtual_path) != parent)
		return true;
	hash_for_each_possible(ksu_nomount_real_inodes, existing, real_node,
				       rule->real_ino) {
		if (existing == replacement || existing == shared_child ||
		    existing->real_ino != rule->real_ino ||
		    existing->real_dev != rule->real_dev)
			continue;
		if (existing->parent == rule->parent &&
		    !strcmp(existing->name, rule->name) &&
		    ksu_nomount_rules_share_child(rule, existing))
			continue;
		return true;
	}
	return false;
}

static void ksu_nomount_drop_empty_parent_locked(
	struct ksu_nomount_parent *parent, struct list_head *victims)
{
	struct ksu_nomount_child_array *children;

	if (!parent)
		return;
	children = rcu_dereference_protected(
		parent->children, lockdep_is_held(&ksu_nomount_lock));
	if (children && READ_ONCE(children->live_children))
		return;
	hash_del_rcu(&parent->path_node);
	if (parent->inode_hashed) {
		hash_del_rcu(&parent->inode_node);
		parent->inode_hashed = false;
	}
	list_del(&parent->all_node);
	list_add_tail(&parent->all_node, victims);
}

static void ksu_nomount_link_rule_locked(struct ksu_nomount_rule *rule)
{
	u16 i;

	hash_add_rcu(ksu_nomount_rules, &rule->path_node, rule->hash);
	hash_add_rcu(ksu_nomount_basenames, &rule->basename_node,
		     rule->basename_hash);
	if (!(rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT)) {
		hash_add_rcu(ksu_nomount_real_inodes, &rule->real_node,
			     rule->real_ino);
		hash_add_rcu(ksu_nomount_real_paths, &rule->real_path_node,
			     rule->real_hash);
	}
	for (i = 0; i < rule->private_count; i++)
		list_add_tail_rcu(&rule->private_paths[i].node,
				  &ksu_nomount_private_paths);
	for (i = 0; i < rule->private_count; i++)
		hash_add_rcu(ksu_nomount_private_paths_hash,
			     &rule->private_paths[i].hash_node,
			     rule->private_paths[i].hash);
}

static void ksu_nomount_unlink_rule_locked(struct ksu_nomount_rule *rule)
{
	u16 i;

	hash_del_rcu(&rule->path_node);
	if (!hlist_unhashed(&rule->basename_node))
		hash_del_rcu(&rule->basename_node);
	if (!hlist_unhashed(&rule->real_node))
		hash_del_rcu(&rule->real_node);
	if (!hlist_unhashed(&rule->real_path_node))
		hash_del_rcu(&rule->real_path_node);
	for (i = 0; i < rule->private_count; i++) {
		if (!list_empty(&rule->private_paths[i].node))
			list_del_rcu(&rule->private_paths[i].node);
		if (!hlist_unhashed(&rule->private_paths[i].hash_node))
			hash_del_rcu(&rule->private_paths[i].hash_node);
	}
}

static int ksu_nomount_publish_rule_locked(
	struct ksu_nomount_rule *rule, struct list_head *rule_victims,
	struct list_head *parent_victims)
{
	struct ksu_nomount_rule *victim;
	struct ksu_nomount_rule *shared_child;
	struct ksu_nomount_parent *parent;
	struct ksu_nomount_parent *identity_parent;
	struct ksu_nomount_parent_identity old_identity;
	char *parent_path;
	const char *unused_name;
	bool parent_identity_changed = false;
	bool new_parent;
	int err;

	parent_path = __getname();
	if (!parent_path)
		return -ENOMEM;
	err = ksu_nomount_split_path(rule->virtual_path, parent_path,
				     KSU_NOMOUNT_MAX_PATH, &unused_name);
	if (err)
		goto out;
	parent = ksu_nomount_get_or_create_parent_locked(parent_path,
							 &new_parent);
	if (IS_ERR(parent)) {
		err = PTR_ERR(parent);
		goto out;
	}
	victim = ksu_nomount_find_rule_locked(rule->virtual_path);
	rule->parent = parent;
	shared_child = ksu_nomount_find_parent_child_rule_locked(
		parent, rule->name, victim);
	if (shared_child &&
	    (!ksu_nomount_rules_share_child(rule, shared_child) ||
	     !ksu_nomount_adopt_shared_child_identity(rule, shared_child))) {
		err = -EEXIST;
		goto out_drop_parent;
	}
	if (ksu_nomount_real_inode_conflicts_locked(rule, victim,
						    shared_child)) {
		err = -EEXIST;
		goto out_drop_parent;
	}
	if (victim && ksu_nomount_path_has_children_locked(rule->virtual_path) &&
	    rule->d_type != DT_DIR) {
		err = -ENOTDIR;
		goto out_drop_parent;
	}
	if (!rule->visible_dev) {
		rule->visible_dev = parent->visible_dev;
		rule->fs_type = parent->fs_type;
	}
	/* A file rule never becomes a directory parent.  Resolving it as a
	 * prospective parent returns -ENOTDIR and used to reject every regular
	 * NoMount rule.  Only directory rules change the inode identity used by
	 * child enumeration; regular-file replacements inherit the already
	 * published parent identity above. */
	if (rule->d_type == DT_DIR) {
		identity_parent = ksu_nomount_find_parent_for_path_locked(
			rule->virtual_path);
		if (identity_parent) {
			ksu_nomount_snapshot_parent_identity(identity_parent,
							     &old_identity);
		}
		err = ksu_nomount_update_parent_identity_locked(
			rule->virtual_path, rule);
		if (err)
			goto out_drop_parent;
		parent_identity_changed = !!identity_parent;
	} else {
		err = 0;
	}
	err = ksu_nomount_replace_child_array_locked(
		parent, rule, shared_child ?: victim);
	if (err)
		goto out_drop_parent;
	parent_identity_changed = false;
	if (victim) {
		ksu_nomount_unlink_rule_locked(victim);
		list_add_tail(&victim->gc_node, rule_victims);
	}
	ksu_nomount_link_rule_locked(rule);
	if (!victim && atomic_inc_return(&ksu_nomount_rule_count) == 1)
		static_branch_enable(&ksu_nomount_active_rules);
	err = 0;
	goto out;

out_drop_parent:
	if (parent_identity_changed) {
		int restore_err = ksu_nomount_apply_parent_identity_locked(
			identity_parent, &old_identity);

		if (restore_err)
			pr_warn("NoMount: failed to restore parent identity for %s: %d\n",
				rule->virtual_path, restore_err);
	}
	if (new_parent)
		ksu_nomount_drop_empty_parent_locked(parent, parent_victims);
out:
	__putname(parent_path);
	return err;
}

static int ksu_nomount_remove_rule_locked(
	struct ksu_nomount_rule *rule, struct list_head *rule_victims,
	struct list_head *parent_victims)
{
	struct ksu_nomount_rule *shared_child =
		ksu_nomount_find_parent_child_rule_locked(rule->parent,
							 rule->name, rule);
	int err = shared_child ? 0 :
		ksu_nomount_delete_child_locked(rule->parent, rule);

	if (err)
		return err;
	ksu_nomount_unlink_rule_locked(rule);
	if (atomic_dec_return(&ksu_nomount_rule_count) == 0)
		static_branch_disable(&ksu_nomount_active_rules);
	list_add_tail(&rule->gc_node, rule_victims);
	ksu_nomount_drop_empty_parent_locked(rule->parent, parent_victims);
	return 0;
}

static void ksu_nomount_prune_internal_ancestors_locked(
	const char *start_path, struct list_head *rule_victims,
	struct list_head *parent_victims);

static int ksu_nomount_del_normalized_locked(
	const char *normalized, const char *parent_path,
	struct list_head *rule_victims, struct list_head *parent_victims,
	bool prune_parent)
{
	struct ksu_nomount_rule *rule;
	u32 old_flags;
	int err;

	rule = ksu_nomount_find_rule_locked(normalized);
	if (!rule || (rule->flags & KSU_NOMOUNT_FLAG_INTERNAL))
		return -ENOENT;
	if (rule->d_type == DT_DIR &&
	    ksu_nomount_path_has_children_locked(normalized)) {
		old_flags = rule->flags;
		WRITE_ONCE(rule->flags,
			   old_flags | KSU_NOMOUNT_FLAG_INTERNAL |
				       KSU_NOMOUNT_FLAG_IS_DIR);
		err = ksu_nomount_update_parent_identity_locked(normalized, rule);
		if (err)
			WRITE_ONCE(rule->flags, old_flags);
		return err;
	}
	err = ksu_nomount_remove_rule_locked(
		rule, rule_victims, parent_victims);
	if (!err && prune_parent)
		ksu_nomount_prune_internal_ancestors_locked(
			parent_path, rule_victims, parent_victims);
	return err;
}

static void ksu_nomount_prune_internal_ancestors_locked(
	const char *start_path, struct list_head *rule_victims,
	struct list_head *parent_victims)
{
	char *cursor = __getname();

	if (!cursor)
		return;
	if (strscpy(cursor, start_path, KSU_NOMOUNT_MAX_PATH) < 0)
		goto out;
	while (strcmp(cursor, "/")) {
		struct ksu_nomount_rule *rule =
			ksu_nomount_find_rule_locked(cursor);
		char *slash;

		if (!rule || !(rule->flags & KSU_NOMOUNT_FLAG_INTERNAL) ||
		    ksu_nomount_path_has_children_locked(cursor))
			break;
		if (ksu_nomount_remove_rule_locked(rule, rule_victims,
						   parent_victims))
			break;
		slash = strrchr(cursor, '/');
		if (!slash || slash == cursor)
			strscpy(cursor, "/", KSU_NOMOUNT_MAX_PATH);
		else
			*slash = '\0';
	}
out:
	__putname(cursor);
}

static int ksu_nomount_internal_anchor_status_locked(const char *path,
					      unsigned long avoid_ino,
					      dev_t avoid_dev)
{
	struct ksu_nomount_rule *rule;
	struct path resolved;
	struct inode *inode;
	int err;

	/* Mapping a virtual directory to global root would hijack root readdir. */
	if (!strcmp(path, "/"))
		return -EEXIST;
	err = ksu_nomount_resolve_path_flags(path, LOOKUP_FOLLOW, &resolved);
	if (err)
		return err;
	inode = d_backing_inode(resolved.dentry);
	if (!inode || !S_ISDIR(inode->i_mode)) {
		err = -ENOTDIR;
		goto out;
	}
	if (inode->i_ino == avoid_ino && inode->i_sb->s_dev == avoid_dev) {
		err = -EEXIST;
		goto out;
	}
	if (ksu_nomount_find_parent_inode_locked(inode->i_ino,
						 inode->i_sb->s_dev)) {
		err = -EEXIST;
		goto out;
	}
	hash_for_each_possible(ksu_nomount_real_inodes, rule, real_node,
				       inode->i_ino) {
		if (rule->real_ino == inode->i_ino &&
		    rule->real_dev == inode->i_sb->s_dev) {
			err = -EEXIST;
			goto out;
		}
	}
	err = 0;
out:
	path_put(&resolved);
	return err;
}

static int ksu_nomount_select_internal_real_path(
	const char *virtual_path, const char *prefix_path, const char *real_path,
	bool whiteout, char *out)
{
	struct ksu_nomount_rule *parent_rule;
	char *seed = __getname();
	char *parent = __getname();
	unsigned int virtual_depth, prefix_depth, trim, max_trim;
	unsigned long parent_ino;
	unsigned long parent_visible_ino;
	dev_t parent_dev;
	dev_t parent_visible_dev;
	u32 parent_fs_type;
	bool parent_internal;
	int err = -EEXIST;

	if (!seed || !parent) {
		if (seed)
			__putname(seed);
		if (parent)
			__putname(parent);
		return -ENOMEM;
	}
	virtual_depth = ksu_nomount_count_components(virtual_path);
	prefix_depth = ksu_nomount_count_components(prefix_path);
	if (!virtual_depth || !prefix_depth || prefix_depth >= virtual_depth)
		goto out;
	err = ksu_nomount_trim_components(prefix_path, 1, parent,
						   KSU_NOMOUNT_MAX_PATH);
	if (err)
		goto out;
	err = ksu_nomount_parent_identity_locked(
		parent, NULL, &parent_ino, &parent_dev, &parent_visible_ino,
		&parent_visible_dev, &parent_fs_type, &parent_internal);
	if (err)
		goto out;

	if (!whiteout && real_path && real_path[0]) {
		if (strscpy(seed, real_path, KSU_NOMOUNT_MAX_PATH) < 0) {
			err = -ENAMETOOLONG;
			goto out;
		}
		trim = virtual_depth - prefix_depth;
	} else {
		err = ksu_nomount_trim_components(prefix_path, 1, seed,
						   KSU_NOMOUNT_MAX_PATH);
		if (err)
			goto out;
		parent_rule = ksu_nomount_find_rule_locked(seed);
		if (parent_rule) {
			if (parent_rule->d_type != DT_DIR ||
			    (parent_rule->flags & KSU_NOMOUNT_FLAG_WHITEOUT)) {
				err = -ENOTDIR;
				goto out;
			}
			if (strscpy(seed, parent_rule->real_path,
				    KSU_NOMOUNT_MAX_PATH) < 0) {
				err = -ENAMETOOLONG;
				goto out;
			}
		}
		trim = 0;
	}

	/*
	 * Each synthetic directory needs a distinct backend identity so readdir
	 * can select one virtual child set from the inode alone.  Prefer the
	 * matching real ancestor, then walk upward until an unused anchor exists.
	 */
	max_trim = ksu_nomount_count_components(seed);
	if (trim > max_trim)
		trim = max_trim;
	for (; trim <= max_trim; trim++) {
		err = ksu_nomount_trim_components(seed, trim, out,
						   KSU_NOMOUNT_MAX_PATH);
		if (err)
			goto out;
		if (!ksu_nomount_internal_anchor_status_locked(out, parent_ino,
								 parent_dev)) {
			err = 0;
			goto out;
		}
	}
	err = -EEXIST;
out:
	__putname(parent);
	__putname(seed);
	return err;
}

static int ksu_nomount_create_missing_ancestors_locked(
	const char *virtual_path, const char *real_path, bool whiteout,
	const struct kstatfs *visible_statfs,
	struct list_head *rule_victims, struct list_head *parent_victims)
{
	char *prefix = __getname();
	char *internal_real = __getname();
	char *last_created = __getname();
	unsigned int depth = ksu_nomount_count_components(virtual_path);
	unsigned int i;
	int err = 0;

	if (!prefix || !internal_real || !last_created) {
		err = -ENOMEM;
		goto out;
	}
	last_created[0] = '\0';
	for (i = 1; i < depth; i++) {
		struct ksu_nomount_rule *existing;
		struct ksu_nomount_rule *rule;
		struct path resolved;
		struct inode *inode;

		err = ksu_nomount_prefix_components(virtual_path, i, prefix,
						     KSU_NOMOUNT_MAX_PATH);
		if (err)
			goto prune;
		existing = ksu_nomount_find_rule_locked(prefix);
		if (existing) {
			if (existing->d_type != DT_DIR) {
				err = -ENOTDIR;
				goto prune;
			}
			continue;
		}
		err = ksu_nomount_real_dir_status(prefix);
		if (!err)
			continue;
		if (err != -ENOENT)
			goto prune;
		err = ksu_nomount_select_internal_real_path(
			virtual_path, prefix, real_path, whiteout, internal_real);
		if (err)
			goto prune;
		err = ksu_nomount_resolve_path_flags(
			internal_real, LOOKUP_FOLLOW, &resolved);
		if (err)
			goto prune;
		inode = d_backing_inode(resolved.dentry);
		if (!inode || !S_ISDIR(inode->i_mode)) {
			path_put(&resolved);
			err = -ENOTDIR;
			goto prune;
		}
			rule = ksu_nomount_alloc_rule(
				prefix, internal_real,
				KSU_NOMOUNT_FLAG_INTERNAL | KSU_NOMOUNT_FLAG_IS_DIR,
				DT_DIR, &resolved, false, 0, 0, visible_statfs);
		path_put(&resolved);
		if (IS_ERR(rule)) {
			err = PTR_ERR(rule);
			goto prune;
		}
		err = ksu_nomount_publish_rule_locked(rule, rule_victims,
						      parent_victims);
		if (err) {
			ksu_nomount_rule_free(rule);
			goto prune;
		}
		strscpy(last_created, prefix, KSU_NOMOUNT_MAX_PATH);
	}
	goto out;

prune:
	if (last_created[0])
		ksu_nomount_prune_internal_ancestors_locked(
			last_created, rule_victims, parent_victims);
out:
	if (prefix)
		__putname(prefix);
	if (internal_real)
		__putname(internal_real);
	if (last_created)
		__putname(last_created);
	return err;
}

static void ksu_nomount_release_victims(struct list_head *rule_victims,
					struct list_head *parent_victims)
{
	struct ksu_nomount_rule *rule, *rule_tmp;
	struct ksu_nomount_parent *parent, *parent_tmp;

	if (list_empty(rule_victims) && list_empty(parent_victims))
		return;
	synchronize_rcu();
	list_for_each_entry_safe(rule, rule_tmp, rule_victims, gc_node) {
		list_del(&rule->gc_node);
		ksu_nomount_rule_free(rule);
	}
	list_for_each_entry_safe(parent, parent_tmp, parent_victims, all_node) {
		list_del(&parent->all_node);
		kfree(parent->path);
		kfree(parent);
	}
}

int ksu_nomount_add_rule(const char *virtual_path, const char *real_path,
			 u32 flags)
{
	char *normalized_virtual = __getname();
	char *normalized_real = __getname();
	char *parent_path = __getname();
	const char *unused_name;
	struct ksu_nomount_rule *rule = NULL;
	struct path backend;
	struct path visible;
	struct inode *inode;
	struct kstatfs visible_statfs = { };
	unsigned long visible_ino = 0;
	dev_t visible_dev = 0;
	u8 d_type = DT_REG;
	bool backend_resolved = false;
	bool visible_exists = false;
	bool whiteout = flags & KSU_NOMOUNT_FLAG_WHITEOUT;
	LIST_HEAD(rule_victims);
	LIST_HEAD(parent_victims);
	int err;

	if (!normalized_virtual || !normalized_real || !parent_path) {
		err = -ENOMEM;
		goto out;
	}
	flags &= ~KSU_NOMOUNT_FLAG_INTERNAL;
	err = ksu_nomount_normalize_path(normalized_virtual,
					 KSU_NOMOUNT_MAX_PATH, virtual_path);
	if (err)
		goto out;
	err = ksu_nomount_split_path(normalized_virtual, parent_path,
				     KSU_NOMOUNT_MAX_PATH, &unused_name);
	if (err)
		goto out;

	normalized_real[0] = '\0';
	if (!whiteout) {
		if (!real_path) {
			err = -EINVAL;
			goto out;
		}
		err = ksu_nomount_normalize_path(normalized_real,
						 KSU_NOMOUNT_MAX_PATH, real_path);
		if (err)
			goto out;
		if (strlen(normalized_real) >= KSU_NOMOUNT_EMBEDDED_NAME_MAX) {
			err = -ENAMETOOLONG;
			goto out;
		}
		/* Keep the final symlink dentry.  Normal opens/readlink then apply
		 * their own follow/no-follow semantics after the pathname has been
		 * redirected, while rule metadata and readdir retain DT_LNK. */
		err = ksu_nomount_resolve_path_flags(
			normalized_real, KSU_NOMOUNT_LOOKUP_NOFOLLOW, &backend);
		if (err)
			goto out;
		backend_resolved = true;
		inode = d_backing_inode(backend.dentry);
		if (!inode) {
			err = -ENOENT;
			goto out;
		}
		if (S_ISDIR(inode->i_mode))
			d_type = DT_DIR;
		else if (S_ISREG(inode->i_mode))
			d_type = DT_REG;
		else if (S_ISLNK(inode->i_mode))
			d_type = DT_LNK;
		else {
			err = -EOPNOTSUPP;
			goto out;
		}
	}

	if (!ksu_nomount_resolve_path_flags(normalized_virtual,
					     KSU_NOMOUNT_LOOKUP_NOFOLLOW,
						     &visible)) {
		inode = d_backing_inode(visible.dentry);
		if (inode) {
			visible_exists = true;
			visible_ino = inode->i_ino;
			visible_dev = inode->i_sb->s_dev;
		}
		path_put(&visible);
	}
	if (!whiteout) {
		const char *statfs_path = visible_exists ? normalized_virtual :
							 parent_path;

		err = ksu_nomount_capture_visible_statfs(statfs_path,
							&visible_statfs);
		if (err)
			goto out;
	}
	rule = ksu_nomount_alloc_rule(
		normalized_virtual, normalized_real, flags,
		whiteout ? DT_REG : d_type, backend_resolved ? &backend : NULL,
		visible_exists, visible_ino, visible_dev,
		whiteout ? NULL : &visible_statfs);
	if (IS_ERR(rule)) {
		err = PTR_ERR(rule);
		rule = NULL;
		goto out;
	}
	if (backend_resolved) {
		path_put(&backend);
		backend_resolved = false;
	}

	mutex_lock(&ksu_nomount_lock);
	err = ksu_nomount_create_missing_ancestors_locked(
			normalized_virtual, normalized_real, whiteout,
			whiteout ? NULL : &rule->visible_statfs, &rule_victims,
			&parent_victims);
	if (!err)
		err = ksu_nomount_publish_rule_locked(
			rule, &rule_victims, &parent_victims);
	if (err)
		ksu_nomount_prune_internal_ancestors_locked(
			parent_path, &rule_victims, &parent_victims);
	mutex_unlock(&ksu_nomount_lock);
	ksu_nomount_release_victims(&rule_victims, &parent_victims);
	if (err)
		goto out;
	rule = NULL;

out:
	if (backend_resolved)
		path_put(&backend);
	ksu_nomount_rule_free(rule);
	if (normalized_virtual)
		__putname(normalized_virtual);
	if (normalized_real)
		__putname(normalized_real);
	if (parent_path)
		__putname(parent_path);
	return err;
}

int ksu_nomount_del_rule(const char *virtual_path)
{
	char *normalized = __getname();
	char *parent_path = __getname();
	const char *unused_name;
	LIST_HEAD(rule_victims);
	LIST_HEAD(parent_victims);
	int err;

	if (!normalized || !parent_path) {
		err = -ENOMEM;
		goto out;
	}
	err = ksu_nomount_normalize_path(normalized, KSU_NOMOUNT_MAX_PATH,
					 virtual_path);
	if (err)
		goto out;
	err = ksu_nomount_split_path(normalized, parent_path,
				     KSU_NOMOUNT_MAX_PATH, &unused_name);
	if (err)
		goto out;

	mutex_lock(&ksu_nomount_lock);
	err = ksu_nomount_del_normalized_locked(
		normalized, parent_path, &rule_victims, &parent_victims, true);
	mutex_unlock(&ksu_nomount_lock);
	ksu_nomount_release_victims(&rule_victims, &parent_victims);
out:
	if (normalized)
		__putname(normalized);
	if (parent_path)
		__putname(parent_path);
	return err;
}

static bool ksu_nomount_del_batch_common_parent(char **virtual_paths,
						unsigned int count,
						char *common_parent)
{
	char *normalized = __getname();
	char *parent_path = __getname();
	const char *unused_name;
	unsigned int i;
	bool common = true;

	if (!normalized || !parent_path || !count) {
		common = false;
		goto out;
	}
	for (i = 0; i < count; i++) {
		if (ksu_nomount_normalize_path(normalized,
					       KSU_NOMOUNT_MAX_PATH,
					       virtual_paths[i]) ||
		    ksu_nomount_split_path(normalized, parent_path,
					   KSU_NOMOUNT_MAX_PATH,
					   &unused_name)) {
			common = false;
			break;
		}
		if (!i) {
			if (strscpy(common_parent, parent_path,
				    KSU_NOMOUNT_MAX_PATH) < 0) {
				common = false;
				break;
			}
		} else if (strcmp(common_parent, parent_path)) {
			common = false;
			break;
		}
	}
out:
	if (normalized)
		__putname(normalized);
	if (parent_path)
		__putname(parent_path);
	return common;
}

int ksu_nomount_del_rules(char **virtual_paths, unsigned int count)
{
	char *common_parent = __getname();
	char *normalized = __getname();
	char *parent_path = __getname();
	const char *unused_name;
	LIST_HEAD(rule_victims);
	LIST_HEAD(parent_victims);
	unsigned int i;
	bool deleted = false;
	int first_err = 0;

	if (!count)
		goto out;
	if (!common_parent || !normalized || !parent_path ||
	    !ksu_nomount_del_batch_common_parent(virtual_paths, count,
						 common_parent)) {
		for (i = 0; i < count; i++) {
			int err = ksu_nomount_del_rule(virtual_paths[i]);

			if (err && !first_err)
				first_err = err;
		}
		goto out;
	}

	mutex_lock(&ksu_nomount_lock);
	for (i = 0; i < count; i++) {
		int err;

		err = ksu_nomount_normalize_path(normalized,
						 KSU_NOMOUNT_MAX_PATH,
						 virtual_paths[i]);
		if (!err)
			err = ksu_nomount_split_path(normalized, parent_path,
						     KSU_NOMOUNT_MAX_PATH,
						     &unused_name);
		if (!err)
			err = ksu_nomount_del_normalized_locked(
				normalized, parent_path, &rule_victims,
				&parent_victims, false);
		if (err) {
			if (!first_err)
				first_err = err;
		} else {
			deleted = true;
		}
	}
	if (deleted)
		ksu_nomount_prune_internal_ancestors_locked(
			common_parent, &rule_victims, &parent_victims);
	mutex_unlock(&ksu_nomount_lock);
	ksu_nomount_release_victims(&rule_victims, &parent_victims);
out:
	if (common_parent)
		__putname(common_parent);
	if (normalized)
		__putname(normalized);
	if (parent_path)
		__putname(parent_path);
	return first_err;
}

void ksu_nomount_clear_all(void)
{
	struct ksu_nomount_rule *rule, *rule_tmp;
	struct ksu_nomount_uid *uid, *uid_tmp;
	struct ksu_nomount_parent *parent, *parent_tmp;
	struct ksu_nomount_child_array *children;
	struct hlist_node *tmp;
	LIST_HEAD(rule_victims);
	LIST_HEAD(uid_victims);
	LIST_HEAD(parent_victims);
	int bkt;

	mutex_lock(&ksu_nomount_lock);
	hash_for_each_safe(ksu_nomount_rules, bkt, tmp, rule, path_node) {
		ksu_nomount_unlink_rule_locked(rule);
		list_add_tail(&rule->gc_node, &rule_victims);
	}
	hash_for_each_safe(ksu_nomount_uids, bkt, tmp, uid, node) {
		hash_del_rcu(&uid->node);
		list_add_tail(&uid->gc_node, &uid_victims);
	}
	list_for_each_entry_safe(parent, parent_tmp, &ksu_nomount_parent_list,
				 all_node) {
		hash_del_rcu(&parent->path_node);
		if (parent->inode_hashed)
			hash_del_rcu(&parent->inode_node);
		list_del(&parent->all_node);
		children = rcu_dereference_protected(
			parent->children, lockdep_is_held(&ksu_nomount_lock));
		rcu_assign_pointer(parent->children, NULL);
		ksu_nomount_child_array_put(children);
		list_add_tail(&parent->all_node, &parent_victims);
	}
	if (atomic_read(&ksu_nomount_rule_count))
		static_branch_disable(&ksu_nomount_active_rules);
	if (atomic_read(&ksu_nomount_uid_count))
		static_branch_disable(&ksu_nomount_active_uids);
	atomic_set(&ksu_nomount_rule_count, 0);
	atomic_set(&ksu_nomount_uid_count, 0);
	mutex_unlock(&ksu_nomount_lock);

	synchronize_rcu();
	list_for_each_entry_safe(rule, rule_tmp, &rule_victims, gc_node) {
		list_del(&rule->gc_node);
		ksu_nomount_rule_free(rule);
	}
	list_for_each_entry_safe(uid, uid_tmp, &uid_victims, gc_node) {
		list_del(&uid->gc_node);
		kfree(uid);
	}
	list_for_each_entry_safe(parent, parent_tmp, &parent_victims, all_node) {
		list_del(&parent->all_node);
		kfree(parent->path);
		kfree(parent);
	}
}

int ksu_nomount_add_uid(uid_t uid)
{
	struct ksu_nomount_uid *entry, *existing;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;
	INIT_LIST_HEAD(&entry->gc_node);
	entry->uid = uid;
	mutex_lock(&ksu_nomount_lock);
	hash_for_each_possible(ksu_nomount_uids, existing, node, uid) {
		if (existing->uid == uid) {
			mutex_unlock(&ksu_nomount_lock);
			kfree(entry);
			return -EEXIST;
		}
	}
	hash_add_rcu(ksu_nomount_uids, &entry->node, uid);
	if (atomic_inc_return(&ksu_nomount_uid_count) == 1)
		static_branch_enable(&ksu_nomount_active_uids);
	mutex_unlock(&ksu_nomount_lock);
	return 0;
}

int ksu_nomount_del_uid(uid_t uid)
{
	struct ksu_nomount_uid *entry;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&ksu_nomount_lock);
	hash_for_each_safe(ksu_nomount_uids, bkt, tmp, entry, node) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->node);
			if (atomic_dec_return(&ksu_nomount_uid_count) == 0)
				static_branch_disable(&ksu_nomount_active_uids);
			mutex_unlock(&ksu_nomount_lock);
			synchronize_rcu();
			kfree(entry);
			return 0;
		}
	}
	mutex_unlock(&ksu_nomount_lock);
	return -ENOENT;
}

int ksu_nomount_get_dump_rule(struct ksu_nomount_dump_state *state,
				      char *virtual_path, size_t virtual_size,
				      char *real_path, size_t real_size, u32 *flags)
{
	struct ksu_nomount_rule *rule;
	u32 bucket;
	int ret = -ENOENT;

	if (!state || !virtual_path || !real_path || !flags)
		return -EINVAL;

	rcu_read_lock();
	for (bucket = state->bucket; bucket < HASH_SIZE(ksu_nomount_rules);
	     bucket++) {
		u32 skip = bucket == state->bucket ? state->index : 0;

		hlist_for_each_entry_rcu(rule, &ksu_nomount_rules[bucket],
					 path_node) {
			u32 rule_flags = READ_ONCE(rule->flags);

			if (rule_flags & KSU_NOMOUNT_FLAG_INTERNAL)
				continue;
			if (skip) {
				skip--;
				continue;
			}
			if (strscpy(virtual_path, rule->virtual_path,
				    virtual_size) < 0 ||
			    strscpy(real_path, rule->real_path, real_size) < 0) {
				ret = -ENAMETOOLONG;
				goto out_unlock;
			}
			*flags = rule_flags & ~KSU_NOMOUNT_FLAG_INTERNAL;
			state->bucket = bucket;
			state->index = state->index + 1;
			ret = 0;
			goto out_unlock;
		}
		state->index = 0;
	}
	state->bucket = HASH_SIZE(ksu_nomount_rules);
	state->index = 0;

out_unlock:
	rcu_read_unlock();
	return ret;
}

static const char *ksu_nomount_build_path_from_dfd(
	int dfd, const char *relative, size_t relative_len, size_t *out_len,
	const char **out_path, char *fast_buf)
{
	struct path base;
	struct fd f = { };
	struct inode *inode;
	char *page_buf = fast_buf;
	char *base_path;
	size_t dir_len, capacity = 512;

	if (dfd == AT_FDCWD) {
		get_fs_pwd(current->fs, &base);
	} else {
		f = fdget_raw(dfd);
		if (!f.file)
			return NULL;
		inode = file_inode(f.file);
		if (!inode || !S_ISDIR(inode->i_mode)) {
			fdput(f);
			return NULL;
		}
		base = f.file->f_path;
		path_get(&base);
		fdput(f);
	}
	base_path = d_path(&base, page_buf, capacity);
	if (IS_ERR(base_path) && PTR_ERR(base_path) == -ENAMETOOLONG) {
		page_buf = __getname();
		if (!page_buf) {
			path_put(&base);
			return NULL;
		}
		capacity = KSU_NOMOUNT_MAX_PATH;
		base_path = d_path(&base, page_buf, capacity);
	}
	path_put(&base);
	if (IS_ERR(base_path)) {
		if (page_buf != fast_buf)
			__putname(page_buf);
		return NULL;
	}
	dir_len = strlen(base_path);
	if (dir_len + relative_len + 2 > capacity) {
		if (page_buf != fast_buf)
			__putname(page_buf);
		return NULL;
	}
	if (base_path != page_buf)
		memmove(page_buf, base_path, dir_len + 1);
	if (dir_len && page_buf[dir_len - 1] != '/')
		page_buf[dir_len++] = '/';
	memcpy(page_buf + dir_len, relative, relative_len + 1);
	*out_len = dir_len + relative_len;
	*out_path = page_buf;
	return page_buf;
}

struct filename *ksu_nomount_handle_getname(struct filename *name)
{
	const char *path;
	const char *page_buf = NULL;
	char *canonical_buf = NULL;
	char fast_buf[512];
	struct ksu_nomount_inode_identity
		scope_ancestors[KSU_NOMOUNT_MAX_ANCESTORS];
	struct ksu_nomount_rule *rule;
	size_t len;
	size_t dir_prefix_len = 0;
	size_t name_capacity;
	unsigned long scope_real_ino = 0;
	unsigned long scope_visible_ino = 0;
	dev_t scope_real_dev = 0;
	dev_t scope_visible_dev = 0;
	u16 scope_ancestor_count = 0;
	u16 i;
	int err = 0;
	bool matched = false;
	bool have_private = false;
	bool needs_access_scope = false;
	bool nomount_active;
	bool susfs_active;
	bool private = false;
	bool whiteout = false;
	bool preserve_real_ino = false;

	if (IS_ERR_OR_NULL(name) || !name->name)
		return name;
	if (ksu_nomount_bypass_active())
		return name;

	nomount_active = !ksu_nomount_should_skip();
	susfs_active = ksu_susfs_path_filter_active();
	if (!nomount_active && !susfs_active)
		return name;

	path = name->name;
	len = strlen(path);
	name_capacity = name->name == name->iname ?
		KSU_NOMOUNT_EMBEDDED_NAME_MAX : KSU_NOMOUNT_MAX_PATH;
	/* Preserve AT_EMPTY_PATH and other empty-name VFS semantics. */
	if (!len)
		return name;
	if (len == 1 && path[0] == '/')
		return name;
	if (path[0] != '/') {
		bool relative_candidate = false;

		if (nomount_active)
			relative_candidate =
				ksu_nomount_relative_rule_may_match(path, len);
		if (!relative_candidate && susfs_active)
			relative_candidate =
				ksu_susfs_relative_hide_rule_may_match(path, len);
		if (!relative_candidate)
			return name;
		page_buf = ksu_nomount_build_path_from_dfd(
			ksu_nomount_current_lookup_dfd(), path, len, &len, &path,
			fast_buf);
		if (!page_buf)
			return name;
		if (ksu_nomount_path_needs_canonicalize(path, len))
			len = ksu_nomount_collapse_slashes((char *)path);
	} else if (ksu_nomount_path_needs_canonicalize(path, len)) {
		if (len + 1 <= sizeof(fast_buf))
			canonical_buf = fast_buf;
		else
			canonical_buf = __getname();
		if (!canonical_buf)
			return name;
		memcpy(canonical_buf, path, len + 1);
		path = canonical_buf;
		len = ksu_nomount_collapse_slashes(canonical_buf);
	}

	if (susfs_active && ksu_susfs_should_hide_path(path, len)) {
		whiteout = true;
		goto out;
	}

	if (!nomount_active)
		goto out;

	rcu_read_lock();
	have_private = !list_empty(&ksu_nomount_private_paths);
	rule = ksu_nomount_find_rule_rcu_len(path, len);
	if (rule) {
		u32 rule_flags = READ_ONCE(rule->flags);

		matched = true;
		if (rule_flags & KSU_NOMOUNT_FLAG_WHITEOUT)
			whiteout = true;
		else {
			needs_access_scope = true;
			scope_real_ino = READ_ONCE(rule->real_ino);
			scope_real_dev = READ_ONCE(rule->real_dev);
			scope_visible_ino = READ_ONCE(rule->visible_ino);
			scope_visible_dev = READ_ONCE(rule->visible_dev);
			scope_ancestor_count = READ_ONCE(rule->ancestor_count);
			if (scope_ancestor_count > KSU_NOMOUNT_MAX_ANCESTORS) {
				err = -E2BIG;
				goto unlock;
			}
			for (i = 0; i < scope_ancestor_count; i++) {
				scope_ancestors[i].ino =
					READ_ONCE(rule->ancestors[i].ino);
				scope_ancestors[i].dev =
					READ_ONCE(rule->ancestors[i].dev);
			}
			if (rule->real_len + 1 > name_capacity) {
				err = -ENAMETOOLONG;
				goto unlock;
			}
			memcpy((char *)name->name, rule->real_path,
			       rule->real_len + 1);
		}
	} else {
		rule = ksu_nomount_find_dir_prefix_rule_rcu(path, len,
							    &dir_prefix_len);
		if (rule) {
			size_t suffix_len = len - dir_prefix_len;
			size_t replacement_len = rule->real_len + suffix_len;

			if (replacement_len + 1 > name_capacity) {
				err = -ENAMETOOLONG;
				goto unlock;
			}
			matched = true;
			needs_access_scope = true;
			scope_real_ino = READ_ONCE(rule->real_ino);
			scope_real_dev = READ_ONCE(rule->real_dev);
			scope_visible_dev = READ_ONCE(rule->visible_dev);
			scope_ancestor_count = READ_ONCE(rule->ancestor_count);
			if (scope_ancestor_count > KSU_NOMOUNT_MAX_ANCESTORS) {
				err = -E2BIG;
				goto unlock;
			}
			for (i = 0; i < scope_ancestor_count; i++) {
				scope_ancestors[i].ino =
					READ_ONCE(rule->ancestors[i].ino);
				scope_ancestors[i].dev =
					READ_ONCE(rule->ancestors[i].dev);
			}
			preserve_real_ino = true;
			memmove((char *)name->name + rule->real_len,
				 path + dir_prefix_len, suffix_len);
			memcpy((char *)name->name, rule->real_path,
			       rule->real_len);
			((char *)name->name)[replacement_len] = '\0';
		} else if (current_uid().val >= 10000 && have_private) {
			private = ksu_nomount_path_is_private_rcu(path, len);
		}
	}

unlock:
	rcu_read_unlock();

	if (!err && matched && needs_access_scope &&
	    (current_uid().val != 0 || preserve_real_ino))
		err = ksu_nomount_access_scope_enter(
			scope_real_ino, scope_real_dev, scope_visible_ino,
			scope_visible_dev, preserve_real_ino, scope_ancestors,
			scope_ancestor_count);

out:
	if (canonical_buf && canonical_buf != fast_buf)
		__putname(canonical_buf);
	if (page_buf && page_buf != fast_buf)
		__putname(page_buf);
	if (err) {
		putname(name);
		return ERR_PTR(err);
	}
	if (private) {
		putname(name);
		return ERR_PTR(-ENOENT);
	}
	if (whiteout) {
		putname(name);
		return ERR_PTR(-ENOENT);
	}
	return name;
}

static loff_t ksu_nomount_magic_pos(void)
{
#ifdef CONFIG_COMPAT
	if (in_compat_syscall())
		return KSU_NOMOUNT_COMPAT_MAGIC_POS;
#endif
	return KSU_NOMOUNT_MAGIC_POS;
}

static struct ksu_nomount_child_array *
ksu_nomount_get_children_for_inode(struct inode *inode, bool *internal,
				   unsigned long *visible_ino,
				   unsigned long *parent_visible_ino)
{
	struct ksu_nomount_child_array *children = NULL;
	struct ksu_nomount_parent *parent;

	if (!inode || !inode->i_sb || ksu_nomount_should_skip())
		return NULL;
	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_nomount_parent_inodes, parent,
				   inode_node, inode->i_ino) {
		if (READ_ONCE(parent->ino) != inode->i_ino ||
		    READ_ONCE(parent->dev) != inode->i_sb->s_dev)
			continue;
		children = rcu_dereference(parent->children);
		if (children && atomic_inc_not_zero(&children->refcnt)) {
			const char *slash = strrchr(parent->path, '/');
			size_t parent_len = slash == parent->path ? 1 :
							       slash - parent->path;
			struct ksu_nomount_parent *virtual_parent;
			u32 hash = ksu_nomount_hash_path_len(parent->path,
							     parent_len);

			*internal = READ_ONCE(parent->internal);
			*visible_ino = READ_ONCE(parent->visible_ino);
			*parent_visible_ino = *visible_ino;
			hash_for_each_possible_rcu(ksu_nomount_parents,
						   virtual_parent, path_node,
						   hash) {
				if (strlen(virtual_parent->path) == parent_len &&
				    !memcmp(virtual_parent->path, parent->path,
					    parent_len)) {
					*parent_visible_ino = READ_ONCE(
						virtual_parent->visible_ino);
					break;
				}
			}
			break;
		}
		children = NULL;
	}
	rcu_read_unlock();
	return children;
}

static bool ksu_nomount_parent_has_child_rcu(unsigned long parent_ino,
					     dev_t parent_dev,
					     const char *name, int namelen)
{
	struct ksu_nomount_rule *rule;
	u32 name_hash;
	bool found = false;

	if (namelen < 0 || namelen > U16_MAX)
		return false;
	name_hash = ksu_nomount_hash_path_len(name, namelen);

	rcu_read_lock();
	hash_for_each_possible_rcu(ksu_nomount_basenames, rule, basename_node,
				   name_hash) {
		struct ksu_nomount_parent *parent;

		if (READ_ONCE(rule->basename_hash) != name_hash ||
		    READ_ONCE(rule->basename_len) != (u16)namelen)
			continue;
		if (READ_ONCE(rule->visible_exists))
			continue;
		parent = READ_ONCE(rule->parent);
		if (!parent ||
		    READ_ONCE(parent->ino) != parent_ino ||
		    READ_ONCE(parent->dev) != parent_dev)
			continue;
		if (!memcmp(rule->name, name, namelen)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

static KSU_SUSFS_ACTOR_RET ksu_nomount_iter_actor(
	struct dir_context *ctx, const char *name, int namelen, loff_t offset,
	u64 ino, unsigned int d_type)
{
	struct ksu_nomount_iter_ctx *proxy =
		container_of(ctx, struct ksu_nomount_iter_ctx, ctx);
	KSU_SUSFS_ACTOR_RET ret;

	if (ksu_nomount_parent_has_child_rcu(proxy->parent_ino,
					     proxy->parent_dev, name, namelen))
		return KSU_SUSFS_ACTOR_CONTINUE;
	if (namelen == 1 && name[0] == '.')
		ino = proxy->visible_ino;
	else if (namelen == 2 && name[0] == '.' && name[1] == '.')
		ino = proxy->parent_visible_ino;
	proxy->orig_ctx->pos = proxy->ctx.pos;
	ret = proxy->orig_ctx->actor(proxy->orig_ctx, name, namelen, offset,
				     ino, d_type);
	proxy->ctx.pos = proxy->orig_ctx->pos;
	return ret;
}

static int ksu_nomount_call_real_iterate(struct file *file,
					 struct dir_context *ctx)
{
#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
	if (file->f_op->iterate_shared)
		return file->f_op->iterate_shared(file, ctx);
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
	if (file->f_op->iterate)
		return file->f_op->iterate(file, ctx);
#endif
	return -ENOTDIR;
}

static void ksu_nomount_emit_children_array(
	struct ksu_nomount_child_array *children, struct dir_context *ctx)
{
	loff_t magic = ksu_nomount_magic_pos();
	unsigned long start = 0;
	u32 i;
	u32 limit = ksu_nomount_child_count(children);

	if (ctx->pos >= magic &&
	    ctx->pos < magic + KSU_NOMOUNT_MAGIC_WINDOW)
		start = ctx->pos - magic;
	else
		ctx->pos = magic;
	for (i = start; i < limit; i++) {
		const struct ksu_nomount_child *child = &children->entries[i];
		const char *name;
		u16 child_len;
		u8 flags = ksu_nomount_child_flags_rcu(child);

		if (flags & KSU_NOMOUNT_CHILD_DELETED) {
			ctx->pos = magic + i + 1;
			continue;
		}
		if (flags & KSU_NOMOUNT_CHILD_NATIVE) {
			ctx->pos = magic + i + 1;
			continue;
		}
		if (flags & KSU_NOMOUNT_FLAG_WHITEOUT) {
			ctx->pos = magic + i + 1;
			continue;
		}
		child_len = READ_ONCE(child->name_len);
		name = ksu_nomount_child_name(children, child);
		if (!dir_emit(ctx, name, child_len, child->ino, child->d_type))
			break;
		ctx->pos = magic + i + 1;
	}
}

static bool ksu_nomount_emit_internal_dots(struct dir_context *ctx,
					  unsigned long visible_ino,
					  unsigned long parent_visible_ino)
{
	if (ctx->pos == 0) {
		if (!dir_emit(ctx, ".", 1, visible_ino, DT_DIR))
			return false;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (!dir_emit(ctx, "..", 2, parent_visible_ino, DT_DIR))
			return false;
		ctx->pos = 2;
	}
	return true;
}

int ksu_nomount_handle_iterate_dir(struct file *file,
				   struct dir_context *ctx)
{
	struct ksu_nomount_child_array *children;
	struct ksu_nomount_iter_ctx proxy;
	struct inode *inode = file_inode(file);
	bool internal = false;
	unsigned long visible_ino = 0;
	unsigned long parent_visible_ino = 0;
	loff_t old_pos = ctx->pos;
	loff_t magic = ksu_nomount_magic_pos();
	int ret;

	children = ksu_nomount_get_children_for_inode(
		inode, &internal, &visible_ino, &parent_visible_ino);
	if (!children)
		return ksu_nomount_call_real_iterate(file, ctx);
	if (internal) {
		if (!ksu_nomount_emit_internal_dots(ctx, visible_ino,
						     parent_visible_ino)) {
			ksu_nomount_child_array_put(children);
			return 0;
		}
		ksu_nomount_emit_children_array(children, ctx);
		ksu_nomount_child_array_put(children);
		return 0;
	}
	if (ctx->pos >= magic &&
	    ctx->pos < magic + KSU_NOMOUNT_MAGIC_WINDOW) {
		ksu_nomount_emit_children_array(children, ctx);
		ksu_nomount_child_array_put(children);
		return 0;
	}

	memset(&proxy, 0, sizeof(proxy));
	proxy.ctx.actor = ksu_nomount_iter_actor;
	proxy.ctx.pos = ctx->pos;
	proxy.orig_ctx = ctx;
	proxy.children = children;
	proxy.parent_ino = inode->i_ino;
	proxy.visible_ino = visible_ino;
	proxy.parent_visible_ino = parent_visible_ino;
	proxy.parent_dev = inode->i_sb->s_dev;
	ret = ksu_nomount_call_real_iterate(file, &proxy.ctx);
	ctx->pos = proxy.ctx.pos;
	if (ret >= 0 && (ctx->pos == old_pos || ctx->pos >= magic))
		ksu_nomount_emit_children_array(children, ctx);
	ksu_nomount_child_array_put(children);
	return ret;
}

bool ksu_nomount_handle_permission(struct inode *inode, int mask)
{
	struct ksu_nomount_access_scope *scope;
	unsigned long irq_flags;
	bool injected = false;
	bool traversal = false;
	struct ksu_nomount_access_scope *matched_scope = NULL;
	u16 i;

	if (!inode || !inode->i_sb || ksu_nomount_should_skip() ||
	    !atomic_read(&ksu_nomount_access_scope_count))
		return false;

	spin_lock_irqsave(&ksu_nomount_access_scope_lock, irq_flags);
	hash_for_each_possible(ksu_nomount_access_scopes, scope, node,
			       (unsigned long)current) {
		if (scope->task != current)
			continue;
		if (!scope->permission_consumed &&
		    scope->real_ino == inode->i_ino &&
		    scope->real_dev == inode->i_sb->s_dev) {
			injected = true;
			matched_scope = scope;
			break;
		}
		if (scope->permission_consumed || !S_ISDIR(inode->i_mode))
			continue;
		for (i = 0; i < scope->ancestor_count; i++) {
			if (scope->ancestors[i].ino == inode->i_ino &&
			    scope->ancestors[i].dev == inode->i_sb->s_dev) {
				traversal = true;
				break;
			}
		}
	}
	if (matched_scope)
		matched_scope->permission_consumed = true;
	spin_unlock_irqrestore(&ksu_nomount_access_scope_lock, irq_flags);
	if (injected)
		return !(mask & (MAY_WRITE | MAY_APPEND));
	if (traversal)
		return (mask & MAY_EXEC) &&
		       !(mask & (MAY_READ | MAY_WRITE | MAY_APPEND));
	return false;
}

char *ksu_nomount_handle_dpath(const struct path *path, char *buf, int buflen,
				       const char *native_path)
{
	struct ksu_nomount_rule *rule;
	struct inode *inode;
	char *result = NULL;
	size_t prefix_len = 0;
	size_t native_len;
	size_t suffix_len;
	size_t result_len;

	/* The virtual path may fit even when native d_path() returned ENAMETOOLONG. */
	(void)native_path;
	if (!path || !path->dentry || !buf || buflen <= 0 ||
	    ksu_nomount_should_skip())
		return NULL;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return NULL;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule && buflen > rule->virtual_len) {
		result = buf + buflen - rule->virtual_len - 1;
		memcpy(result, rule->virtual_path, rule->virtual_len + 1);
	} else if (native_path && !IS_ERR(native_path)) {
		native_len = strlen(native_path);
		rule = ksu_nomount_find_real_dir_prefix_rule_rcu(
			native_path, strlen(native_path), &prefix_len);
		if (rule) {
			suffix_len = native_len - prefix_len;
			result_len = rule->virtual_len + suffix_len;
			if (result_len + 1 <= (size_t)buflen) {
				result = buf + buflen - result_len - 1;
				memmove(result + rule->virtual_len,
					native_path + prefix_len, suffix_len + 1);
				memcpy(result, rule->virtual_path,
				       rule->virtual_len);
			}
		}
	}
	rcu_read_unlock();
	return result;
}

void ksu_nomount_handle_getattr(long ret, const struct path *path,
				struct kstat *stat)
{
	struct ksu_nomount_rule *rule;
	struct inode *inode;

	if (ret || !path || !path->dentry || !stat ||
	    ksu_nomount_should_skip())
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule) {
		stat->ino = rule->visible_ino;
		if (rule->visible_dev)
			stat->dev = rule->visible_dev;
	}
	rcu_read_unlock();
}

/*
 * Descriptor stats still carry the resolved backend path, so use the native
 * d_path to handle a descendant of a redirected directory.  The regular
 * kretprobe path intentionally remains exact/inode-only and allocation-free;
 * branch-link syscall wrappers call this richer variant in process context.
 */
void ksu_nomount_handle_fd_getattr(long ret, const struct path *path,
				   struct kstat *stat)
{
	struct ksu_nomount_bypass bypass;
	struct ksu_nomount_rule *rule;
	struct inode *inode;
	char *page;
	char *native;
	size_t prefix_len = 0;

	if (ret || !path || !path->dentry || !stat ||
		ksu_nomount_should_skip())
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule) {
		stat->ino = rule->visible_ino;
		if (rule->visible_dev)
			stat->dev = rule->visible_dev;
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	page = __getname();
	if (!page)
		return;
	ksu_nomount_bypass_enter(&bypass);
	native = d_path(path, page, KSU_NOMOUNT_MAX_PATH);
	ksu_nomount_bypass_exit(&bypass);
	if (!IS_ERR(native)) {
		rcu_read_lock();
		rule = ksu_nomount_find_real_dir_prefix_rule_rcu(
			native, strlen(native), &prefix_len);
		if (rule && rule->visible_dev)
			stat->dev = rule->visible_dev;
		rcu_read_unlock();
	}
	__putname(page);
}

void ksu_nomount_handle_stat_result(long ret, unsigned long native_ino,
				    dev_t native_dev, struct kstat *stat)
{
	struct ksu_nomount_rule *rule;
	struct ksu_nomount_access_scope *scope;
	unsigned long irq_flags;

	if (ret || !stat || ksu_nomount_should_skip())
		return;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_identity_rcu(native_ino, native_dev);
	if (rule) {
		stat->ino = rule->visible_ino;
		if (rule->visible_dev)
			stat->dev = rule->visible_dev;
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	if (!atomic_read(&ksu_nomount_access_scope_count))
		return;
	spin_lock_irqsave(&ksu_nomount_access_scope_lock, irq_flags);
	hash_for_each_possible(ksu_nomount_access_scopes, scope, node,
				       (unsigned long)current) {
		if (scope->task != current)
			continue;
		/* An exact symlink rule is resolved without LOOKUP_FOLLOW when the
		 * visible operation is lstat/readlink, but a normal stat/open follows
		 * the link and returns the target inode.  Do not apply the symlink's
		 * visible identity to that unrelated target.  Recursive directory
		 * scopes intentionally preserve only the visible device below. */
		if (!scope->preserve_real_ino &&
		    (native_ino != scope->real_ino ||
		     native_dev != scope->real_dev))
			continue;
		if (scope->preserve_real_ino) {
			if (scope->visible_dev)
				stat->dev = scope->visible_dev;
		} else {
			if (scope->visible_ino)
				stat->ino = scope->visible_ino;
			if (scope->visible_dev)
				stat->dev = scope->visible_dev;
		}
		break;
	}
	spin_unlock_irqrestore(&ksu_nomount_access_scope_lock, irq_flags);
}

void ksu_nomount_handle_statfs(long ret, const struct path *path,
				       struct kstatfs *statfs)
{
	struct ksu_nomount_rule *rule;
	struct inode *inode;

	if (ret || !path || !path->dentry || !statfs ||
	    ksu_nomount_should_skip())
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule) {
		if (rule->has_visible_statfs)
			*statfs = rule->visible_statfs;
		else if (rule->fs_type)
			statfs->f_type = rule->fs_type;
	}
	rcu_read_unlock();
}

void ksu_nomount_handle_statfs_path(long ret, const struct path *path,
				    struct kstatfs *statfs)
{
	struct ksu_nomount_bypass bypass;
	struct ksu_nomount_rule *rule;
	struct inode *inode;
	char *page;
	char *native;
	size_t prefix_len = 0;

	if (ret || !path || !path->dentry || !statfs ||
		ksu_nomount_should_skip())
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule) {
		if (rule->has_visible_statfs)
			*statfs = rule->visible_statfs;
		else if (rule->fs_type)
			statfs->f_type = rule->fs_type;
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	page = __getname();
	if (!page)
		return;
	ksu_nomount_bypass_enter(&bypass);
	native = d_path(path, page, KSU_NOMOUNT_MAX_PATH);
	ksu_nomount_bypass_exit(&bypass);
	if (!IS_ERR(native)) {
		rcu_read_lock();
		rule = ksu_nomount_find_real_dir_prefix_rule_rcu(
			native, strlen(native), &prefix_len);
		if (rule) {
			if (rule->has_visible_statfs)
				*statfs = rule->visible_statfs;
			else if (rule->fs_type)
				statfs->f_type = rule->fs_type;
		}
		rcu_read_unlock();
	}
	__putname(page);
}

bool ksu_nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev,
				     unsigned long *ino)
{
	struct ksu_nomount_rule *rule;
	bool matched = false;

	if (!inode || !dev || !ino || ksu_nomount_should_skip())
		return false;
	rcu_read_lock();
	rule = ksu_nomount_find_real_rule_rcu(inode);
	if (rule) {
		*ino = rule->visible_ino;
		if (rule->visible_dev)
			*dev = rule->visible_dev;
		matched = true;
	}
	rcu_read_unlock();
	return matched;
}

void ksu_nomount_init(void)
{
	int err;

	hash_init(ksu_nomount_rules);
	hash_init(ksu_nomount_real_inodes);
	hash_init(ksu_nomount_real_paths);
	hash_init(ksu_nomount_basenames);
	hash_init(ksu_nomount_private_paths_hash);
	hash_init(ksu_nomount_parents);
	hash_init(ksu_nomount_parent_inodes);
	hash_init(ksu_nomount_uids);
	hash_init(ksu_nomount_bypasses);
	hash_init(ksu_nomount_access_scopes);
	hash_init(ksu_nomount_lookup_scopes);
	atomic_set(&ksu_nomount_rule_count, 0);
	atomic_set(&ksu_nomount_uid_count, 0);
	atomic_set(&ksu_nomount_bypass_count, 0);
	atomic_set(&ksu_nomount_access_scope_count, 0);

	err = ksu_nomount_hooks_init();
	if (err) {
		pr_warn("NoMount: required VFS hooks unavailable: %d\n", err);
		return;
	}
	err = ksu_nomount_netlink_init();
	if (err) {
		ksu_nomount_hooks_exit();
		pr_warn("NoMount: Generic Netlink registration failed: %d\n", err);
		return;
	}
	pr_info("NoMount: native pathname redirection initialized\n");
}

void ksu_nomount_exit(void)
{
	ksu_nomount_netlink_exit();
	ksu_nomount_hooks_exit();
	ksu_nomount_clear_all();
	pr_info("NoMount: native pathname redirection exited\n");
}
