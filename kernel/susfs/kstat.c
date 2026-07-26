#include <linux/cred.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
#include <linux/generic-radix-tree.h>
#else
#include <linux/flex_array.h>
#endif
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/huge_mm.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/kdev_t.h>
#include <linux/kprobes.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#ifdef KSU_SUSFS_HAS_MM_WALK_OPS
#include <linux/pagewalk.h>
#endif
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/rmap.h>
#include <linux/seq_file.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "proc/internal.h"

#include "arch.h"
#include "hook/patch_memory.h"
#include "infra/symbol_resolver.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
#include "nomount/nomount.h"
#endif
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "susfs/compat.h"
#include "susfs/kstat.h"
#include "susfs/susfs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
struct page *follow_trans_huge_pmd(struct vm_area_struct *vma,
				   unsigned long addr, pmd_t *pmd,
				   unsigned int flags);
#endif

#define KSU_SUSFS_KSTAT_HASH_BITS 8
#define KSU_SUSFS_USER_CALLCHAIN_MAX 8

struct ksu_susfs_kstat_entry {
	struct hlist_node node;
	struct list_head list;
	struct rcu_head rcu;
	unsigned long target_ino;
	dev_t target_dev;
	unsigned long spoofed_ino;
	dev_t spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	unsigned long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_sec;
	unsigned long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_sec;
	unsigned long spoofed_ctime_tv_nsec;
	long long spoofed_blocks;
	long spoofed_blksize;
	int flags;
	bool is_statically;
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_sus_map_entry {
	struct hlist_node node;
	struct list_head list;
	struct rcu_head rcu;
	unsigned long target_ino;
	dev_t target_dev;
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
};

struct ksu_susfs_vfs_getattr_ctx {
	const struct path *path;
	struct kstat *stat;
};

struct ksu_susfs_mem_size_stats {
	unsigned long resident;
	unsigned long shared_clean;
	unsigned long shared_dirty;
	unsigned long private_clean;
	unsigned long private_dirty;
	unsigned long referenced;
	unsigned long anonymous;
	unsigned long lazyfree;
	unsigned long anonymous_thp;
	unsigned long shmem_thp;
	unsigned long file_thp;
	unsigned long swap;
	unsigned long shared_hugetlb;
	unsigned long private_hugetlb;
	u64 pss;
	u64 pss_anon;
	u64 pss_file;
	u64 pss_shmem;
	u64 pss_locked;
	u64 swap_pss;
	bool check_shmem_swap;
};

struct ksu_susfs_map_files_info {
	unsigned long start;
	unsigned long end;
	fmode_t mode;
};

struct ksu_susfs_map_files_store {
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
	GENRADIX(struct ksu_susfs_map_files_info) entries;
#else
	struct flex_array *entries;
#endif
};

static int ksu_susfs_map_files_store_init(
	struct ksu_susfs_map_files_store *store, unsigned long capacity)
{
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
	(void)capacity;
	genradix_init(&store->entries);
	return 0;
#else
	if (!capacity) {
		return 0;
	}
	if (capacity > UINT_MAX) {
		return -EOVERFLOW;
	}

	store->entries = flex_array_alloc(
		sizeof(struct ksu_susfs_map_files_info), capacity, GFP_KERNEL);
	if (!store->entries ||
	    flex_array_prealloc(store->entries, 0, capacity, GFP_KERNEL)) {
		if (store->entries) {
			flex_array_free(store->entries);
			store->entries = NULL;
		}
		return -ENOMEM;
	}

	return 0;
#endif
}

static int ksu_susfs_map_files_store_add(
	struct ksu_susfs_map_files_store *store, unsigned long index,
	const struct ksu_susfs_map_files_info *info)
{
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
	struct ksu_susfs_map_files_info *entry =
		genradix_ptr_alloc(&store->entries, index, GFP_KERNEL);

	if (!entry) {
		return -ENOMEM;
	}
	*entry = *info;
	return 0;
#else
	if (index > UINT_MAX || !store->entries) {
		return -EOVERFLOW;
	}
	return flex_array_put(store->entries, index, (void *)info, GFP_KERNEL);
#endif
}

static struct ksu_susfs_map_files_info *
ksu_susfs_map_files_store_get(struct ksu_susfs_map_files_store *store,
				      unsigned long index)
{
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
	return genradix_ptr(&store->entries, index);
#else
	if (index > UINT_MAX || !store->entries) {
		return NULL;
	}
	return flex_array_get(store->entries, index);
#endif
}

static void ksu_susfs_map_files_store_free(
	struct ksu_susfs_map_files_store *store)
{
#ifdef KSU_SUSFS_HAS_GENERIC_RADIX_TREE
	genradix_free(&store->entries);
#else
	if (store->entries) {
		flex_array_free(store->entries);
		store->entries = NULL;
	}
#endif
}

static DEFINE_HASHTABLE(ksu_susfs_kstat_ht, KSU_SUSFS_KSTAT_HASH_BITS);
static DEFINE_HASHTABLE(ksu_susfs_sus_map_ht, KSU_SUSFS_KSTAT_HASH_BITS);
static LIST_HEAD(ksu_susfs_kstat_list);
static LIST_HEAD(ksu_susfs_sus_map_list);
static DEFINE_MUTEX(ksu_susfs_kstat_lock);
static DEFINE_MUTEX(ksu_susfs_sus_map_lock);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_kstat_enabled);
static DEFINE_STATIC_KEY_FALSE(ksu_susfs_sus_map_enabled);

static struct kretprobe *ksu_susfs_vfs_getattr_nosec_rp;
#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
static int (*ksu_susfs_orig_pid_smaps_rollup_open)(struct inode *inode,
						   struct file *file);
#endif
static ssize_t (*ksu_susfs_orig_pagemap_read)(struct file *file,
					      char __user *buf, size_t count,
					      loff_t *ppos);
static int (*ksu_susfs_orig_fd_readlink)(struct dentry *dentry,
					 char __user *buf, int buflen);
static int (*ksu_susfs_orig_map_files_readlink)(struct dentry *dentry,
						char __user *buf, int buflen);
static int (*ksu_susfs_orig_map_files_iterate_shared)(struct file *file,
						      struct dir_context *ctx);
static struct dentry *(*ksu_susfs_orig_map_files_lookup)(
	struct inode *dir, struct dentry *dentry, unsigned int flags);
static int (*ksu_susfs_orig_map_files_d_revalidate)(struct dentry *dentry,
						    unsigned int flags);
static ssize_t (*ksu_susfs_orig_mem_read)(struct file *file, char __user *buf,
					  size_t count, loff_t *ppos);
static ssize_t (*ksu_susfs_orig_mem_write)(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos);
static int (*ksu_susfs_orig_maps_show)(struct seq_file *m, void *v);
static int (*ksu_susfs_orig_smaps_show)(struct seq_file *m, void *v);
static bool ksu_susfs_getattr_ready;
static bool ksu_susfs_maps_ready;
static bool ksu_susfs_smaps_ready;
#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
static bool ksu_susfs_smaps_rollup_ready;
#endif
static bool ksu_susfs_pagemap_ready;
static bool ksu_susfs_fd_readlink_ready;
static bool ksu_susfs_map_files_readlink_ready;
static bool ksu_susfs_map_files_iterate_ready;
static bool ksu_susfs_map_files_lookup_ready;
static bool ksu_susfs_map_files_d_revalidate_ready;
static bool ksu_susfs_mem_read_ready;
static bool ksu_susfs_mem_write_ready;
static int ksu_susfs_kstat_rule_count;
static int ksu_susfs_sus_map_rule_count;
static const struct inode_operations *ksu_susfs_fd_link_iops;
static const struct inode_operations *ksu_susfs_map_files_link_iops;
static const struct file_operations *ksu_susfs_map_files_fops;
static const struct inode_operations *ksu_susfs_map_files_iops;
static const struct dentry_operations *ksu_susfs_map_files_dops;
static const struct file_operations *ksu_susfs_mem_fops;
static const struct seq_operations *ksu_susfs_maps_seqops;
static const struct seq_operations *ksu_susfs_smaps_seqops;
static instantiate_t *ksu_susfs_map_files_instantiate;

#define KSU_SUSFS_PAGEMAP_ENTRY_BYTES sizeof(u64)
#define KSU_SUSFS_PSS_SHIFT 12

#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
#define KSU_SUSFS_ITERATE_MEMBER iterate_shared
#else
#define KSU_SUSFS_ITERATE_MEMBER iterate
#endif

/*
 * The hookless sus_map runtime layer intentionally stays close to the
 * upstream SUSFS procfs patch surface. Direct map_files lookup/revalidate and
 * /proc/<pid>/mem patching were found to destabilize LSPosed preload mappings
 * during live-device testing, so we keep those stock for now.
 */
static const bool ksu_susfs_sus_map_fd_readlink_enabled = true;
static const bool ksu_susfs_sus_map_map_files_readlink_enabled = true;
static const bool ksu_susfs_sus_map_proc_maps_enabled = true;
static const bool ksu_susfs_sus_map_map_files_lookup_enabled = false;
static const bool ksu_susfs_sus_map_proc_mem_enabled = false;
/*
 * The broader proc/mm wrappers still hard-lock the device when a live LSPosed
 * preload mapping is registered via add_sus_map. Keep hookless sus_map on the
 * low-risk procfs surface until those paths are narrowed down.
 */
#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
static const bool ksu_susfs_sus_map_smaps_rollup_enabled = false;
#endif
static const bool ksu_susfs_sus_map_pagemap_enabled = false;
static const bool ksu_susfs_sus_map_map_files_iterate_enabled = false;

static bool
ksu_susfs_current_callchain_from_sus_map_locked(struct mm_struct *locked_mm);
static bool ksu_susfs_current_callchain_from_sus_map(void);

static bool ksu_susfs_kstat_compat_root_allowed(void)
{
	return current_uid().val == 0 || is_ksu_domain();
}

static bool ksu_susfs_proc_mm_view_allowed_current(void)
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

static bool ksu_susfs_kstat_should_spoof_current(void)
{
	if (!static_branch_unlikely(&ksu_susfs_kstat_enabled)) {
		return false;
	}

	return ksu_susfs_proc_mm_view_allowed_current();
}

bool ksu_susfs_kstat_active_for_current(void)
{
	return ksu_susfs_kstat_should_spoof_current();
}

static bool ksu_susfs_sus_map_should_hide_current(void)
{
	if (!static_branch_unlikely(&ksu_susfs_sus_map_enabled)) {
		return false;
	}

	return ksu_susfs_proc_mm_view_allowed_current();
}

static bool ksu_susfs_sus_map_should_hide_maps_current(void)
{
	return ksu_susfs_sus_map_proc_maps_enabled &&
	       ksu_susfs_sus_map_should_hide_current();
}

static bool ksu_susfs_proc_maps_view_enabled_current(void)
{
	if (ksu_susfs_kstat_should_spoof_current() ||
	    ksu_susfs_sus_map_should_hide_maps_current()) {
		return true;
	}

#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	return ksu_nomount_active_for_current();
#else
	return false;
#endif
}

static int ksu_susfs_kstat_normalize_path(char *dst, size_t dst_size,
					  const char *src)
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

static int ksu_susfs_kstat_resolve_path(const char *path, struct path *out)
{
	const struct cred *saved;
	int err;

	saved = override_creds(ksu_cred);
	err = kern_path(path, 0, out);
	revert_creds(saved);
	return err;
}

static int ksu_susfs_kstat_fill_target(const char *path, unsigned long *ino,
				       dev_t *dev)
{
	struct path resolved;
	struct inode *inode;
	int err;

	err = ksu_susfs_kstat_resolve_path(path, &resolved);
	if (err) {
		return err;
	}

	inode = d_backing_inode(resolved.dentry);
	if (!inode) {
		path_put(&resolved);
		return -ENOENT;
	}

	*ino = inode->i_ino;
	*dev = inode->i_sb->s_dev;
	path_put(&resolved);
	return 0;
}

static dev_t ksu_susfs_kstat_decode_dev(unsigned long dev)
{
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef CONFIG_MIPS
	return new_decode_dev(dev);
#else
	return huge_decode_dev(dev);
#endif
#else
	return old_decode_dev(dev);
#endif
}

static struct ksu_susfs_kstat_entry *
ksu_susfs_kstat_find_path_locked(const char *path)
{
	struct ksu_susfs_kstat_entry *entry;

	list_for_each_entry(entry, &ksu_susfs_kstat_list, list) {
		if (!strcmp(entry->target_pathname, path)) {
			return entry;
		}
	}

	return NULL;
}

static struct ksu_susfs_kstat_entry *
ksu_susfs_kstat_lookup_rcu(unsigned long ino, dev_t dev)
{
	struct ksu_susfs_kstat_entry *entry;

	hash_for_each_possible_rcu(ksu_susfs_kstat_ht, entry, node, ino) {
		if (entry->target_ino == ino && entry->target_dev == dev) {
			return entry;
		}
	}

	return NULL;
}

static struct ksu_susfs_sus_map_entry *
ksu_susfs_sus_map_find_path_locked(const char *path)
{
	struct ksu_susfs_sus_map_entry *entry;

	list_for_each_entry(entry, &ksu_susfs_sus_map_list, list) {
		if (!strcmp(entry->target_pathname, path)) {
			return entry;
		}
	}

	return NULL;
}

static struct ksu_susfs_sus_map_entry *
ksu_susfs_sus_map_lookup_rcu(unsigned long ino, dev_t dev)
{
	struct ksu_susfs_sus_map_entry *entry;

	hash_for_each_possible_rcu(ksu_susfs_sus_map_ht, entry, node, ino) {
		if (entry->target_ino == ino && entry->target_dev == dev) {
			return entry;
		}
	}

	return NULL;
}

static void
ksu_susfs_kstat_apply_spoof(const struct ksu_susfs_kstat_entry *entry,
			     struct kstat *stat)
{
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_INO) {
		stat->ino = entry->spoofed_ino;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_DEV) {
		stat->dev = entry->spoofed_dev;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_NLINK) {
		stat->nlink = entry->spoofed_nlink;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_SIZE) {
		stat->size = entry->spoofed_size;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_ATIME_TV_SEC) {
		stat->atime.tv_sec = entry->spoofed_atime_tv_sec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_ATIME_TV_NSEC) {
		stat->atime.tv_nsec = entry->spoofed_atime_tv_nsec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_MTIME_TV_SEC) {
		stat->mtime.tv_sec = entry->spoofed_mtime_tv_sec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_MTIME_TV_NSEC) {
		stat->mtime.tv_nsec = entry->spoofed_mtime_tv_nsec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_CTIME_TV_SEC) {
		stat->ctime.tv_sec = entry->spoofed_ctime_tv_sec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_CTIME_TV_NSEC) {
		stat->ctime.tv_nsec = entry->spoofed_ctime_tv_nsec;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_BLOCKS) {
		stat->blocks = entry->spoofed_blocks;
	}
	if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_BLKSIZE) {
		stat->blksize = entry->spoofed_blksize;
	}
}

static bool ksu_susfs_kstat_vma_spoof(struct vm_area_struct *vma, dev_t *dev,
				      unsigned long *ino)
{
	struct file *file;
	struct inode *inode;
	struct ksu_susfs_kstat_entry *entry;
	unsigned long native_ino;
	dev_t native_dev;
	bool changed = false;

	if (!vma || !dev || !ino)
		return false;

	file = vma->vm_file;
	if (!file) {
		return false;
	}

	inode = file_inode(file);
	if (!inode) {
		return false;
	}

	native_dev = inode->i_sb->s_dev;
	native_ino = inode->i_ino;
	*dev = native_dev;
	*ino = native_ino;

	if (ksu_susfs_kstat_should_spoof_current()) {
		rcu_read_lock();
		entry = ksu_susfs_kstat_lookup_rcu(native_ino, native_dev);
		if (entry) {
			if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_DEV)
				*dev = entry->spoofed_dev;
			if (entry->flags & KSU_SUSFS_KSTAT_SPOOF_INO)
				*ino = entry->spoofed_ino;
			changed = true;
		}
		rcu_read_unlock();
	}
	if (ksu_susfs_open_redirect_spoof_inode_identity(inode, dev, ino))
		changed = true;

	/* The virtual NoMount alias is the final identity exposed for its target. */
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	if (ksu_nomount_spoof_mmap_metadata(inode, dev, ino))
		changed = true;
#endif

	return changed;
}

static bool ksu_susfs_sus_map_match_inode(struct inode *inode)
{
	struct ksu_susfs_sus_map_entry *entry;
	bool matched = false;

	if (!inode || !ksu_susfs_sus_map_should_hide_current()) {
		return false;
	}

	rcu_read_lock();
	entry = ksu_susfs_sus_map_lookup_rcu(inode->i_ino, inode->i_sb->s_dev);
	matched = !!entry;
	rcu_read_unlock();
	return matched;
}

static bool ksu_susfs_sus_map_match_vma(struct vm_area_struct *vma)
{
	if (!vma || !vma->vm_file) {
		return false;
	}

	return ksu_susfs_sus_map_match_inode(file_inode(vma->vm_file));
}

static bool ksu_susfs_sus_map_hide_vma_current(struct vm_area_struct *vma,
					       struct mm_struct *locked_mm)
{
	return ksu_susfs_sus_map_should_hide_maps_current() &&
	       ksu_susfs_sus_map_match_vma(vma) &&
	       !ksu_susfs_current_callchain_from_sus_map_locked(locked_mm);
}

static bool ksu_susfs_sus_map_match_file(struct file *file)
{
	if (!file) {
		return false;
	}

	return ksu_susfs_sus_map_match_inode(file_inode(file));
}

static int ksu_susfs_kstat_vfs_getattr_entry(struct kretprobe_instance *ri,
					     struct pt_regs *regs)
{
	struct ksu_susfs_vfs_getattr_ctx *ctx =
		(struct ksu_susfs_vfs_getattr_ctx *)ri->data;

	ctx->path = (const struct path *)PT_REGS_PARM1(regs);
	ctx->stat = (struct kstat *)PT_REGS_PARM2(regs);
	return 0;
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
void
#else
static void
#endif
ksu_susfs_handle_vfs_getattr_nosec(const struct path *path, struct kstat *stat,
				   long ret)
{
	struct inode *inode;
	struct ksu_susfs_kstat_entry *entry;

	if (ret || !path || !stat || !path->dentry)
		return;

	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;

	if (ksu_susfs_kstat_should_spoof_current()) {
		rcu_read_lock();
		entry = ksu_susfs_kstat_lookup_rcu(inode->i_ino,
						      inode->i_sb->s_dev);
		if (entry)
			ksu_susfs_kstat_apply_spoof(entry, stat);
		rcu_read_unlock();
	}
	ksu_susfs_open_redirect_apply_kstat(inode, stat);
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	/* NoMount is the final visible identity layer. */
	ksu_nomount_handle_getattr(ret, path, stat);
#endif
}

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
/*
 * Vendor LTO can inline vfs_getattr() into vfs_statx(), bypassing the
 * vfs_getattr_nosec() branch-link callsite above.  Match the completed kstat
 * by its native inode/device identity so the userspace stat family still gets
 * the registered SUSFS metadata.
 */
void ksu_susfs_handle_stat_result(struct kstat *stat, long ret)
{
	struct ksu_susfs_kstat_entry *entry;
	unsigned long native_ino;
	dev_t native_dev;
	bool open_redirect_applied;

	if (ret || !stat)
		return;
	native_ino = stat->ino;
	native_dev = stat->dev;
	open_redirect_applied =
		ksu_susfs_open_redirect_apply_kstat_identity(stat);

	if (!open_redirect_applied && ksu_susfs_kstat_should_spoof_current()) {
		rcu_read_lock();
		entry = ksu_susfs_kstat_lookup_rcu(native_ino, native_dev);
		if (entry)
			ksu_susfs_kstat_apply_spoof(entry, stat);
		rcu_read_unlock();
	}
#ifdef CONFIG_KSU_KPROBES_NOMOUNT
	ksu_nomount_handle_stat_result(ret, native_ino, native_dev, stat);
#endif
}
#endif

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
void ksu_susfs_set_getattr_ready(bool ready)
{
	ksu_susfs_getattr_ready = ready;
}

bool ksu_susfs_kstat_runtime_ready(void)
{
	return READ_ONCE(ksu_susfs_getattr_ready);
}
#endif

static int ksu_susfs_kstat_vfs_getattr_handler(struct kretprobe_instance *ri,
					       struct pt_regs *regs)
{
	struct ksu_susfs_vfs_getattr_ctx *ctx =
		(struct ksu_susfs_vfs_getattr_ctx *)ri->data;

	ksu_susfs_handle_vfs_getattr_nosec(ctx->path, ctx->stat,
					   (long)regs_return_value(regs));

	return 0;
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
		pr_err("susfs: failed to restore proc maps open\n");
	}

	*old_open = NULL;
}

static int ksu_susfs_patch_seqop_show(
	const struct seq_operations *seqops,
	int (*new_show)(struct seq_file *, void *),
	int (**old_show)(struct seq_file *, void *))
{
	int (*orig_show)(struct seq_file *m, void *v);
	void *dst;

	if (!seqops || !new_show) {
		return -EINVAL;
	}

	orig_show = READ_ONCE(seqops->show);
	if (!orig_show) {
		return -EINVAL;
	}

	if (old_show) {
		*old_show = orig_show;
	}

	dst = (void *)&((struct seq_operations *)seqops)->show;
	return ksu_patch_text(dst, &new_show, sizeof(new_show),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_seqop_show(
	const struct seq_operations *seqops,
	int (**old_show)(struct seq_file *, void *))
{
	int (*orig_show)(struct seq_file *m, void *v);
	void *dst;

	if (!seqops || !old_show || !*old_show) {
		return;
	}

	orig_show = *old_show;
	dst = (void *)&((struct seq_operations *)seqops)->show;
	if (ksu_patch_text(dst, &orig_show, sizeof(orig_show),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore seq show\n");
	}

	*old_show = NULL;
}

static int ksu_susfs_patch_fop_read(
	const struct file_operations *fops,
	ssize_t (*new_read)(struct file *, char __user *, size_t, loff_t *),
	ssize_t (**old_read)(struct file *, char __user *, size_t, loff_t *))
{
	ssize_t (*orig_read)(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos);
	void *dst;

	if (!fops || !new_read) {
		return -EINVAL;
	}

	orig_read = READ_ONCE(fops->read);
	if (!orig_read) {
		return -EINVAL;
	}

	if (old_read) {
		*old_read = orig_read;
	}

	dst = (void *)&((struct file_operations *)fops)->read;
	return ksu_patch_text(dst, &new_read, sizeof(new_read),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_fop_read(
	const struct file_operations *fops,
	ssize_t (**old_read)(struct file *, char __user *, size_t, loff_t *))
{
	ssize_t (*orig_read)(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos);
	void *dst;

	if (!fops || !old_read || !*old_read) {
		return;
	}

	orig_read = *old_read;
	dst = (void *)&((struct file_operations *)fops)->read;
	if (ksu_patch_text(dst, &orig_read, sizeof(orig_read),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore file_operations read\n");
	}

	*old_read = NULL;
}

static int ksu_susfs_patch_fop_write(
	const struct file_operations *fops,
	ssize_t (*new_write)(struct file *, const char __user *, size_t,
			     loff_t *),
	ssize_t (**old_write)(struct file *, const char __user *, size_t,
			      loff_t *))
{
	ssize_t (*orig_write)(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos);
	void *dst;

	if (!fops || !new_write) {
		return -EINVAL;
	}

	orig_write = READ_ONCE(fops->write);
	if (!orig_write) {
		return -EINVAL;
	}

	if (old_write) {
		*old_write = orig_write;
	}

	dst = (void *)&((struct file_operations *)fops)->write;
	return ksu_patch_text(dst, &new_write, sizeof(new_write),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_fop_write(
	const struct file_operations *fops,
	ssize_t (**old_write)(struct file *, const char __user *, size_t,
			      loff_t *))
{
	ssize_t (*orig_write)(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos);
	void *dst;

	if (!fops || !old_write || !*old_write) {
		return;
	}

	orig_write = *old_write;
	dst = (void *)&((struct file_operations *)fops)->write;
	if (ksu_patch_text(dst, &orig_write, sizeof(orig_write),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore file_operations write\n");
	}

	*old_write = NULL;
}

static int ksu_susfs_patch_fop_iterate_shared(
	const struct file_operations *fops,
	int (*new_iterate_shared)(struct file *, struct dir_context *),
	int (**old_iterate_shared)(struct file *, struct dir_context *))
{
	int (*orig_iterate_shared)(struct file *file, struct dir_context *ctx);
	void *dst;

	if (!fops || !new_iterate_shared) {
		return -EINVAL;
	}

	orig_iterate_shared = READ_ONCE(fops->KSU_SUSFS_ITERATE_MEMBER);
	if (!orig_iterate_shared) {
		return -EINVAL;
	}

	if (old_iterate_shared) {
		*old_iterate_shared = orig_iterate_shared;
	}

	dst = (void *)&((struct file_operations *)fops)->KSU_SUSFS_ITERATE_MEMBER;
	return ksu_patch_text(dst, &new_iterate_shared,
			      sizeof(new_iterate_shared),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_fop_iterate_shared(
	const struct file_operations *fops,
	int (**old_iterate_shared)(struct file *, struct dir_context *))
{
	int (*orig_iterate_shared)(struct file *file, struct dir_context *ctx);
	void *dst;

	if (!fops || !old_iterate_shared || !*old_iterate_shared) {
		return;
	}

	orig_iterate_shared = *old_iterate_shared;
	dst = (void *)&((struct file_operations *)fops)->KSU_SUSFS_ITERATE_MEMBER;
	if (ksu_patch_text(dst, &orig_iterate_shared,
			   sizeof(orig_iterate_shared),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore iterate_shared\n");
	}

	*old_iterate_shared = NULL;
}

static int ksu_susfs_patch_iop_lookup(
	const struct inode_operations *iops,
	struct dentry *(*new_lookup)(struct inode *, struct dentry *,
				     unsigned int),
	struct dentry *(**old_lookup)(struct inode *, struct dentry *,
				      unsigned int))
{
	struct dentry *(*orig_lookup)(struct inode *dir, struct dentry *dentry,
				      unsigned int flags);
	void *dst;

	if (!iops || !new_lookup) {
		return -EINVAL;
	}

	orig_lookup = READ_ONCE(iops->lookup);
	if (!orig_lookup) {
		return -EINVAL;
	}

	if (old_lookup) {
		*old_lookup = orig_lookup;
	}

	dst = (void *)&((struct inode_operations *)iops)->lookup;
	return ksu_patch_text(dst, &new_lookup, sizeof(new_lookup),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_iop_lookup(
	const struct inode_operations *iops,
	struct dentry *(**old_lookup)(struct inode *, struct dentry *,
				      unsigned int))
{
	struct dentry *(*orig_lookup)(struct inode *dir, struct dentry *dentry,
				      unsigned int flags);
	void *dst;

	if (!iops || !old_lookup || !*old_lookup) {
		return;
	}

	orig_lookup = *old_lookup;
	dst = (void *)&((struct inode_operations *)iops)->lookup;
	if (ksu_patch_text(dst, &orig_lookup, sizeof(orig_lookup),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore inode lookup\n");
	}

	*old_lookup = NULL;
}

static int ksu_susfs_patch_iop_readlink(
	const struct inode_operations *iops,
	int (*new_readlink)(struct dentry *, char __user *, int),
	int (**old_readlink)(struct dentry *, char __user *, int))
{
	int (*orig_readlink)(struct dentry *dentry, char __user *buf,
			     int buflen);
	void *dst;

	if (!iops || !new_readlink) {
		return -EINVAL;
	}

	orig_readlink = READ_ONCE(iops->readlink);
	if (!orig_readlink) {
		return -EINVAL;
	}

	if (old_readlink) {
		*old_readlink = orig_readlink;
	}

	dst = (void *)&((struct inode_operations *)iops)->readlink;
	return ksu_patch_text(dst, &new_readlink, sizeof(new_readlink),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_iop_readlink(
	const struct inode_operations *iops,
	int (**old_readlink)(struct dentry *, char __user *, int))
{
	int (*orig_readlink)(struct dentry *dentry, char __user *buf,
			     int buflen);
	void *dst;

	if (!iops || !old_readlink || !*old_readlink) {
		return;
	}

	orig_readlink = *old_readlink;
	dst = (void *)&((struct inode_operations *)iops)->readlink;
	if (ksu_patch_text(dst, &orig_readlink, sizeof(orig_readlink),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore inode readlink\n");
	}

	*old_readlink = NULL;
}

static int ksu_susfs_patch_dop_d_revalidate(
	const struct dentry_operations *dops,
	int (*new_d_revalidate)(struct dentry *, unsigned int),
	int (**old_d_revalidate)(struct dentry *, unsigned int))
{
	int (*orig_d_revalidate)(struct dentry *dentry, unsigned int flags);
	void *dst;

	if (!dops || !new_d_revalidate) {
		return -EINVAL;
	}

	orig_d_revalidate = READ_ONCE(dops->d_revalidate);
	if (!orig_d_revalidate) {
		return -EINVAL;
	}

	if (old_d_revalidate) {
		*old_d_revalidate = orig_d_revalidate;
	}

	dst = (void *)&((struct dentry_operations *)dops)->d_revalidate;
	return ksu_patch_text(dst, &new_d_revalidate, sizeof(new_d_revalidate),
			      KSU_PATCH_TEXT_FLUSH_DCACHE);
}

static void ksu_susfs_restore_dop_d_revalidate(
	const struct dentry_operations *dops,
	int (**old_d_revalidate)(struct dentry *, unsigned int))
{
	int (*orig_d_revalidate)(struct dentry *dentry, unsigned int flags);
	void *dst;

	if (!dops || !old_d_revalidate || !*old_d_revalidate) {
		return;
	}

	orig_d_revalidate = *old_d_revalidate;
	dst = (void *)&((struct dentry_operations *)dops)->d_revalidate;
	if (ksu_patch_text(dst, &orig_d_revalidate, sizeof(orig_d_revalidate),
			   KSU_PATCH_TEXT_FLUSH_DCACHE)) {
		pr_err("susfs: failed to restore dentry revalidate\n");
	}

	*old_d_revalidate = NULL;
}

static unsigned long
ksu_susfs_clamp_addr_range(struct mm_struct *mm, unsigned long start, size_t len)
{
	unsigned long end;

	if (!mm || !len) {
		return start;
	}

	end = start + len;
	if (end < start || end > mm->task_size) {
		end = mm->task_size;
	}

	return end;
}

static int ksu_susfs_sus_map_scan_locked(struct mm_struct *mm,
					 unsigned long start,
					 unsigned long limit,
					 bool *hidden,
					 unsigned long *boundary)
{
	struct vm_area_struct *vma;

	if (!hidden || !boundary) {
		return -EINVAL;
	}

	*hidden = false;
	*boundary = limit;

	if (!mm || start >= limit) {
		*boundary = start;
		return 0;
	}

	vma = find_vma(mm, start);
	while (vma && vma->vm_start < limit) {
		if (!ksu_susfs_sus_map_match_vma(vma)) {
			vma = ksu_susfs_next_vma(mm, vma);
			continue;
		}

		if (start < vma->vm_start) {
			*boundary = vma->vm_start;
		} else if (start < vma->vm_end) {
			*hidden = true;
			*boundary = min_t(unsigned long, vma->vm_end, limit);
		}
		return 0;
	}

	return 0;
}

static int ksu_susfs_sus_map_next_boundary(struct mm_struct *mm,
					   unsigned long start, size_t len,
					   bool *hidden,
					   unsigned long *boundary)
{
	unsigned long limit;
	int err;

	if (!hidden || !boundary) {
		return -EINVAL;
	}

	*hidden = false;
	*boundary = start;

	if (!mm) {
		return -EINVAL;
	}

	if (!ksu_susfs_mmget_not_zero(mm)) {
		return 0;
	}

	err = ksu_susfs_mmap_read_lock_killable(mm);
	if (err) {
		mmput(mm);
		return err;
	}

	limit = ksu_susfs_clamp_addr_range(mm, start, len);
	err = ksu_susfs_sus_map_scan_locked(mm, start, limit, hidden, boundary);

	ksu_susfs_mmap_read_unlock(mm);
	mmput(mm);
	return err;
}

static unsigned long
ksu_susfs_pagemap_pos_to_addr(struct mm_struct *mm, loff_t pos)
{
	unsigned long svpfn;
	unsigned long addr;

	if (!mm || pos < 0) {
		return 0;
	}

	svpfn = div_u64((u64)pos, KSU_SUSFS_PAGEMAP_ENTRY_BYTES);
	addr = mm->task_size;
	if (svpfn <= (ULONG_MAX >> PAGE_SHIFT)) {
		addr = untagged_addr(svpfn << PAGE_SHIFT);
	}
	if (addr > mm->task_size) {
		addr = mm->task_size;
	}

	return addr;
}

static size_t ksu_susfs_pagemap_addr_bytes(unsigned long start,
					   unsigned long end)
{
	unsigned long pages;

	if (end <= start) {
		return 0;
	}

	pages = (end - start) >> PAGE_SHIFT;
	return pages * KSU_SUSFS_PAGEMAP_ENTRY_BYTES;
}

static struct vm_area_struct *
ksu_susfs_m_next_vma(struct proc_maps_private *priv, struct vm_area_struct *vma)
{
	struct vm_area_struct *next;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (vma == priv->tail_vma) {
		return NULL;
	}
#endif

	next = ksu_susfs_next_vma(priv->mm, vma);
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	if (next) {
		return next;
	}

	return priv->tail_vma;
#else
	return next;
#endif
}

static void ksu_susfs_m_cache_vma(struct seq_file *m, struct vm_area_struct *vma)
{
#ifdef KSU_SUSFS_SEQ_FILE_HAS_VERSION
	if (m->count < m->size) {
		m->version = ksu_susfs_m_next_vma(m->private, vma) ?
				    vma->vm_end :
				    -1UL;
	}
#else
	(void)m;
	(void)vma;
#endif
}

static int ksu_susfs_is_stack(struct vm_area_struct *vma)
{
	return vma->vm_start <= vma->vm_mm->start_stack &&
	       vma->vm_end >= vma->vm_mm->start_stack;
}

static void ksu_susfs_show_vma_header_prefix(struct seq_file *m,
					     unsigned long start,
					     unsigned long end,
					     vm_flags_t flags,
					     unsigned long long pgoff,
					     dev_t dev,
					     unsigned long ino)
{
	seq_setwidth(m, 25 + sizeof(void *) * 6 - 1);
	ksu_susfs_seq_put_hex_ll(m, NULL, start, 8);
	ksu_susfs_seq_put_hex_ll(m, "-", end, 8);
	seq_putc(m, ' ');
	seq_putc(m, flags & VM_READ ? 'r' : '-');
	seq_putc(m, flags & VM_WRITE ? 'w' : '-');
	seq_putc(m, flags & VM_EXEC ? 'x' : '-');
	seq_putc(m, flags & VM_MAYSHARE ? 's' : 'p');
	ksu_susfs_seq_put_hex_ll(m, " ", pgoff, 8);
	ksu_susfs_seq_put_hex_ll(m, " ", MAJOR(dev), 2);
	ksu_susfs_seq_put_hex_ll(m, ":", MINOR(dev), 2);
	seq_put_decimal_ull(m, " ", ino);
	seq_putc(m, ' ');
}

#ifdef KSU_SUSFS_HAS_VMA_ANON_NAME
static void ksu_susfs_seq_print_vma_name(struct seq_file *m,
					 struct vm_area_struct *vma)
{
	const char __user *name = vma_get_anon_name(vma);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long page_start_vaddr;
	unsigned long page_offset;
	unsigned long num_pages;
	unsigned long max_len = NAME_MAX;
	int i;

	page_start_vaddr = (unsigned long)name & PAGE_MASK;
	page_offset = (unsigned long)name - page_start_vaddr;
	num_pages = DIV_ROUND_UP(page_offset + max_len, PAGE_SIZE);

	seq_puts(m, "[anon:");

	for (i = 0; i < num_pages; i++) {
		int len;
		int write_len;
		const char *kaddr;
		long pages_pinned;
		struct page *page;

#if defined(KSU_SUSFS_GUP_REMOTE_HAS_TASK) && \
	defined(KSU_SUSFS_GUP_REMOTE_HAS_LOCKED)
		pages_pinned = get_user_pages_remote(current, mm,
				page_start_vaddr, 1, 0, &page, NULL, NULL);
#elif defined(KSU_SUSFS_GUP_REMOTE_HAS_TASK)
		pages_pinned = get_user_pages_remote(current, mm,
				page_start_vaddr, 1, 0, &page, NULL);
#elif defined(KSU_SUSFS_GUP_REMOTE_HAS_VMAS)
		pages_pinned = get_user_pages_remote(mm, page_start_vaddr, 1, 0,
					     &page, NULL, NULL);
#else
		pages_pinned = get_user_pages_remote(mm, page_start_vaddr, 1, 0,
					     &page, NULL);
#endif
		if (pages_pinned < 1) {
			seq_puts(m, "<fault>]");
			return;
		}

		kaddr = (const char *)kmap(page);
		len = min_t(unsigned long, max_len, PAGE_SIZE - page_offset);
		write_len = strnlen(kaddr + page_offset, len);
		seq_write(m, kaddr + page_offset, write_len);
		kunmap(page);
		put_page(page);

		if (write_len != len) {
			break;
		}

		max_len -= len;
		page_offset = 0;
		page_start_vaddr += PAGE_SIZE;
	}

	seq_putc(m, ']');
}
#endif

static void ksu_susfs_show_map_vma(struct seq_file *m,
				   struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct file *file = vma->vm_file;
	vm_flags_t flags = vma->vm_flags;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long start, end;
	dev_t dev = 0;
	const char *name = NULL;

	if (ksu_susfs_sus_map_hide_vma_current(vma, vma ? vma->vm_mm : NULL)) {
		return;
	}

	if (file) {
		struct inode *inode = file_inode(file);

		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
		ksu_susfs_kstat_vma_spoof(vma, &dev, &ino);
	}

	start = vma->vm_start;
	end = vma->vm_end;
	ksu_susfs_show_vma_header_prefix(m, start, end, flags, pgoff, dev,
					 ino);

	if (file) {
		seq_pad(m, ' ');
		seq_file_path(m, file, "\n");
		goto done;
	}

	if (vma->vm_ops && vma->vm_ops->name) {
		name = vma->vm_ops->name(vma);
		if (name) {
			goto done;
		}
	}

	name = arch_vma_name(vma);
	if (!name) {
		if (!mm) {
			name = "[vdso]";
			goto done;
		}

		if (vma->vm_start <= mm->brk &&
		    vma->vm_end >= mm->start_brk) {
			name = "[heap]";
			goto done;
		}

		if (ksu_susfs_is_stack(vma)) {
			name = "[stack]";
			goto done;
		}

#ifdef KSU_SUSFS_HAS_VMA_ANON_NAME
		if (vma_get_anon_name(vma)) {
			seq_pad(m, ' ');
			ksu_susfs_seq_print_vma_name(m, vma);
		}
#endif
	}

done:
	if (name) {
		seq_pad(m, ' ');
		seq_puts(m, name);
	}
	seq_putc(m, '\n');
}

static int ksu_susfs_show_map(struct seq_file *m, void *v)
{
	struct vm_area_struct *orig_vma = v;
	struct vm_area_struct *pad_vma;
	struct vm_area_struct *vma;

	if (!ksu_susfs_proc_maps_view_enabled_current()) {
		return ksu_susfs_orig_maps_show ? ksu_susfs_orig_maps_show(m, v) :
						 -ENOSYS;
	}

	vma = ksu_susfs_get_data_vma(orig_vma);
	if (ksu_susfs_sus_map_hide_vma_current(vma, vma ? vma->vm_mm : NULL)) {
		ksu_susfs_m_cache_vma(m, orig_vma);
		ksu_susfs_put_data_vma(orig_vma, vma);
		return 0;
	}

	pad_vma = ksu_susfs_get_pad_vma(orig_vma);
	if (vma_pages(vma)) {
		ksu_susfs_show_map_vma(m, vma);
	}

	ksu_susfs_show_map_pad_vma(vma, pad_vma, m,
				   (void *)ksu_susfs_show_map_vma, false);
	ksu_susfs_m_cache_vma(m, orig_vma);
	return 0;
}

static size_t ksu_susfs_build_vma_prefix(struct vm_area_struct *vma, dev_t dev,
					 unsigned long ino, char *buf,
					 size_t buf_size)
{
	struct seq_file tmp = {
		.buf = buf,
		.size = buf_size,
	};
	unsigned long long pgoff;

	if (!vma || !buf || !buf_size) {
		return 0;
	}

	pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	ksu_susfs_show_vma_header_prefix(&tmp, vma->vm_start, vma->vm_end,
					 vma->vm_flags, pgoff, dev, ino);
	seq_pad(&tmp, ' ');

	if (seq_has_overflowed(&tmp)) {
		return 0;
	}

	return tmp.count;
}

static void ksu_susfs_rewrite_smap_prefix(struct seq_file *m,
					  struct vm_area_struct *vma,
					  size_t start)
{
	char prefix[128];
	char *line_start;
	char *path_start;
	char *line_end;
	size_t line_off;
	size_t path_off;
	size_t prefix_len;
	size_t orig_prefix_len;
	size_t tail_len;
	ssize_t delta;
	dev_t dev;
	unsigned long ino;

	if (!m || !m->buf || start >= m->count) {
		return;
	}

	if (!ksu_susfs_kstat_vma_spoof(vma, &dev, &ino)) {
		return;
	}

	line_start = m->buf + start;
	line_end = memchr(line_start, '\n', m->count - start);
	if (!line_end) {
		return;
	}

	path_start = memchr(line_start, '/', line_end - line_start);
	if (!path_start) {
		return;
	}

	memset(prefix, 0, sizeof(prefix));
	prefix_len = ksu_susfs_build_vma_prefix(vma, dev, ino, prefix,
						sizeof(prefix));
	if (!prefix_len) {
		return;
	}

	line_off = line_start - m->buf;
	path_off = path_start - m->buf;
	orig_prefix_len = path_off - line_off;
	delta = (ssize_t)prefix_len - (ssize_t)orig_prefix_len;

	if (delta > 0) {
		if (m->count + delta > m->size) {
			return;
		}
		tail_len = m->count - path_off;
		memmove(m->buf + path_off + delta, m->buf + path_off, tail_len);
		m->count += delta;
	} else if (delta < 0) {
		tail_len = m->count - path_off;
		memmove(m->buf + path_off + delta, m->buf + path_off, tail_len);
		m->count -= -delta;
	}

	memcpy(m->buf + line_off, prefix, prefix_len);
}

static int ksu_susfs_show_smap(struct seq_file *m, void *v)
{
	struct vm_area_struct *orig_vma = v;
	struct vm_area_struct *vma;
	size_t start = m->count;
	int ret;

	if (!ksu_susfs_proc_maps_view_enabled_current()) {
		return ksu_susfs_orig_smaps_show ? ksu_susfs_orig_smaps_show(m, v) :
						  -ENOSYS;
	}

	vma = ksu_susfs_get_data_vma(orig_vma);
	if (ksu_susfs_sus_map_hide_vma_current(vma, vma ? vma->vm_mm : NULL)) {
		ksu_susfs_m_cache_vma(m, orig_vma);
		ksu_susfs_put_data_vma(orig_vma, vma);
		return 0;
	}

	if (!ksu_susfs_orig_smaps_show) {
		ksu_susfs_put_data_vma(orig_vma, vma);
		return -ENOSYS;
	}

	ret = ksu_susfs_orig_smaps_show(m, v);
	if (ret || seq_has_overflowed(m)) {
		ksu_susfs_put_data_vma(orig_vma, vma);
		return ret;
	}

	if (!vma || !vma->vm_file) {
		ksu_susfs_put_data_vma(orig_vma, vma);
		return ret;
	}

	ksu_susfs_rewrite_smap_prefix(m, vma, start);
	ksu_susfs_put_data_vma(orig_vma, vma);
	return ret;
}

#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
static void ksu_susfs_smaps_page_accumulate(
	struct ksu_susfs_mem_size_stats *mss, struct page *page,
	unsigned long size, unsigned long pss, bool dirty, bool locked,
	bool private)
{
	mss->pss += pss;

	if (PageAnon(page)) {
		mss->pss_anon += pss;
	} else if (PageSwapBacked(page)) {
		mss->pss_shmem += pss;
	} else {
		mss->pss_file += pss;
	}

	if (locked) {
		mss->pss_locked += pss;
	}

	if (dirty || PageDirty(page)) {
		if (private) {
			mss->private_dirty += size;
		} else {
			mss->shared_dirty += size;
		}
	} else {
		if (private) {
			mss->private_clean += size;
		} else {
			mss->shared_clean += size;
		}
	}
}

static void ksu_susfs_smaps_account(struct ksu_susfs_mem_size_stats *mss,
				    struct page *page, bool compound,
				    bool young, bool dirty, bool locked)
{
	int i;
	int nr = compound ? ksu_susfs_compound_nr(page) : 1;
	unsigned long size = nr * PAGE_SIZE;

	if (PageAnon(page)) {
		mss->anonymous += size;
		if (!PageSwapBacked(page) && !dirty && !PageDirty(page)) {
			mss->lazyfree += size;
		}
	}

	mss->resident += size;
	if (young || ksu_susfs_page_is_young(page) || PageReferenced(page)) {
		mss->referenced += size;
	}

	if (page_count(page) == 1) {
		ksu_susfs_smaps_page_accumulate(mss, page, size,
						size << KSU_SUSFS_PSS_SHIFT,
						dirty, locked, true);
		return;
	}

	for (i = 0; i < nr; i++, page++) {
		int mapcount = page_mapcount(page);
		unsigned long pss = PAGE_SIZE << KSU_SUSFS_PSS_SHIFT;

		if (mapcount >= 2) {
			pss /= mapcount;
		}

		ksu_susfs_smaps_page_accumulate(mss, page, PAGE_SIZE, pss, dirty,
						locked, mapcount < 2);
	}
}

#ifdef CONFIG_SHMEM
static int ksu_susfs_smaps_pte_hole(unsigned long addr, unsigned long end,
#ifdef KSU_SUSFS_PTE_HOLE_HAS_DEPTH
				    int depth,
#endif
				    struct mm_walk *walk)
{
	struct ksu_susfs_mem_size_stats *mss = walk->private;

#ifdef KSU_SUSFS_PTE_HOLE_HAS_DEPTH
	(void)depth;
#endif
	mss->swap += shmem_partial_swap_usage(walk->vma->vm_file->f_mapping,
					      addr, end);
	return 0;
}
#else
#define ksu_susfs_smaps_pte_hole NULL
#endif

static void ksu_susfs_smaps_pte_entry(pte_t *pte, unsigned long addr,
				      struct mm_walk *walk)
{
	struct ksu_susfs_mem_size_stats *mss = walk->private;
	struct vm_area_struct *vma = walk->vma;
	bool locked = !!(vma->vm_flags & VM_LOCKED);
	struct page *page = NULL;

	if (pte_present(*pte)) {
		page = vm_normal_page(vma, addr, *pte);
	} else if (is_swap_pte(*pte)) {
		swp_entry_t swpent = pte_to_swp_entry(*pte);

		if (!non_swap_entry(swpent)) {
			int mapcount;

			mss->swap += PAGE_SIZE;
			mapcount = swp_swapcount(swpent);
			if (mapcount >= 2) {
				u64 pss_delta = (u64)PAGE_SIZE
						<< KSU_SUSFS_PSS_SHIFT;

				do_div(pss_delta, mapcount);
				mss->swap_pss += pss_delta;
			} else {
				mss->swap_pss += (u64)PAGE_SIZE
						 << KSU_SUSFS_PSS_SHIFT;
			}
		} else if (ksu_susfs_is_pfn_swap_entry(swpent)) {
			page = ksu_susfs_pfn_swap_entry_to_page(swpent);
		}
	} else if (unlikely(IS_ENABLED(CONFIG_SHMEM) &&
			    mss->check_shmem_swap && pte_none(*pte))) {
		bool needs_put = false;

		page = ksu_susfs_find_shmem_swap_entry(
			vma->vm_file->f_mapping, linear_page_index(vma, addr),
			&needs_put);
		if (!page) {
			return;
		}

		if (ksu_susfs_pagecache_is_value(page)) {
			mss->swap += PAGE_SIZE;
		} else if (needs_put) {
			put_page(page);
		}
		return;
	}

	if (!page) {
		return;
	}

	ksu_susfs_smaps_account(mss, page, false, pte_young(*pte),
				pte_dirty(*pte), locked);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static void ksu_susfs_smaps_pmd_entry(pmd_t *pmd, unsigned long addr,
				      struct mm_walk *walk)
{
	struct ksu_susfs_mem_size_stats *mss = walk->private;
	struct vm_area_struct *vma = walk->vma;
	bool locked = !!(vma->vm_flags & VM_LOCKED);
	struct page *page;

	page = follow_trans_huge_pmd(vma, addr, pmd, FOLL_DUMP);
	if (IS_ERR_OR_NULL(page)) {
		return;
	}
	if (PageAnon(page)) {
		mss->anonymous_thp += HPAGE_PMD_SIZE;
	} else if (PageSwapBacked(page)) {
		mss->shmem_thp += HPAGE_PMD_SIZE;
	} else if (!is_zone_device_page(page)) {
		mss->file_thp += HPAGE_PMD_SIZE;
	}

	ksu_susfs_smaps_account(mss, page, true, pmd_young(*pmd),
				pmd_dirty(*pmd), locked);
}
#else
static void ksu_susfs_smaps_pmd_entry(pmd_t *pmd, unsigned long addr,
				      struct mm_walk *walk)
{
}
#endif

static int ksu_susfs_smaps_pte_range(pmd_t *pmd, unsigned long addr,
				     unsigned long end, struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->vma;
	pte_t *pte;
	spinlock_t *ptl;

	ptl = pmd_trans_huge_lock(pmd, vma);
	if (ptl) {
		if (pmd_present(*pmd)) {
			ksu_susfs_smaps_pmd_entry(pmd, addr, walk);
		}
		spin_unlock(ptl);
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	if (!pte) {
		walk->action = ACTION_AGAIN;
		goto out;
	}
#else
	if (pmd_trans_unstable(pmd)) {
		goto out;
	}
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
#endif
	for (; addr != end; pte++, addr += PAGE_SIZE) {
		ksu_susfs_smaps_pte_entry(pte, addr, walk);
	}
	pte_unmap_unlock(pte - 1, ptl);

out:
	cond_resched();
	return 0;
}

#ifdef CONFIG_HUGETLB_PAGE
static int ksu_susfs_smaps_hugetlb_range(pte_t *pte, unsigned long hmask,
					 unsigned long addr, unsigned long end,
					 struct mm_walk *walk)
{
	struct ksu_susfs_mem_size_stats *mss = walk->private;
	struct vm_area_struct *vma = walk->vma;
	struct page *page = NULL;

	if (pte_present(*pte)) {
		page = vm_normal_page(vma, addr, *pte);
	} else if (is_swap_pte(*pte)) {
		swp_entry_t swpent = pte_to_swp_entry(*pte);

		if (ksu_susfs_is_pfn_swap_entry(swpent)) {
			page = ksu_susfs_pfn_swap_entry_to_page(swpent);
		}
	}

	if (page) {
		if (page_mapcount(page) >= 2 ||
		    ksu_susfs_hugetlb_pmd_shared(pte)) {
			mss->shared_hugetlb += huge_page_size(hstate_vma(vma));
		} else {
			mss->private_hugetlb += huge_page_size(hstate_vma(vma));
		}
	}

	return 0;
}
#else
#define ksu_susfs_smaps_hugetlb_range NULL
#endif

#ifdef KSU_SUSFS_HAS_MM_WALK_OPS
static const struct mm_walk_ops ksu_susfs_smaps_walk_ops = {
	.pmd_entry = ksu_susfs_smaps_pte_range,
	.pte_hole = NULL,
	.hugetlb_entry = ksu_susfs_smaps_hugetlb_range,
};

static const struct mm_walk_ops ksu_susfs_smaps_shmem_walk_ops = {
	.pmd_entry = ksu_susfs_smaps_pte_range,
	.pte_hole = ksu_susfs_smaps_pte_hole,
	.hugetlb_entry = ksu_susfs_smaps_hugetlb_range,
};

static int ksu_susfs_walk_page_vma(struct vm_area_struct *vma,
				   struct ksu_susfs_mem_size_stats *mss,
				   bool check_shmem_swap)
{
	const struct mm_walk_ops *ops = check_shmem_swap ?
		&ksu_susfs_smaps_shmem_walk_ops : &ksu_susfs_smaps_walk_ops;

	return walk_page_vma(vma, ops, mss);
}
#else
static int ksu_susfs_walk_page_vma(struct vm_area_struct *vma,
				   struct ksu_susfs_mem_size_stats *mss,
				   bool check_shmem_swap)
{
	struct mm_walk walk = {
		.pmd_entry = ksu_susfs_smaps_pte_range,
		.hugetlb_entry = ksu_susfs_smaps_hugetlb_range,
		.mm = vma->vm_mm,
		.private = mss,
	};

	if (check_shmem_swap) {
		walk.pte_hole = ksu_susfs_smaps_pte_hole;
	}

	return walk_page_vma(vma, &walk);
}
#endif

static void ksu_susfs_smap_gather_stats(struct vm_area_struct *vma,
					struct ksu_susfs_mem_size_stats *mss)
{
#ifdef CONFIG_SHMEM
	mss->check_shmem_swap = false;
	if (vma->vm_file && shmem_mapping(vma->vm_file->f_mapping)) {
		unsigned long shmem_swapped = shmem_swap_usage(vma);

		if (!shmem_swapped || (vma->vm_flags & VM_SHARED) ||
		    !(vma->vm_flags & VM_WRITE)) {
			mss->swap += shmem_swapped;
		} else {
			mss->check_shmem_swap = true;
			ksu_susfs_walk_page_vma(vma, mss, true);
			return;
		}
	}
#endif
	ksu_susfs_walk_page_vma(vma, mss, false);
}

#define KSU_SUSFS_SEQ_PUT_DEC(str, val) \
	ksu_susfs_seq_put_decimal_ull_width(m, str, (val) >> 10, 8)

static void ksu_susfs_show_smap_common(
	struct seq_file *m, const struct ksu_susfs_mem_size_stats *mss,
	bool rollup_mode)
{
	KSU_SUSFS_SEQ_PUT_DEC("Rss:            ", mss->resident);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nPss:            ",
			      mss->pss >> KSU_SUSFS_PSS_SHIFT);
	if (rollup_mode) {
		KSU_SUSFS_SEQ_PUT_DEC(" kB\nPss_Anon:       ",
				      mss->pss_anon >> KSU_SUSFS_PSS_SHIFT);
		KSU_SUSFS_SEQ_PUT_DEC(" kB\nPss_File:       ",
				      mss->pss_file >> KSU_SUSFS_PSS_SHIFT);
		KSU_SUSFS_SEQ_PUT_DEC(" kB\nPss_Shmem:      ",
				      mss->pss_shmem >> KSU_SUSFS_PSS_SHIFT);
	}
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nShared_Clean:   ", mss->shared_clean);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nShared_Dirty:   ", mss->shared_dirty);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nPrivate_Clean:  ", mss->private_clean);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nPrivate_Dirty:  ", mss->private_dirty);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nReferenced:     ", mss->referenced);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nAnonymous:      ", mss->anonymous);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nLazyFree:       ", mss->lazyfree);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nAnonHugePages:  ", mss->anonymous_thp);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nShmemPmdMapped: ", mss->shmem_thp);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nFilePmdMapped:  ", mss->file_thp);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nShared_Hugetlb: ", mss->shared_hugetlb);
	ksu_susfs_seq_put_decimal_ull_width(
		m, " kB\nPrivate_Hugetlb: ", mss->private_hugetlb >> 10, 7);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nSwap:           ", mss->swap);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nSwapPss:        ",
			      mss->swap_pss >> KSU_SUSFS_PSS_SHIFT);
	KSU_SUSFS_SEQ_PUT_DEC(" kB\nLocked:         ",
			      mss->pss_locked >> KSU_SUSFS_PSS_SHIFT);
	seq_puts(m, " kB\n");
}

#undef KSU_SUSFS_SEQ_PUT_DEC

#ifdef CONFIG_NUMA
static void ksu_susfs_hold_task_mempolicy(struct proc_maps_private *priv)
{
	struct task_struct *task = priv->task;

	task_lock(task);
	priv->task_mempolicy = get_task_policy(task);
	mpol_get(priv->task_mempolicy);
	task_unlock(task);
}

static void ksu_susfs_release_task_mempolicy(struct proc_maps_private *priv)
{
	mpol_put(priv->task_mempolicy);
}
#else
static void ksu_susfs_hold_task_mempolicy(struct proc_maps_private *priv)
{
}

static void ksu_susfs_release_task_mempolicy(struct proc_maps_private *priv)
{
}
#endif

static int ksu_susfs_show_smaps_rollup(struct seq_file *m, void *v)
{
	struct proc_maps_private *priv = m->private;
	struct ksu_susfs_mem_size_stats mss;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long first_vma_start = 0;
	unsigned long last_vma_end = 0;
	bool have_visible_vma = false;
	int ret = 0;

	priv->task = get_proc_task(priv->inode);
	if (!priv->task) {
		return -ESRCH;
	}

	mm = priv->mm;
	if (!mm || !ksu_susfs_mmget_not_zero(mm)) {
		ret = -ESRCH;
		goto out_put_task;
	}

	memset(&mss, 0, sizeof(mss));

	ret = ksu_susfs_mmap_read_lock_killable(mm);
	if (ret) {
		goto out_put_mm;
	}

	ksu_susfs_hold_task_mempolicy(priv);

	for (vma = ksu_susfs_first_vma(mm); vma;
	     vma = ksu_susfs_next_vma(mm, vma)) {
		if (ksu_susfs_sus_map_hide_vma_current(vma, mm)) {
			last_vma_end = vma->vm_end;
			continue;
		}

		if (!have_visible_vma) {
			first_vma_start = vma->vm_start;
			have_visible_vma = true;
		}

		ksu_susfs_smap_gather_stats(vma, &mss);
		last_vma_end = vma->vm_end;
	}

	ksu_susfs_show_vma_header_prefix(m,
					 have_visible_vma ? first_vma_start : 0,
					 last_vma_end, 0, 0, 0, 0);
	seq_pad(m, ' ');
	seq_puts(m, "[rollup]\n");
	ksu_susfs_show_smap_common(m, &mss, true);

	ksu_susfs_release_task_mempolicy(priv);
	ksu_susfs_mmap_read_unlock(mm);

out_put_mm:
	mmput(mm);
out_put_task:
	put_task_struct(priv->task);
	priv->task = NULL;
	return ret;
}

static int ksu_susfs_pid_smaps_rollup_open(struct inode *inode,
					   struct file *file)
{
	struct proc_maps_private *priv;
	int ret;

	if (!ksu_susfs_orig_pid_smaps_rollup_open) {
		return -ENOSYS;
	}

	if (!ksu_susfs_proc_maps_view_enabled_current()) {
		return ksu_susfs_orig_pid_smaps_rollup_open(inode, file);
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL_ACCOUNT);
	if (!priv) {
		return -ENOMEM;
	}

	ret = single_open(file, ksu_susfs_show_smaps_rollup, priv);
	if (ret) {
		kfree(priv);
		return ret;
	}

	priv->inode = inode;
	priv->mm = proc_mem_open(inode, PTRACE_MODE_READ);
	if (IS_ERR(priv->mm)) {
		ret = PTR_ERR(priv->mm);
		single_release(inode, file);
		kfree(priv);
		return ret;
	}

	return 0;
}
#endif

static ssize_t ksu_susfs_pagemap_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct mm_struct *mm = file->private_data;
	ssize_t total = 0;

	if (!ksu_susfs_orig_pagemap_read || !mm ||
	    !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_pagemap_read ?
			       ksu_susfs_orig_pagemap_read(file, buf, count, ppos) :
			       -ENOSYS;
	}

	if ((*ppos % KSU_SUSFS_PAGEMAP_ENTRY_BYTES) ||
	    (count % KSU_SUSFS_PAGEMAP_ENTRY_BYTES)) {
		return ksu_susfs_orig_pagemap_read(file, buf, count, ppos);
	}

	while (count) {
		unsigned long addr;
		unsigned long boundary = 0;
		unsigned long span = 0;
		size_t chunk;
		size_t pages;
		bool hidden = false;
		int err;
		ssize_t ret;

		addr = ksu_susfs_pagemap_pos_to_addr(mm, *ppos);
		if (addr >= mm->task_size) {
			break;
		}

		pages = count / KSU_SUSFS_PAGEMAP_ENTRY_BYTES;
		span = mm->task_size - addr;
		if (pages < (span >> PAGE_SHIFT)) {
			span = pages << PAGE_SHIFT;
		}

		err = ksu_susfs_sus_map_next_boundary(mm, addr, span, &hidden,
						      &boundary);
		if (err) {
			return total ? total : err;
		}

		if (hidden) {
			chunk = min_t(size_t, count,
				      ksu_susfs_pagemap_addr_bytes(addr,
								  boundary));
			if (!chunk) {
				break;
			}
			if (clear_user(buf, chunk)) {
				return total ? total : -EFAULT;
			}
			*ppos += chunk;
			buf += chunk;
			count -= chunk;
			total += chunk;
			continue;
		}

		chunk = count;
		if (boundary > addr) {
			size_t limited = ksu_susfs_pagemap_addr_bytes(addr,
								      boundary);

			if (limited && limited < chunk) {
				chunk = limited;
			}
		}
		if (!chunk) {
			break;
		}

		ret = ksu_susfs_orig_pagemap_read(file, buf, chunk, ppos);
		if (ret <= 0) {
			return total ? total : ret;
		}

		buf += ret;
		count -= ret;
		total += ret;
		if (ret < chunk) {
			break;
		}
	}

	return total;
}

static __always_inline struct file *
ksu_susfs_files_lookup_fd_locked(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = files_fdtable(files);

	if (unlikely(fd >= fdt->max_fds))
		return NULL;

	fd = array_index_nospec(fd, fdt->max_fds);
	return rcu_dereference_check_fdtable(files, fdt->fd[fd]);
}

static bool ksu_susfs_fd_is_hidden(struct task_struct *task, unsigned int fd)
{
	struct files_struct *files;
	struct file *fd_file;
	bool hidden = false;

	if (!task) {
		return false;
	}

	files = get_files_struct(task);
	if (!files) {
		return false;
	}

	spin_lock(&files->file_lock);
	fd_file = ksu_susfs_files_lookup_fd_locked(files, fd);
	if (fd_file) {
		hidden = ksu_susfs_sus_map_match_file(fd_file);
	}
	spin_unlock(&files->file_lock);
	put_files_struct(files);
	return hidden;
}

static bool ksu_susfs_proc_fd_dentry_hidden(struct dentry *dentry)
{
	struct task_struct *task;
	struct dentry *parent;
	unsigned int fd;
	bool hidden;

	if (!dentry) {
		return false;
	}

	parent = READ_ONCE(dentry->d_parent);
	if (!parent || parent == dentry || parent->d_name.len != 2 ||
	    memcmp(parent->d_name.name, "fd", 2)) {
		return false;
	}

	fd = name_to_int(&dentry->d_name);
	if (fd == ~0U) {
		return false;
	}

	task = get_proc_task(d_inode(dentry));
	if (!task) {
		return false;
	}

	hidden = ksu_susfs_fd_is_hidden(task, fd);
	put_task_struct(task);
	return hidden;
}

static int ksu_susfs_copy_fake_link(char __user *buf, int buflen)
{
	static const char fake[] = "anon_inode:[eventfd]";
	int len;

	if (buflen <= 0) {
		return 0;
	}

	len = min_t(int, buflen, sizeof(fake) - 1);
	return copy_to_user(buf, fake, len) ? -EFAULT : len;
}

#ifdef __aarch64__
struct ksu_susfs_user_frame {
	unsigned long fp;
	unsigned long lr;
};

static int ksu_susfs_collect_user_callchain(unsigned long *pcs, int max)
{
	struct pt_regs *regs = current_pt_regs();
	struct mm_struct *mm = current->mm;
	unsigned long fp;
	unsigned long sp;
	unsigned long last_fp = 0;
	int nr = 0;
	int i;

	if (!regs || !mm || max <= 0) {
		return 0;
	}

	pcs[nr++] = untagged_addr(PT_REGS_IP(regs));
	if (nr < max) {
		pcs[nr++] = untagged_addr(PT_REGS_RET(regs));
	}

	fp = untagged_addr(PT_REGS_FP(regs));
	sp = untagged_addr(PT_REGS_SP(regs));
	for (i = 0; i < KSU_SUSFS_USER_CALLCHAIN_MAX && nr < max; i++) {
		struct ksu_susfs_user_frame frame;

		if (!fp || fp >= mm->task_size || (fp & 0xf)) {
			break;
		}
		if (sp && fp < sp) {
			break;
		}
		if (last_fp && fp <= last_fp) {
			break;
		}
		if (fp + sizeof(frame) < fp ||
		    fp + sizeof(frame) > mm->task_size) {
			break;
		}
		if (copy_from_user_nofault(&frame,
					   (const void __user *)fp,
					   sizeof(frame))) {
			break;
		}

		pcs[nr++] = untagged_addr(frame.lr);
		last_fp = fp;
		fp = untagged_addr(frame.fp);
	}

	return nr;
}

static bool
ksu_susfs_current_callchain_from_sus_map_locked(struct mm_struct *locked_mm)
{
	unsigned long pcs[KSU_SUSFS_USER_CALLCHAIN_MAX + 2];
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	bool have_lock;
	int nr;
	int i;
	bool matched = false;

	if (!mm) {
		return false;
	}

	nr = ksu_susfs_collect_user_callchain(pcs, ARRAY_SIZE(pcs));
	if (!nr) {
		return false;
	}
	have_lock = locked_mm == mm;
	if (!have_lock && ksu_susfs_mmap_read_lock_killable(mm)) {
		return false;
	}

	for (i = 0; i < nr; i++) {
		unsigned long addr = pcs[i];

		if (!addr || addr >= mm->task_size) {
			continue;
		}

		vma = find_vma(mm, addr);
		if (vma && addr >= vma->vm_start &&
		    ksu_susfs_sus_map_match_vma(vma)) {
			matched = true;
			break;
		}
	}

	if (!have_lock) {
		ksu_susfs_mmap_read_unlock(mm);
	}
	return matched;
}

static bool ksu_susfs_current_callchain_from_sus_map(void)
{
	return ksu_susfs_current_callchain_from_sus_map_locked(NULL);
}
#else
static bool
ksu_susfs_current_callchain_from_sus_map_locked(struct mm_struct *locked_mm)
{
	return false;
}

static bool ksu_susfs_current_callchain_from_sus_map(void)
{
	return false;
}
#endif

static int ksu_susfs_fd_readlink(struct dentry *dentry, char __user *buf,
				 int buflen)
{
	if (!ksu_susfs_orig_fd_readlink) {
		return -ENOSYS;
	}
	if (ksu_susfs_sus_map_should_hide_current() &&
	    ksu_susfs_proc_fd_dentry_hidden(dentry) &&
	    !ksu_susfs_current_callchain_from_sus_map()) {
		return ksu_susfs_copy_fake_link(buf, buflen);
	}

	return ksu_susfs_orig_fd_readlink(dentry, buf, buflen);
}

static int ksu_susfs_dname_to_vma_addr(struct dentry *dentry,
				       unsigned long *start,
				       unsigned long *end)
{
	const char *str = dentry->d_name.name;
	char *sep;
	char *tail;
	unsigned long sval;
	unsigned long eval;

	if (!start || !end) {
		return -EINVAL;
	}

	if (str[0] == '0' && str[1] != '-') {
		return -EINVAL;
	}

	sep = strchr(str, '-');
	if (!sep || sep == str || !sep[1]) {
		return -EINVAL;
	}

	sval = simple_strtoul(str, &tail, 16);
	if (tail != sep) {
		return -EINVAL;
	}

	if (sep[1] == '0' && sep[2]) {
		return -EINVAL;
	}

	eval = simple_strtoul(sep + 1, &tail, 16);
	if (!tail || *tail != '\0') {
		return -EINVAL;
	}

	*start = sval;
	*end = eval;
	return 0;
}

static bool ksu_susfs_map_files_dentry_hidden(struct dentry *dentry)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long vm_start;
	unsigned long vm_end;
	bool hidden = false;

	if (!dentry || ksu_susfs_dname_to_vma_addr(dentry, &vm_start, &vm_end)) {
		return false;
	}

	task = get_proc_task(d_inode(dentry));
	if (!task) {
		return false;
	}

	mm = mm_access(task, PTRACE_MODE_READ_FSCREDS);
	if (!IS_ERR_OR_NULL(mm)) {
		if (!ksu_susfs_mmap_read_lock_killable(mm)) {
			vma = find_exact_vma(mm, vm_start, vm_end);
			hidden = vma && vma->vm_file &&
				 ksu_susfs_sus_map_match_vma(vma);
			ksu_susfs_mmap_read_unlock(mm);
		}
		mmput(mm);
	}
	put_task_struct(task);
	return hidden;
}

static int ksu_susfs_map_files_readlink(struct dentry *dentry,
					char __user *buf, int buflen)
{
	if (!ksu_susfs_orig_map_files_readlink) {
		return -ENOSYS;
	}
	if (ksu_susfs_sus_map_should_hide_current() &&
	    ksu_susfs_map_files_dentry_hidden(dentry) &&
	    !ksu_susfs_current_callchain_from_sus_map()) {
		return ksu_susfs_copy_fake_link(buf, buflen);
	}

	return ksu_susfs_orig_map_files_readlink(dentry, buf, buflen);
}

static int ksu_susfs_map_files_d_revalidate(struct dentry *dentry,
					    unsigned int flags)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long vm_start;
	unsigned long vm_end;
	bool hidden = false;
	int status;

	if (!ksu_susfs_orig_map_files_d_revalidate ||
	    !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_map_files_d_revalidate ?
			       ksu_susfs_orig_map_files_d_revalidate(dentry,
								      flags) :
			       0;
	}

	if (flags & LOOKUP_RCU) {
		return -ECHILD;
	}

	if (ksu_susfs_dname_to_vma_addr(dentry, &vm_start, &vm_end)) {
		return ksu_susfs_orig_map_files_d_revalidate(dentry, flags);
	}

	task = get_proc_task(d_inode(dentry));
	if (!task) {
		return 0;
	}

	mm = mm_access(task, PTRACE_MODE_READ_FSCREDS);
	if (!IS_ERR_OR_NULL(mm)) {
		status = ksu_susfs_mmap_read_lock_killable(mm);
		if (!status) {
			vma = find_exact_vma(mm, vm_start, vm_end);
			hidden = vma && vma->vm_file &&
				 ksu_susfs_sus_map_match_vma(vma);
			ksu_susfs_mmap_read_unlock(mm);
		}
		mmput(mm);
	}
	put_task_struct(task);

	if (hidden) {
		return 0;
	}

	return ksu_susfs_orig_map_files_d_revalidate(dentry, flags);
}

static struct dentry *ksu_susfs_map_files_lookup(struct inode *dir,
						 struct dentry *dentry,
						 unsigned int flags)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long vm_start;
	unsigned long vm_end;
	int err;
	bool visible = false;

	if (!ksu_susfs_orig_map_files_lookup ||
	    !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_map_files_lookup ?
			       ksu_susfs_orig_map_files_lookup(dir, dentry, flags) :
			       ERR_PTR(-ENOSYS);
	}

	task = get_proc_task(dir);
	if (!task) {
		return ERR_PTR(-ENOENT);
	}

	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)) {
		put_task_struct(task);
		return ERR_PTR(-EACCES);
	}

	if (ksu_susfs_dname_to_vma_addr(dentry, &vm_start, &vm_end)) {
		put_task_struct(task);
		return ERR_PTR(-ENOENT);
	}

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return ERR_PTR(-ENOENT);
	}

	err = ksu_susfs_mmap_read_lock_killable(mm);
	if (err) {
		mmput(mm);
		put_task_struct(task);
		return ERR_PTR(err);
	}

	vma = find_exact_vma(mm, vm_start, vm_end);
	if (vma && vma->vm_file && !ksu_susfs_sus_map_match_vma(vma)) {
		visible = true;
	}

	ksu_susfs_mmap_read_unlock(mm);
	mmput(mm);
	put_task_struct(task);

	if (!visible) {
		return ERR_PTR(-ENOENT);
	}

	return ksu_susfs_orig_map_files_lookup(dir, dentry, flags);
}

static int ksu_susfs_map_files_iterate_shared(struct file *file,
					      struct dir_context *ctx)
{
	struct vm_area_struct *vma;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long nr_files;
	unsigned long pos;
	unsigned long i;
	struct ksu_susfs_map_files_store store = { };
	struct ksu_susfs_map_files_info info;
	struct ksu_susfs_map_files_info *p;
	int ret;

	if (!ksu_susfs_orig_map_files_iterate_shared ||
	    !ksu_susfs_map_files_instantiate ||
	    !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_map_files_iterate_shared ?
			       ksu_susfs_orig_map_files_iterate_shared(file, ctx) :
			       -ENOSYS;
	}

	ret = -ENOENT;
	task = get_proc_task(file_inode(file));
	if (!task) {
		goto out;
	}

	ret = -EACCES;
	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)) {
		goto out_put_task;
	}

	ret = 0;
	if (!dir_emit_dots(file, ctx)) {
		goto out_put_task;
	}

	mm = get_task_mm(task);
	if (!mm) {
		goto out_put_task;
	}

	ret = ksu_susfs_mmap_read_lock_killable(mm);
	if (ret) {
		mmput(mm);
		goto out_put_task;
	}
	ret = ksu_susfs_map_files_store_init(&store, mm->map_count);
	if (ret) {
		ksu_susfs_mmap_read_unlock(mm);
		mmput(mm);
		goto out_put_task;
	}

	nr_files = 0;
	for (vma = ksu_susfs_first_vma(mm), pos = 2; vma;
	     vma = ksu_susfs_next_vma(mm, vma)) {
		if (!vma->vm_file || ksu_susfs_sus_map_match_vma(vma)) {
			continue;
		}
		if (++pos <= ctx->pos) {
			continue;
		}

		info.start = vma->vm_start;
		info.end = ksu_susfs_vma_pad_start(vma);
		info.mode = vma->vm_file->f_mode;
		ret = ksu_susfs_map_files_store_add(&store, nr_files, &info);
		if (ret) {
			ksu_susfs_mmap_read_unlock(mm);
			mmput(mm);
			goto out_put_task;
		}
		nr_files++;
	}
	ksu_susfs_mmap_read_unlock(mm);
	mmput(mm);

	for (i = 0; i < nr_files; i++) {
		char name[4 * sizeof(long) + 2];
		unsigned int len;

		p = ksu_susfs_map_files_store_get(&store, i);
		if (!p) {
			ret = -EIO;
			break;
		}
		len = snprintf(name, sizeof(name), "%lx-%lx", p->start, p->end);
		if (!proc_fill_cache(file, ctx, name, len,
				     ksu_susfs_map_files_instantiate, task,
				     (void *)(unsigned long)p->mode)) {
			break;
		}
		ctx->pos++;
	}

out_put_task:
	put_task_struct(task);
out:
	ksu_susfs_map_files_store_free(&store);
	return ret;
}

static ssize_t ksu_susfs_mem_visible_count(struct file *file, loff_t *ppos,
					   size_t count, bool *hidden)
{
	struct mm_struct *mm = file->private_data;
	unsigned long addr;
	unsigned long boundary = 0;
	int err;

	if (!hidden) {
		return -EINVAL;
	}

	*hidden = false;
	if (!mm || !count) {
		return count;
	}

	addr = (unsigned long)*ppos;
	err = ksu_susfs_sus_map_next_boundary(mm, addr, count, hidden, &boundary);
	if (err) {
		return err;
	}

	if (*hidden) {
		return 0;
	}
	if (boundary <= addr) {
		return count;
	}

	return min_t(size_t, count, boundary - addr);
}

static ssize_t ksu_susfs_mem_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	ssize_t visible;
	bool hidden;

	if (!ksu_susfs_orig_mem_read || !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_mem_read ?
			       ksu_susfs_orig_mem_read(file, buf, count, ppos) :
			       -ENOSYS;
	}

	visible = ksu_susfs_mem_visible_count(file, ppos, count, &hidden);
	if (visible < 0) {
		return visible;
	}
	if (hidden) {
		return -EIO;
	}
	if (visible > 0 && visible < count) {
		count = visible;
	}

	return ksu_susfs_orig_mem_read(file, buf, count, ppos);
}

static ssize_t ksu_susfs_mem_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	ssize_t visible;
	bool hidden;

	if (!ksu_susfs_orig_mem_write ||
	    !ksu_susfs_sus_map_should_hide_current()) {
		return ksu_susfs_orig_mem_write ?
			       ksu_susfs_orig_mem_write(file, buf, count, ppos) :
			       -ENOSYS;
	}

	visible = ksu_susfs_mem_visible_count(file, ppos, count, &hidden);
	if (visible < 0) {
		return visible;
	}
	if (hidden) {
		return -EIO;
	}
	if (visible > 0 && visible < count) {
		count = visible;
	}

	return ksu_susfs_orig_mem_write(file, buf, count, ppos);
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

static void ksu_susfs_kstat_clear_all(void)
{
	struct ksu_susfs_kstat_entry *entry, *tmp;
	LIST_HEAD(free_list);

	mutex_lock(&ksu_susfs_kstat_lock);
	list_for_each_entry_safe(entry, tmp, &ksu_susfs_kstat_list, list) {
		hash_del_rcu(&entry->node);
		list_del(&entry->list);
		list_add_tail(&entry->list, &free_list);
	}

	ksu_susfs_kstat_rule_count = 0;
	if (static_key_enabled(&ksu_susfs_kstat_enabled)) {
		static_branch_disable(&ksu_susfs_kstat_enabled);
	}
	mutex_unlock(&ksu_susfs_kstat_lock);

	synchronize_rcu();

	list_for_each_entry_safe(entry, tmp, &free_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static void ksu_susfs_sus_map_clear_all(void)
{
	struct ksu_susfs_sus_map_entry *entry, *tmp;
	LIST_HEAD(free_list);

	mutex_lock(&ksu_susfs_sus_map_lock);
	list_for_each_entry_safe(entry, tmp, &ksu_susfs_sus_map_list, list) {
		hash_del_rcu(&entry->node);
		list_del(&entry->list);
		list_add_tail(&entry->list, &free_list);
	}

	ksu_susfs_sus_map_rule_count = 0;
	if (static_key_enabled(&ksu_susfs_sus_map_enabled)) {
		static_branch_disable(&ksu_susfs_sus_map_enabled);
	}
	mutex_unlock(&ksu_susfs_sus_map_lock);

	synchronize_rcu();

	list_for_each_entry_safe(entry, tmp, &free_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
}

static int
ksu_susfs_kstat_build_entry(struct ksu_susfs_kstat_entry *entry,
			     struct ksu_susfs_kstat_cmd *cmd,
			     const char *normalized_path)
{
	int err;

	memset(entry, 0, sizeof(*entry));

	err = ksu_susfs_kstat_fill_target(normalized_path, &entry->target_ino,
					  &entry->target_dev);
	if (err) {
		return err;
	}

	INIT_LIST_HEAD(&entry->list);
	INIT_HLIST_NODE(&entry->node);
	strscpy(entry->target_pathname, normalized_path,
		sizeof(entry->target_pathname));
	entry->spoofed_ino = cmd->spoofed_ino;
	entry->spoofed_dev = ksu_susfs_kstat_decode_dev(cmd->spoofed_dev);
	entry->spoofed_nlink = cmd->spoofed_nlink;
	entry->spoofed_size = cmd->spoofed_size;
	entry->spoofed_atime_tv_sec = cmd->spoofed_atime_tv_sec;
	entry->spoofed_atime_tv_nsec = cmd->spoofed_atime_tv_nsec;
	entry->spoofed_mtime_tv_sec = cmd->spoofed_mtime_tv_sec;
	entry->spoofed_mtime_tv_nsec = cmd->spoofed_mtime_tv_nsec;
	entry->spoofed_ctime_tv_sec = cmd->spoofed_ctime_tv_sec;
	entry->spoofed_ctime_tv_nsec = cmd->spoofed_ctime_tv_nsec;
	entry->spoofed_blocks = cmd->spoofed_blocks;
	entry->spoofed_blksize = cmd->spoofed_blksize;
	entry->flags = cmd->flags;
	entry->is_statically = !!cmd->is_statically;

	cmd->target_ino = entry->target_ino;
	return 0;
}

static int ksu_susfs_kstat_add_rule(struct ksu_susfs_kstat_cmd *cmd)
{
	struct ksu_susfs_kstat_entry *entry;
	struct ksu_susfs_kstat_entry *old = NULL;
	char normalized_path[KSU_SUSFS_MAX_PATHNAME];
	int err;

	err = ksu_susfs_kstat_normalize_path(normalized_path,
					     sizeof(normalized_path),
					     cmd->target_pathname);
	if (err) {
		return err;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		return -ENOMEM;
	}

	err = ksu_susfs_kstat_build_entry(entry, cmd, normalized_path);
	if (err) {
		kfree(entry);
		return err;
	}

	mutex_lock(&ksu_susfs_kstat_lock);
	old = ksu_susfs_kstat_find_path_locked(normalized_path);
	if (old) {
		hash_del_rcu(&old->node);
		list_del(&old->list);
	}

	hash_add_rcu(ksu_susfs_kstat_ht, &entry->node, entry->target_ino);
	list_add_tail(&entry->list, &ksu_susfs_kstat_list);

	if (!old && ksu_susfs_kstat_rule_count++ == 0) {
		static_branch_enable(&ksu_susfs_kstat_enabled);
	}
	mutex_unlock(&ksu_susfs_kstat_lock);

	if (old) {
		synchronize_rcu();
		kfree(old);
	}

	return 0;
}

static int ksu_susfs_sus_map_add_rule(struct ksu_susfs_map_cmd *cmd)
{
	struct ksu_susfs_sus_map_entry *entry;
	struct ksu_susfs_sus_map_entry *old = NULL;
	char normalized_path[KSU_SUSFS_MAX_PATHNAME];
	int err;

	err = ksu_susfs_kstat_normalize_path(normalized_path,
					     sizeof(normalized_path),
					     cmd->target_pathname);
	if (err) {
		return err;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		return -ENOMEM;
	}

	err = ksu_susfs_kstat_fill_target(normalized_path, &entry->target_ino,
					  &entry->target_dev);
	if (err) {
		kfree(entry);
		return err;
	}

	INIT_LIST_HEAD(&entry->list);
	INIT_HLIST_NODE(&entry->node);
	strscpy(entry->target_pathname, normalized_path,
		sizeof(entry->target_pathname));

	mutex_lock(&ksu_susfs_sus_map_lock);
	old = ksu_susfs_sus_map_find_path_locked(normalized_path);
	if (old) {
		hash_del_rcu(&old->node);
		list_del(&old->list);
	} else if (ksu_susfs_sus_map_rule_count++ == 0) {
		static_branch_enable(&ksu_susfs_sus_map_enabled);
	}

	hash_add_rcu(ksu_susfs_sus_map_ht, &entry->node, entry->target_ino);
	list_add_tail(&entry->list, &ksu_susfs_sus_map_list);
	mutex_unlock(&ksu_susfs_sus_map_lock);

	if (old) {
		synchronize_rcu();
		kfree(old);
	}

	return 0;
}

static int ksu_susfs_kstat_update_rule(struct ksu_susfs_kstat_cmd *cmd)
{
	struct ksu_susfs_kstat_entry *entry;
	struct ksu_susfs_kstat_entry *old;
	char normalized_path[KSU_SUSFS_MAX_PATHNAME];
	int err;

	err = ksu_susfs_kstat_normalize_path(normalized_path,
					     sizeof(normalized_path),
					     cmd->target_pathname);
	if (err) {
		return err;
	}

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		return -ENOMEM;
	}

	mutex_lock(&ksu_susfs_kstat_lock);
	old = ksu_susfs_kstat_find_path_locked(normalized_path);
	if (!old) {
		mutex_unlock(&ksu_susfs_kstat_lock);
		kfree(entry);
		return -ENOENT;
	}

	memcpy(entry, old, sizeof(*entry));
	INIT_LIST_HEAD(&entry->list);
	INIT_HLIST_NODE(&entry->node);
	entry->target_ino = 0;
	entry->target_dev = 0;
	entry->spoofed_ino = cmd->spoofed_ino;
	entry->spoofed_dev = ksu_susfs_kstat_decode_dev(cmd->spoofed_dev);
	entry->spoofed_nlink = cmd->spoofed_nlink;
	entry->spoofed_size = cmd->spoofed_size;
	entry->spoofed_atime_tv_sec = cmd->spoofed_atime_tv_sec;
	entry->spoofed_atime_tv_nsec = cmd->spoofed_atime_tv_nsec;
	entry->spoofed_mtime_tv_sec = cmd->spoofed_mtime_tv_sec;
	entry->spoofed_mtime_tv_nsec = cmd->spoofed_mtime_tv_nsec;
	entry->spoofed_ctime_tv_sec = cmd->spoofed_ctime_tv_sec;
	entry->spoofed_ctime_tv_nsec = cmd->spoofed_ctime_tv_nsec;
	entry->spoofed_blocks = cmd->spoofed_blocks;
	entry->spoofed_blksize = cmd->spoofed_blksize;
	entry->flags = cmd->flags;
	mutex_unlock(&ksu_susfs_kstat_lock);

	err = ksu_susfs_kstat_fill_target(normalized_path, &entry->target_ino,
					  &entry->target_dev);
	if (err) {
		kfree(entry);
		return err;
	}

	cmd->target_ino = entry->target_ino;

	mutex_lock(&ksu_susfs_kstat_lock);
	old = ksu_susfs_kstat_find_path_locked(normalized_path);
	if (!old) {
		mutex_unlock(&ksu_susfs_kstat_lock);
		kfree(entry);
		return -ENOENT;
	}

	hash_del_rcu(&old->node);
	list_del(&old->list);
	hash_add_rcu(ksu_susfs_kstat_ht, &entry->node, entry->target_ino);
	list_add_tail(&entry->list, &ksu_susfs_kstat_list);
	mutex_unlock(&ksu_susfs_kstat_lock);

	synchronize_rcu();
	kfree(old);
	return 0;
}

bool ksu_susfs_handle_kstat_compat(unsigned int cmd, void __user *arg)
{
	struct ksu_susfs_kstat_cmd cmd_data;
	int err = -EINVAL;

	memset(&cmd_data, 0, sizeof(cmd_data));
	if (copy_from_user(&cmd_data, arg, sizeof(cmd_data))) {
		return true;
	}

	cmd_data.target_pathname[sizeof(cmd_data.target_pathname) - 1] = '\0';

	if (!ksu_susfs_kstat_compat_root_allowed()) {
		cmd_data.err = -EPERM;
		goto out;
	}

	if (!ksu_susfs_getattr_ready) {
		cmd_data.err = -EOPNOTSUPP;
		goto out;
	}

	switch (cmd) {
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT:
		cmd_data.is_statically = 0;
		err = ksu_susfs_kstat_add_rule(&cmd_data);
		break;
	case KSU_SUSFS_CMD_ADD_SUS_KSTAT_STATICALLY:
		cmd_data.is_statically = 1;
		err = ksu_susfs_kstat_add_rule(&cmd_data);
		break;
	case KSU_SUSFS_CMD_UPDATE_SUS_KSTAT:
		err = ksu_susfs_kstat_update_rule(&cmd_data);
		break;
	default:
		err = -EINVAL;
		break;
	}

	cmd_data.err = err;

out:
	if (copy_to_user(arg, &cmd_data, sizeof(cmd_data))) {
		pr_err("susfs: kstat compat copy_to_user failed\n");
	}
	return true;
}

bool ksu_susfs_handle_sus_map_compat(void __user *arg)
{
	struct ksu_susfs_map_cmd cmd_data;
	int err = -EINVAL;

	memset(&cmd_data, 0, sizeof(cmd_data));
	if (copy_from_user(&cmd_data, arg, sizeof(cmd_data))) {
		return true;
	}

	cmd_data.target_pathname[sizeof(cmd_data.target_pathname) - 1] = '\0';

	if (!ksu_susfs_kstat_compat_root_allowed()) {
		cmd_data.err = -EPERM;
		goto out;
	}

	err = ksu_susfs_sus_map_add_rule(&cmd_data);
	cmd_data.err = err;

out:
	if (copy_to_user(arg, &cmd_data, sizeof(cmd_data))) {
		pr_err("susfs: sus_map compat copy_to_user failed\n");
	}

	return true;
}

int ksu_susfs_kstat_init(void)
{
	unsigned long addr;
	int err;

	hash_init(ksu_susfs_kstat_ht);
	hash_init(ksu_susfs_sus_map_ht);
	ksu_susfs_kstat_rule_count = 0;
	ksu_susfs_sus_map_rule_count = 0;

#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
	ksu_susfs_getattr_ready = false;
#else
	ksu_susfs_vfs_getattr_nosec_rp = ksu_susfs_init_kretprobe(
		"vfs_getattr_nosec", ksu_susfs_kstat_vfs_getattr_entry,
		ksu_susfs_kstat_vfs_getattr_handler,
		sizeof(struct ksu_susfs_vfs_getattr_ctx));
	if (!ksu_susfs_vfs_getattr_nosec_rp) {
		return -ENOENT;
	}
	ksu_susfs_getattr_ready = true;
#endif

	addr = find_kernel_symbol_exact("proc_pid_maps_op");
	if (addr) {
		ksu_susfs_maps_seqops = (const struct seq_operations *)addr;
		err = ksu_susfs_patch_seqop_show(ksu_susfs_maps_seqops,
						 ksu_susfs_show_map,
						 &ksu_susfs_orig_maps_show);
		if (err) {
			pr_warn("susfs: proc maps seq wrapper unavailable: %d\n",
				err);
			ksu_susfs_maps_seqops = NULL;
		} else {
			ksu_susfs_maps_ready = true;
		}
	}

	addr = find_kernel_symbol_exact("proc_pid_smaps_op");
	if (addr) {
		ksu_susfs_smaps_seqops = (const struct seq_operations *)addr;
		err = ksu_susfs_patch_seqop_show(ksu_susfs_smaps_seqops,
						 ksu_susfs_show_smap,
						 &ksu_susfs_orig_smaps_show);
		if (err) {
			pr_warn("susfs: proc smaps seq wrapper unavailable: %d\n",
				err);
			ksu_susfs_smaps_seqops = NULL;
		} else {
			ksu_susfs_smaps_ready = true;
		}
	}

#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
	if (ksu_susfs_sus_map_smaps_rollup_enabled) {
		err = ksu_susfs_patch_fop_open(
			&proc_pid_smaps_rollup_operations,
			ksu_susfs_pid_smaps_rollup_open,
			&ksu_susfs_orig_pid_smaps_rollup_open);
		if (err) {
			pr_warn("susfs: proc smaps_rollup wrapper unavailable: %d\n",
				err);
		} else {
			ksu_susfs_smaps_rollup_ready = true;
		}
	}
#endif

	if (ksu_susfs_sus_map_pagemap_enabled) {
		err = ksu_susfs_patch_fop_read(&proc_pagemap_operations,
					       ksu_susfs_pagemap_read,
					       &ksu_susfs_orig_pagemap_read);
		if (err) {
			pr_warn("susfs: proc pagemap wrapper unavailable: %d\n", err);
		} else {
			ksu_susfs_pagemap_ready = true;
		}
	}

	if (ksu_susfs_sus_map_fd_readlink_enabled) {
		ksu_susfs_fd_link_iops = &proc_pid_link_inode_operations;
		err = ksu_susfs_patch_iop_readlink(
			ksu_susfs_fd_link_iops, ksu_susfs_fd_readlink,
			&ksu_susfs_orig_fd_readlink);
		if (err) {
			pr_warn("susfs: proc fd readlink wrapper unavailable: %d\n",
				err);
		} else {
			ksu_susfs_fd_readlink_ready = true;
		}
		if (!ksu_susfs_fd_readlink_ready) {
			ksu_susfs_fd_link_iops = NULL;
		}
	}

	if (ksu_susfs_sus_map_map_files_readlink_enabled) {
		addr = find_kernel_symbol_exact("proc_map_files_link_inode_operations");
		if (addr) {
			ksu_susfs_map_files_link_iops =
				(const struct inode_operations *)addr;
			err = ksu_susfs_patch_iop_readlink(
				ksu_susfs_map_files_link_iops,
				ksu_susfs_map_files_readlink,
				&ksu_susfs_orig_map_files_readlink);
			if (err) {
				pr_warn("susfs: proc map_files readlink wrapper unavailable: %d\n",
					err);
				ksu_susfs_map_files_link_iops = NULL;
			} else {
				ksu_susfs_map_files_readlink_ready = true;
			}
		}
	}

	if (ksu_susfs_sus_map_map_files_iterate_enabled) {
		ksu_susfs_map_files_instantiate =
			(instantiate_t *)ksu_resolve_symbol_for_functable_hook(
				"proc_map_files_instantiate");

		addr = find_kernel_symbol_exact("proc_map_files_operations");
		if (addr) {
			ksu_susfs_map_files_fops =
				(const struct file_operations *)addr;
			err = ksu_susfs_patch_fop_iterate_shared(
				ksu_susfs_map_files_fops,
				ksu_susfs_map_files_iterate_shared,
				&ksu_susfs_orig_map_files_iterate_shared);
			if (err) {
				pr_warn("susfs: proc map_files iterate wrapper unavailable: %d\n",
					err);
				ksu_susfs_map_files_fops = NULL;
			} else {
				ksu_susfs_map_files_iterate_ready = true;
			}
		}
	}

	if (ksu_susfs_sus_map_map_files_lookup_enabled) {
		addr = find_kernel_symbol_exact("proc_map_files_inode_operations");
		if (addr) {
			ksu_susfs_map_files_iops =
				(const struct inode_operations *)addr;
			err = ksu_susfs_patch_iop_lookup(
				ksu_susfs_map_files_iops,
				ksu_susfs_map_files_lookup,
				&ksu_susfs_orig_map_files_lookup);
			if (err) {
				pr_warn("susfs: proc map_files lookup wrapper unavailable: %d\n",
					err);
				ksu_susfs_map_files_iops = NULL;
			} else {
				ksu_susfs_map_files_lookup_ready = true;
			}
		}

		addr = find_kernel_symbol_exact("tid_map_files_dentry_operations");
		if (addr) {
			ksu_susfs_map_files_dops =
				(const struct dentry_operations *)addr;
			err = ksu_susfs_patch_dop_d_revalidate(
				ksu_susfs_map_files_dops,
				ksu_susfs_map_files_d_revalidate,
				&ksu_susfs_orig_map_files_d_revalidate);
			if (err) {
				pr_warn("susfs: proc map_files d_revalidate wrapper unavailable: %d\n",
					err);
				ksu_susfs_map_files_dops = NULL;
			} else {
				ksu_susfs_map_files_d_revalidate_ready = true;
			}
		}
	}

	if (ksu_susfs_sus_map_proc_mem_enabled) {
		addr = find_kernel_symbol_exact("proc_mem_operations");
		if (addr) {
			ksu_susfs_mem_fops = (const struct file_operations *)addr;

			err = ksu_susfs_patch_fop_read(ksu_susfs_mem_fops,
						       ksu_susfs_mem_read,
						       &ksu_susfs_orig_mem_read);
			if (err) {
				pr_warn("susfs: proc mem read wrapper unavailable: %d\n",
					err);
				ksu_susfs_mem_fops = NULL;
			} else {
				ksu_susfs_mem_read_ready = true;
				err = ksu_susfs_patch_fop_write(
					ksu_susfs_mem_fops,
					ksu_susfs_mem_write,
					&ksu_susfs_orig_mem_write);
				if (err) {
					pr_warn("susfs: proc mem write wrapper unavailable: %d\n",
						err);
					ksu_susfs_restore_fop_read(
						ksu_susfs_mem_fops,
						&ksu_susfs_orig_mem_read);
					ksu_susfs_mem_read_ready = false;
					ksu_susfs_mem_fops = NULL;
				} else {
					ksu_susfs_mem_write_ready = true;
				}
			}
		}
	}

	return 0;
}

void ksu_susfs_kstat_exit(void)
{
	if (ksu_susfs_mem_write_ready) {
		ksu_susfs_restore_fop_write(ksu_susfs_mem_fops,
					    &ksu_susfs_orig_mem_write);
		ksu_susfs_mem_write_ready = false;
	}

	if (ksu_susfs_mem_read_ready) {
		ksu_susfs_restore_fop_read(ksu_susfs_mem_fops,
					   &ksu_susfs_orig_mem_read);
		ksu_susfs_mem_read_ready = false;
	}
	ksu_susfs_mem_fops = NULL;

	if (ksu_susfs_fd_readlink_ready) {
		ksu_susfs_restore_iop_readlink(ksu_susfs_fd_link_iops,
					       &ksu_susfs_orig_fd_readlink);
		ksu_susfs_fd_readlink_ready = false;
	}
	ksu_susfs_fd_link_iops = NULL;

	if (ksu_susfs_map_files_readlink_ready) {
		ksu_susfs_restore_iop_readlink(
			ksu_susfs_map_files_link_iops,
			&ksu_susfs_orig_map_files_readlink);
		ksu_susfs_map_files_readlink_ready = false;
	}
	ksu_susfs_map_files_link_iops = NULL;

	if (ksu_susfs_map_files_lookup_ready) {
		ksu_susfs_restore_iop_lookup(ksu_susfs_map_files_iops,
					     &ksu_susfs_orig_map_files_lookup);
		ksu_susfs_map_files_lookup_ready = false;
	}
	ksu_susfs_map_files_iops = NULL;

	if (ksu_susfs_map_files_d_revalidate_ready) {
		ksu_susfs_restore_dop_d_revalidate(
			ksu_susfs_map_files_dops,
			&ksu_susfs_orig_map_files_d_revalidate);
		ksu_susfs_map_files_d_revalidate_ready = false;
	}
	ksu_susfs_map_files_dops = NULL;

	if (ksu_susfs_map_files_iterate_ready) {
		ksu_susfs_restore_fop_iterate_shared(
			ksu_susfs_map_files_fops,
			&ksu_susfs_orig_map_files_iterate_shared);
		ksu_susfs_map_files_iterate_ready = false;
	}
	ksu_susfs_map_files_fops = NULL;
	ksu_susfs_map_files_instantiate = NULL;

	if (ksu_susfs_pagemap_ready) {
		ksu_susfs_restore_fop_read(&proc_pagemap_operations,
					   &ksu_susfs_orig_pagemap_read);
		ksu_susfs_pagemap_ready = false;
	}

#ifdef KSU_SUSFS_HAS_SMAPS_ROLLUP
	if (ksu_susfs_smaps_rollup_ready) {
		ksu_susfs_restore_fop_open(&proc_pid_smaps_rollup_operations,
					   &ksu_susfs_orig_pid_smaps_rollup_open);
		ksu_susfs_smaps_rollup_ready = false;
	}
#endif

	if (ksu_susfs_smaps_ready) {
		ksu_susfs_restore_seqop_show(ksu_susfs_smaps_seqops,
					     &ksu_susfs_orig_smaps_show);
		ksu_susfs_smaps_ready = false;
	}
	ksu_susfs_smaps_seqops = NULL;

	if (ksu_susfs_maps_ready) {
		ksu_susfs_restore_seqop_show(ksu_susfs_maps_seqops,
					     &ksu_susfs_orig_maps_show);
		ksu_susfs_maps_ready = false;
	}
	ksu_susfs_maps_seqops = NULL;

	ksu_susfs_destroy_kretprobe(&ksu_susfs_vfs_getattr_nosec_rp);
	ksu_susfs_getattr_ready = false;
	ksu_susfs_kstat_clear_all();
	ksu_susfs_sus_map_clear_all();
}
