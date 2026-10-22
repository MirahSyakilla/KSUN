/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_SUSFS_COMPAT_H
#define __KSU_SUSFS_COMPAT_H

#include <linux/hugetlb.h>
#include <linux/jump_label.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/pagemap.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/radix-tree.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/uaccess.h>

#if defined(KSU_SUSFS_HAS_XA_IS_VALUE) || defined(KSU_SUSFS_HAS_XA_LOAD)
#include <linux/xarray.h>
#endif

#ifdef KSU_SUSFS_HAS_SCHED_MM
#include <linux/sched/mm.h>
#else
#include <linux/sched.h>
#endif

#ifdef KSU_SUSFS_HAS_PAGE_IDLE
#include <linux/page_idle.h>
#endif

#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
#include <linux/pgsize_migration.h>
#endif

#ifndef PTRACE_MODE_READ_FSCREDS
#define PTRACE_MODE_READ_FSCREDS PTRACE_MODE_READ
#endif

#ifndef untagged_addr
#define untagged_addr(addr) (addr)
#endif

/* The typed static-branch API landed after the original static-key API. */
#ifndef DEFINE_STATIC_KEY_FALSE
#define DEFINE_STATIC_KEY_FALSE(name) \
	struct static_key name = STATIC_KEY_INIT_FALSE
#endif

#ifndef static_branch_unlikely
#define static_branch_unlikely(key) static_key_false(key)
#endif

#ifndef static_branch_enable
#define static_branch_enable(key) static_key_slow_inc(key)
#endif

#ifndef static_branch_disable
#define static_branch_disable(key) static_key_slow_dec(key)
#endif

static inline bool ksu_susfs_mmget_not_zero(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMGET_NOT_ZERO
	return mmget_not_zero(mm);
#else
	return atomic_inc_not_zero(&mm->mm_users);
#endif
}

static inline int ksu_susfs_mmap_read_lock_killable(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMAP_LOCK
	return mmap_read_lock_killable(mm);
#elif defined(KSU_SUSFS_HAS_DOWN_READ_KILLABLE)
	return down_read_killable(&mm->mmap_sem);
#else
	down_read(&mm->mmap_sem);
	return 0;
#endif
}

static inline void ksu_susfs_mmap_read_unlock(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MMAP_LOCK
	mmap_read_unlock(mm);
#else
	up_read(&mm->mmap_sem);
#endif
}

static inline struct vm_area_struct *
ksu_susfs_first_vma(struct mm_struct *mm)
{
#ifdef KSU_SUSFS_HAS_MM_MT
	unsigned long index = 0;

	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
#else
	return mm->mmap;
#endif
}

static inline struct vm_area_struct *
ksu_susfs_next_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
#ifdef KSU_SUSFS_HAS_MM_MT
	unsigned long index = vma->vm_end;

	return mt_find(&mm->mm_mt, &index, ULONG_MAX);
#else
	(void)mm;
	return vma->vm_next;
#endif
}

static inline int ksu_susfs_compound_nr(struct page *page)
{
#ifdef KSU_SUSFS_HAS_COMPOUND_NR
	return compound_nr(page);
#else
	return 1 << compound_order(page);
#endif
}

static inline bool ksu_susfs_page_is_young(struct page *page)
{
#ifdef KSU_SUSFS_HAS_PAGE_IDLE
	return page_is_young(page);
#else
	(void)page;
	return false;
#endif
}

static inline bool ksu_susfs_pagecache_is_value(const void *entry)
{
#ifdef KSU_SUSFS_HAS_XA_IS_VALUE
	return xa_is_value(entry);
#else
	return radix_tree_exceptional_entry((void *)entry);
#endif
}

static inline void ksu_susfs_seq_put_hex_ll(struct seq_file *m,
					     const char *delimiter,
					     unsigned long long value,
					     unsigned int width)
{
#ifdef KSU_SUSFS_HAS_SEQ_PUT_HEX_LL
	seq_put_hex_ll(m, delimiter, value, width);
#else
	if (delimiter)
		seq_puts(m, delimiter);
	seq_printf(m, "%0*llx", (int)width, value);
#endif
}

static inline void
ksu_susfs_seq_put_decimal_ull_width(struct seq_file *m,
				    const char *delimiter,
				    unsigned long long value,
				    unsigned int width)
{
#ifdef KSU_SUSFS_HAS_SEQ_PUT_DECIMAL_ULL_WIDTH
	seq_put_decimal_ull_width(m, delimiter, value, width);
#else
	if (delimiter)
		seq_puts(m, delimiter);
	seq_printf(m, "%*llu", (int)width, value);
#endif
}

static inline bool ksu_susfs_hugetlb_pmd_shared(pte_t *pte)
{
#ifdef KSU_SUSFS_HAS_HUGETLB_PMD_SHARED
	return hugetlb_pmd_shared(pte);
#else
	(void)pte;
	return false;
#endif
}

static inline unsigned long
ksu_susfs_vma_pad_start(struct vm_area_struct *vma)
{
#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
	return VMA_PAD_START(vma);
#else
	return vma->vm_end;
#endif
}

static inline struct vm_area_struct *
ksu_susfs_get_data_vma(struct vm_area_struct *vma)
{
#if defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION) && \
	defined(KSU_SUSFS_SHOW_MAP_PAD_VMA_HAS_PAD) && \
	defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION_VMA_ACCESSORS)
	return get_data_vma(vma);
#else
	return vma;
#endif
}

static inline struct vm_area_struct *
ksu_susfs_get_pad_vma(struct vm_area_struct *vma)
{
#if defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION) && \
	defined(KSU_SUSFS_SHOW_MAP_PAD_VMA_HAS_PAD) && \
	defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION_VMA_ACCESSORS)
	return get_pad_vma(vma);
#else
	(void)vma;
	return NULL;
#endif
}

static inline void ksu_susfs_put_data_vma(struct vm_area_struct *orig,
					  struct vm_area_struct *data)
{
#if defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION) && \
	defined(KSU_SUSFS_SHOW_MAP_PAD_VMA_HAS_PAD) && \
	defined(KSU_SUSFS_HAS_PGSIZE_MIGRATION_VMA_ACCESSORS)
	if (data != orig) {
		kfree(data);
	}
#else
	(void)orig;
	(void)data;
#endif
}

static inline void ksu_susfs_show_map_pad_vma(struct vm_area_struct *vma,
					       struct vm_area_struct *pad,
					       struct seq_file *m, void *show,
					       bool smaps)
{
#ifdef KSU_SUSFS_HAS_PGSIZE_MIGRATION
#ifdef KSU_SUSFS_SHOW_MAP_PAD_VMA_HAS_PAD
	show_map_pad_vma(vma, pad, m, show, smaps);
#else
	(void)pad;
	show_map_pad_vma(vma, m, show, smaps);
#endif
#else
	(void)vma;
	(void)pad;
	(void)m;
	(void)show;
	(void)smaps;
#endif
}

static inline bool ksu_susfs_is_pfn_swap_entry(swp_entry_t entry)
{
#ifdef KSU_SUSFS_HAS_IS_PFN_SWAP_ENTRY
	return is_pfn_swap_entry(entry);
#else
	if (is_migration_entry(entry)) {
		return true;
	}
#ifdef KSU_SUSFS_HAS_DEVICE_PRIVATE_ENTRY
	return is_device_private_entry(entry);
#else
	return false;
#endif
#endif
}

static inline struct page *ksu_susfs_pfn_swap_entry_to_page(swp_entry_t entry)
{
#ifdef KSU_SUSFS_HAS_PFN_SWAP_ENTRY_TO_PAGE
	return pfn_swap_entry_to_page(entry);
#else
#ifdef KSU_SUSFS_HAS_MIGRATION_ENTRY_TO_PAGE
	if (is_migration_entry(entry)) {
		return migration_entry_to_page(entry);
	}
#endif
#if defined(KSU_SUSFS_HAS_DEVICE_PRIVATE_ENTRY) && \
	defined(KSU_SUSFS_HAS_DEVICE_PRIVATE_ENTRY_TO_PAGE)
	if (is_device_private_entry(entry)) {
		return device_private_entry_to_page(entry);
	}
#endif
	return NULL;
#endif
}

static inline void *ksu_susfs_find_shmem_swap_entry(
	struct address_space *mapping, pgoff_t index, bool *needs_put)
{
	*needs_put = false;

#ifdef KSU_SUSFS_HAS_XA_LOAD
	return xa_load(&mapping->i_pages, index);
#elif defined(KSU_SUSFS_HAS_FIND_GET_ENTRY)
	*needs_put = true;
	return find_get_entry(mapping, index);
#else
	*needs_put = true;
	return find_get_page(mapping, index);
#endif
}

/*
 * ---- the readlink face's path lookup ----
 *
 * do_readlinkat() resolves the caller's pathname with LOOKUP_EMPTY and
 * without a final follow, and on the kernels that still carry the out
 * parameter it also tells the caller whether the pathname was the empty
 * string.  The face has to resolve the very same object, otherwise the
 * readlink answer and the stat family's answer could disagree.
 *
 * The API that does this changed shape in v5.8: upstream retired
 * user_path_at_empty() and folded the empty-path handling into
 * user_path_at() (commit dff60734fc760, "vfs: retire user_path_at_empty and
 * drop empty arg from getname_flags").  The function therefore exists on
 * every kernel this branch supports - it was added in v3.2 - EXCEPT on v5.8
 * and later, where the opposite holds.  A version macro would therefore get
 * both ends of the range wrong, so the shape is selected from the source
 * tree instead (kernel/Kbuild probes include/linux/namei.h):
 *
 *   - user_path_at_empty() present (v3.2 .. v5.7): use it.  The empty
 *     pathname is told apart exactly, and the face answers exactly as the
 *     stat family does.
 *   - user_path_at() only, LOOKUP_EMPTY present (v5.8 ..): use
 *     user_path_at() with LOOKUP_EMPTY.  The empty pathname then resolves to
 *     the base directory instead of being reported, but the kernel's own
 *     answer for the empty pathname is -ENOENT there, so there is nothing
 *     to decide and nothing to hide.
 *   - no LOOKUP_EMPTY at all: resolve with flags 0, which is the same
 *     object readlink(2) reports (no final follow), and treat a failed
 *     lookup as "not hidden".
 *
 * The helper lives in this shared header because the readlink route is
 * shared: NoMount's lookup scope and sus_path's readlink face both answer
 * from the same interception point, and a symbol that both of them need must
 * not live inside one feature's #ifdef.
 */
static inline int ksu_susfs_readlink_lookup(int dfd,
					    const char __user *pathname,
					    struct path *path, bool *empty)
{
	int err;

	*empty = false;

#ifdef KSU_SUSFS_HAS_USER_PATH_AT_EMPTY
	{
		int empty_flag = 0;

		err = user_path_at_empty(dfd, pathname, LOOKUP_EMPTY, path,
					  &empty_flag);
		*empty = empty_flag != 0;
		return err;
	}
#elif defined(KSU_SUSFS_HAS_LOOKUP_EMPTY)
	err = user_path_at(dfd, pathname, LOOKUP_EMPTY, path);
	return err;
#else
	err = user_path_at(dfd, pathname, 0, path);
	return err;
#endif
}

#endif /* __KSU_SUSFS_COMPAT_H */
