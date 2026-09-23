/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
#ifdef __aarch64__

#include "../patch_memory.h"
#include "klog.h" // IWYU pragma: keep
#include "linux/cpumask.h"
#include "linux/gfp.h" // IWYU pragma: keep
#include "linux/uaccess.h"
#include "linux/stop_machine.h"
#include "linux/string.h"
#include "asm/cacheflush.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#include "asm-generic/fixmap.h"
#include "asm/fixmap.h"
#else
#include "linux/vmalloc.h"
#include "linux/mm.h"
#include "linux/highmem.h"
#endif

#ifndef __p4d_to_phys
#define KSU_P4D_TO_PHYS(p4d) (p4d_val(p4d) & PHYS_MASK)
#else
#define KSU_P4D_TO_PHYS(p4d) __p4d_to_phys(p4d)
#endif

// https://github.com/fuqiuluo/ovo/blob/f7da411458e87d32438dc14fce5a3313ed0c967e/ovo/mmuhack.c#L21

// Translate a kernel virtual address to a physical address by walking the
// init_mm page tables. Returns the physical address on success, or writes
// a non-zero error to *err. Callers must check *err before using the result,
// since physical address 0 is a valid address.
unsigned long phys_from_virt(unsigned long addr, int *err)
{
    struct mm_struct *mm = &init_mm;
    pgd_t *pgd;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d_t *p4d;
#endif
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *err = 0;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto fail;
    pr_debug("pgd of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pgd,
             (uintptr_t)pgd_val(*pgd));

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto fail;
    pr_debug("p4d of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)p4d,
             (uintptr_t)p4d_val(*p4d));
#if defined(p4d_leaf)
    if (p4d_leaf(*p4d)) {
        pr_debug("Address 0x%lx maps to a P4D-level huge page\n", addr);
        return KSU_P4D_TO_PHYS(*p4d) + ((addr & ~P4D_MASK));
    }
#endif

    pud = pud_offset(p4d, addr);
#else // For older kernels without 4-level paging, the pud is directly under pgd.
    pud = pud_offset(pgd, addr);
#endif
    if (pud_none(*pud))
        goto fail;
    pr_debug("pud of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pud,
             (uintptr_t)pud_val(*pud));
#if defined(pud_leaf)
    if (pud_leaf(*pud)) {
        pr_debug("Address 0x%lx maps to a PUD-level huge page\n", addr);
        return __pud_to_phys(*pud) + ((addr & ~PUD_MASK));
    }
#elif defined(pud_sect)
    if (pud_sect(*pud)) {
        pr_debug("Address 0x%lx maps to a PUD-level section\n", addr);
        return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
    }
#endif
    if (pud_bad(*pud))
        goto fail;

    pmd = pmd_offset(pud, addr);
    pr_debug("pmd of 0x%lx p=0x%lx v=0x%lx", addr, (uintptr_t)pmd,
             (uintptr_t)pmd_val(*pmd));
#if defined(pmd_leaf)
    if (pmd_leaf(*pmd)) {
        pr_debug("Address 0x%lx maps to a PMD-level huge page\n", addr);
        return __pmd_to_phys(*pmd) + ((addr & ~PMD_MASK));
    }
#elif defined(pmd_sect)
    if (pmd_sect(*pmd)) {
        pr_debug("Address 0x%lx maps to a PMD-level section\n", addr);
        return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
    }
#endif

    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto fail;

    pte = pte_offset_kernel(pmd, addr);
    if (!pte)
        goto fail;
    if (!pte_present(*pte))
        goto fail;

    return __pte_to_phys(*pte) + ((addr & ~PAGE_MASK));

fail:
    *err = -ENOENT;
    return 0;
}

// This function appears in 5.14:
// https://github.com/torvalds/linux/commit/fade9c2c6ee2baea7df8e6059b3f143c681e5ce4#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7L52
// https://github.com/torvalds/linux/commit/814b186079cd54d3fe3b6b8ab539cbd44705ef9d#diff-fc9ef24572e183c6c049b5ae8029762159787f8669d909452bdf40db748f94a7R53
// However, it's backport to android13-5.10 but not to android12-5.10.
// https://cs.android.com/android/_/android/kernel/common/+/6d9f07d8f1ffc310a6877153fe882f35ae380799
// So we need to grep kernel source code to detect which one to use.
#if KSU_NEW_DCACHE_FLUSH
#define ksu_flush_dcache(start, sz)                                            \
    ({                                                                         \
        unsigned long __start = (start);                                       \
        unsigned long __end = __start + (sz);                                  \
        dcache_clean_inval_poc(__start, __end);                                \
    })
#define ksu_flush_icache(start, end) caches_clean_inval_pou(start, end)
#else
#define ksu_flush_dcache(start, sz) __flush_dcache_area((void *)start, sz)
#define ksu_flush_icache(start, end) __flush_icache_range(start, end)
#endif

struct patch_text_info {
    void *dst;
    void *src;
    const void *expected;
    size_t len;
    atomic_t cpu_count;
    int flags;
};

// Implementation of arbitrary kernel address modification.
// We could certainly modify the PTE of the target address to make it writable,
// but this would violate the protection mechanisms of some vendor components
// (such as MTK's MKP, see ^1) at higher EL levels. Fortunately, the kernel's
// `aarch64_insn_write` function works fine, which I believe is achieved by
// modifying memory using fixmaps (MKP's kernel module reports the fixmap address
// to its hypervisor, which might be used to determine whether such memory
// modification is "normal" kernel behavior, see ^1). However, we cannot use the
// `aarch64_insn_write` function directly. First, it can only write 4 bytes
// at a time. Secondly, there's a bug in modifying the kernel's rodata (in our
// case, syscall table). The `patch_map` function uses `vmalloc_to_page` to
// obtain the target's physical address, but `vmalloc_to_page` doesn't handle
// huge page mapping correctly (before version 5.13, see ^2).
// Therefore, we need to obtain the target's physical address and use `fixmap` to
// map and poke it manually. Currently, no patch_lock is held, since I think it's
// not a big problem because we are in stop_machine.
// ^1: https://github.com/NothingOSS/android_kernel_device_modules_6.1_nothing_mt6878/blob/957dac185efe46cbf6336b0fff9516d84c8cd78f/drivers/misc/mediatek/mkp/mkp_main.c#L29
// ^2: https://github.com/torvalds/linux/commit/c0eb315ad9719e41ce44708455cc69df7ac9f3f8
static int ksu_patch_text_nosync(struct patch_text_info *info)
{
    pr_debug("patch dst=0x%lx src=0x%lx len=%ld\n", (unsigned long)info->dst,
             (unsigned long)info->src, info->len);

    unsigned long p = (unsigned long)info->dst;
    int ret;

    int phy_err;
    unsigned long phy = phys_from_virt(p, &phy_err);
    if (phy_err) {
        ret = phy_err;
        pr_err("failed to find phy addr for patch dst addr 0x%lx\n", p);
        goto err;
    }
    pr_debug("phy addr for patch 0x%lx: 0x%lx\n", p, phy);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    void *map = set_fixmap_offset(FIX_TEXT_POKE0, phy);
#else
    unsigned long offset = phy & ~PAGE_MASK;
    unsigned long pfn = phy >> PAGE_SHIFT;
    struct page *page;

    if (offset + info->len > PAGE_SIZE || !pfn_valid(pfn)) {
        pr_err("ksu_patch: invalid pfn or boundary crossing for 0x%lx\n", p);
        return -EINVAL;
    }

    page = pfn_to_page(pfn);
    void *vmap_base = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!vmap_base) return -ENOMEM;
    
    map = (void *)((unsigned long)vmap_base + offset);
#endif
    pr_debug("fixmap addr for patch 0x%lx: 0x%lx\n", p, (unsigned long)map);

    ret = (int)copy_to_kernel_nofault(map, info->src, info->len);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    clear_fixmap(FIX_TEXT_POKE0);
#else
    flush_kernel_vmap_range(map, info->len);
    vunmap((void *)((unsigned long)map - offset));
#endif

    if (ret == 0) {
        if (info->flags & KSU_PATCH_TEXT_FLUSH_ICACHE)
            ksu_flush_icache((uintptr_t)info->dst, (uintptr_t)info->dst + info->len);
        if (info->flags & KSU_PATCH_TEXT_FLUSH_DCACHE)
            ksu_flush_dcache(info->dst, info->len);
    }

err:
    pr_debug("patch result=%d\n", ret);
    return ret;
}

/*
 * Execution quiescence is provided by stop_machine() (see
 * ksu_patch_text()/ksu_patch_text_compare() below): it takes the
 * cpu-hotplug read lock, so no CPU can enter or leave the online set
 * for the duration, and parks every non-master CPU in its per-CPU
 * stopper kthread ("migration/N"), which runs in the stop scheduling
 * class and preempts everything else with IRQs disabled.  While the
 * non-master CPUs spin on @cpu_count, the master performs the fixmap
 * write plus the DC clean / IC invalidate of the patched range; each
 * released CPU then executes isb() below, a context synchronization
 * event that discards already-fetched and pre-decoded instructions.
 * No CPU can therefore execute the patched address across the write,
 * and the aligned 32-bit patch cannot be observed half-applied.
 */
static int ksu_patch_text_cb(void *arg)
{
    struct patch_text_info *pp = arg;
    int ret = 0;

    /* The last CPU becomes master */
    if (atomic_inc_return(&pp->cpu_count) == num_online_cpus()) {
        if (pp->expected) {
            u8 current_word[sizeof(u32)];

            if (pp->len > sizeof(current_word) ||
                copy_from_kernel_nofault(current_word, pp->dst, pp->len) ||
                memcmp(current_word, pp->expected, pp->len)) {
                ret = -EBADE;
                goto notify;
            }
        }
        ret = ksu_patch_text_nosync(pp);
        if (!ret && pp->expected) {
            u8 current_word[sizeof(u32)];

            if (pp->len > sizeof(current_word) ||
                copy_from_kernel_nofault(current_word, pp->dst, pp->len) ||
                memcmp(current_word, pp->src, pp->len))
                ret = -EIO;
        }
notify:
        /* Notify other processors with an additional increment. */
        atomic_inc(&pp->cpu_count);
    } else {
        while (atomic_read(&pp->cpu_count) <= num_online_cpus())
            cpu_relax();
        isb();
    }

    return ret;
}

int ksu_patch_text(void *dst, void *src, size_t len, int flags)
{
    struct patch_text_info info = {
        .dst = dst,
        .src = src,
        .expected = NULL,
        .len = len,
        .cpu_count = ATOMIC_INIT(0),
        .flags = flags,
    };

    return stop_machine(ksu_patch_text_cb, &info, cpu_online_mask);
}

int ksu_patch_text_compare(void *dst, const void *expected, void *src,
                           size_t len, int flags)
{
    struct patch_text_info info = {
        .dst = dst,
        .src = src,
        .expected = expected,
        .len = len,
        .cpu_count = ATOMIC_INIT(0),
        .flags = flags,
    };

    return stop_machine(ksu_patch_text_cb, &info, cpu_online_mask);
}

#endif /* __aarch64__ */
