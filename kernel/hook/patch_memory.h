/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#ifndef __KSU_PATCH_MEMORY_H
#define __KSU_PATCH_MEMORY_H

#include <linux/types.h>
#include "linux/version.h"
#include "compat/kernel_compat.h"

#ifdef __aarch64__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
#include "asm/text-patching.h" // IWYU pragma: keep
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include "asm/patching.h" // IWYU pragma: keep
#else
#include "asm/insn.h" // IWYU pragma: keep
#endif
#elif __x86_64__
#include "asm/text-patching.h" // IWYU pragma: keep
#else
#error "Unsupported arch"
#endif

#define KSU_PATCH_TEXT_FLUSH_DCACHE 1
#define KSU_PATCH_TEXT_FLUSH_ICACHE 2

unsigned long phys_from_virt(unsigned long addr, int *err);
int ksu_patch_text(void *dst, void *src, size_t len, int flags);
/*
 * Formal safety guarantee: ksu_patch_text_compare() runs under
 * stop_machine(), so every non-master CPU is parked in its stopper
 * kthread and cannot execute while the expected word is read and the
 * aligned 32-bit replacement is written; the write is therefore atomic
 * with respect to instruction execution.  On return the patched range
 * has been DC-cleaned and IC-invalidated and each released CPU has
 * executed isb(), so every PE fetches the new instruction.  Success
 * means the old text was verified and replaced; -EBADE means the
 * expected word did not match and the target was left untouched.
 */
int ksu_patch_text_compare(void *dst, const void *expected, void *src,
                           size_t len, int flags);

#endif
