/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Suspect-uid oracle hiding: make a uid the policy hides answer through
 * getpriority()/setpriority() exactly as though it were not registered.
 */
#ifndef KSU_FEATURE_SUSPECT_UID_H
#define KSU_FEATURE_SUSPECT_UID_H

#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#define KSU_SUSPECT_NULL ((kuid_t){ .val = 0 })

/* Start answering for @target as an unregistered uid. */
int ksu_suspect_uid_hide(kuid_t target);

/* Stop hiding @target. */
int ksu_suspect_uid_unhide(kuid_t target);

/* Replace the whole policy with @uids. Returns how many were accepted. */
int ksu_suspect_uid_set_list(const __u32 *uids, __u32 count);
int ksu_suspect_uid_set_mask(kuid_t caller, const u8 *bits);

/* How many uids the table holds. */
__u32 ksu_suspect_uid_max(void);

/*
 * susfs-style config channel. Returns false when @cmd is not one of ours so
 * the caller can keep looking; true means the command was consumed, whether
 * or not it succeeded (the result travels back in the struct's err field).
 */
bool ksu_suspect_uid_handle_compat(unsigned int cmd, void __user *arg);

/* Install the getpriority/setpriority hooks. */
int ksu_suspect_uid_init(void);

/* Remove them again. */
void ksu_suspect_uid_exit(void);

#endif /* KSU_FEATURE_SUSPECT_UID_H */
