/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Suspect-uid oracle hiding: make a uid the policy hides answer through
 * getpriority()/setpriority() exactly as though it were not registered.
 */
#ifndef KSU_FEATURE_SUSPECT_UID_H
#define KSU_FEATURE_SUSPECT_UID_H

#include <linux/types.h>
#include <linux/uidgid.h>

#define KSU_SUSPECT_NULL ((kuid_t){ .val = 0 })

/* Start answering for @target as an unregistered uid. */
int ksu_suspect_uid_hide(kuid_t target);

/* Stop hiding @target. */
int ksu_suspect_uid_unhide(kuid_t target);

/* Install the getpriority/setpriority hooks. */
int ksu_suspect_uid_init(void);

/* Remove them again. */
void ksu_suspect_uid_exit(void);

#endif /* KSU_FEATURE_SUSPECT_UID_H */
