#ifndef __KSU_ARM64_BRANCH_LINK_H
#define __KSU_ARM64_BRANCH_LINK_H

#include <linux/types.h>

int ksu_branch_link_patch_init(void);
int ksu_branch_link_patch_exit(void);
bool ksu_branch_link_faccessat_ready(void);
bool ksu_branch_link_readlink_ready(void);
bool ksu_branch_link_exec_ready(void);
bool ksu_branch_link_stat_path_ready(void);

#endif
