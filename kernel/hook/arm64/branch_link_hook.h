#ifndef __KSU_ARM64_BRANCH_LINK_H
#define __KSU_ARM64_BRANCH_LINK_H

#include <linux/types.h>
#include <linux/init.h>

int ksu_branch_link_patch_init(void);
int ksu_branch_link_patch_exit(void);
bool ksu_branch_link_faccessat_ready(void);
bool ksu_branch_link_readlink_ready(void);
bool ksu_branch_link_exec_ready(void);
bool ksu_branch_link_stat_path_ready(void);

#endif

/* generated manifest consumer (bl_manifest.c, CONFIG_KSU_BL_GENERATED) */
struct ksu_bl_gen_route;
struct ksu_bl_gen_caller;
struct ksu_bl_gen_target;

#ifdef CONFIG_KSU_BL_GENERATED
void ksu_bl_manifest_init(void);
bool ksu_bl_generated_manifest_ready(void);
const struct ksu_bl_gen_route *ksu_bl_generated_route(u16 id);
const struct ksu_bl_gen_caller *ksu_bl_generated_callers(
	const struct ksu_bl_gen_route *route, u16 *count);
const struct ksu_bl_gen_target *ksu_bl_generated_targets(
	const struct ksu_bl_gen_route *route, u16 *count);
const char *ksu_bl_generated_group_name(u16 group_id);
#else
static inline void ksu_bl_manifest_init(void) {}
static inline bool ksu_bl_generated_manifest_ready(void) { return false; }
#endif
