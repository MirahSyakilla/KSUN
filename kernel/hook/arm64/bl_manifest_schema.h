/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Branch-link generated manifest schema (Phase 19).
 *
 * This header is the SOURCE-OWNED schema contract between the offline
 * analyzer (tools/bl-analyzer/bl_analyzer_v2.py) and the runtime consumer
 * (kernel/hook/arm64/branch_link_hook.c).  It contains no build-specific
 * data; the generated data object (bl_manifest_gen.o) supplies that.
 *
 * Identity rules:
 *  - the generated data object stores SYMBOL NAMES and enum IDs only;
 *    never absolute kernel addresses (the runtime resolves names through
 *    its existing ksu_bl_lookup()/ksu_bl_lookup_canonical() and verifies
 *    every instruction before patching);
 *  - the only digest embedded in the object is the payload digest over
 *    the generated table bytes and the policy digest -- both describe
 *    stage-1 inputs, never the artifact they ride in (no self-reference);
 *  - final vmlinux/Image/System.map digests live in the external build
 *    transaction sidecar only.
 */

#ifndef _KSU_BL_MANIFEST_SCHEMA_H
#define _KSU_BL_MANIFEST_SCHEMA_H

#include <linux/types.h>

#include <linux/limits.h>

#define KSU_BL_MANIFEST_MAGIC	0x4b53424cU	/* "KSBL" */
#define KSU_BL_MANIFEST_SCHEMA	3
/* width field is u16; runtime KSU_BL_SCAN_WIDTH is the 0-alias default */
#define KSU_BL_SCAN_WIDTH_MAX	0xFFFFU

/* Classification vocabulary (shared with the runtime engines). */
enum ksu_bl_manifest_class {
	KSU_BL_SITE_OPTIONAL,
	KSU_BL_SITE_REQUIRED,
	KSU_BL_SITE_UNSUPPORTED,
};

/* Runtime capacity and scan constants (must match branch_link_hook.c). */
#ifndef KSU_BL_MAX_RECORDS
#define KSU_BL_MAX_RECORDS	192
#endif
#define KSU_BL_MAX_ROUTE_TARGETS	4
#define KSU_BL_SCAN_WIDTH_DEFAULT	1024

/* The generated data object is flagged bootstrap until the two-stage
 * coordinator's final pass replaces it with census-derived content. */
#define KSU_BL_MANIFEST_F_BOOTSTRAP	0x0001U

struct ksu_bl_gen_header {
	u32 magic;
	u16 schema_version;
	u16 policy_revision;
	u32 flags;		/* KSU_BL_MANIFEST_F_* */
	u32 nonce;		/* per-generation; binds .o to its ids header */
	u32 route_count;
	u32 caller_count;
	u32 target_count;
	u32 group_count;
	u8 payload_digest[16];	/* sha256(trunc) of generated table bytes */
	u8 policy_digest[16];	/* sha256(trunc) of bl_policy.py at build */
};

struct ksu_bl_gen_route {
	u16 id;			/* enum ksu_bl_route_id */
	u16 kind;		/* enum ksu_bl_route_kind */
	u16 group_id;
	u16 flags;
	u16 first_caller;	/* slice into the caller table */
	u16 caller_count;
	u16 first_target;	/* slice into the target table (policy order) */
	u16 target_count;
	u16 census_expected_sites;	/* advisory; log-only at boot */
	u16 reserved;
};

/* Layout prefix must stay field-compatible with
 * struct ksu_bl_manifest_caller (branch_link_hook.c): name, classification,
 * min_sites, width -- the engines consume the prefix directly. */
struct ksu_bl_gen_caller {
	const char *name;
	u8 classification;
	u8 owner;		/* enum ksu_bl_owner */
	u16 route_id;
	u16 min_sites;
	u16 width;		/* 0 = KSU_BL_SCAN_WIDTH */
};

struct ksu_bl_gen_target {
	const char *name;	/* real-body symbol for BL immediates */
	u16 hook_id;		/* enum ksu_bl_hook_id */
	u16 fn_slot_id;		/* enum ksu_bl_slot_id; KSU_BL_SLOT_NONE = none */
	u8 binding;		/* enum ksu_bl_binding */
	u8 flags;
};

enum ksu_bl_route_kind {
	KSU_BL_ROUTE_MANIFEST = 0,
	KSU_BL_ROUTE_ROUTES,
	KSU_BL_ROUTE_EXEC,
};

enum ksu_bl_owner {
	KSU_BL_OWNER_KERNEL = 0,
	KSU_BL_OWNER_KSU,
};

enum ksu_bl_binding {
	KSU_BL_BINDING_CANONICAL = 0,
	KSU_BL_BINDING_REALBODY,
};

#define KSU_BL_SLOT_NONE	0xFFFFU

#endif /* _KSU_BL_MANIFEST_SCHEMA_H */
