// SPDX-License-Identifier: GPL-2.0-only
/*
 * Branch-link generated manifest consumer (Phase 19).
 *
 * Validates and exposes the generated manifest data object produced by the
 * guarded two-stage build coordinator.  The generated object stores symbol
 * names and enum IDs only; the runtime resolves every target through its
 * existing ksu_bl_lookup()/ksu_bl_lookup_canonical() and verifies every
 * instruction before patching.  Nothing here trusts absolute addresses.
 *
 * Fail-closed contract (CONFIG_KSU_BL_GENERATED=y):
 *   - missing generated object          -> BL subsystem disabled
 *   - magic/schema/policy mismatch      -> BL subsystem disabled
 *   - nonce mismatch (.o vs ids header) -> BL subsystem disabled
 *   - malformed rows / bad bounds       -> BL subsystem disabled
 *   - caller duplicates within a route  -> BL subsystem disabled
 *   - budget > KSU_BL_MAX_RECORDS       -> BL subsystem disabled
 * Any disable leaves the kprobe-era fallbacks authoritative, identical to
 * the per-family failure posture.
 */

#include <linux/kernel.h>
#include <linux/string.h>

#include "bl_manifest_schema.h"
#include <bl_manifest_ids.h>
#include "branch_link_hook.h"

extern const struct ksu_bl_gen_header ksu_bl_manifest_header;
extern const struct ksu_bl_gen_route *ksu_bl_manifest_routes;
extern const struct ksu_bl_gen_caller *ksu_bl_manifest_callers;
extern const struct ksu_bl_gen_target *ksu_bl_manifest_targets;
extern const char *const *ksu_bl_manifest_groups;

static bool ksu_bl_manifest_valid;

static bool ksu_bl_manifest_validate(void)
{
	const struct ksu_bl_gen_header *h = &ksu_bl_manifest_header;
	u32 i, j;
	u32 budget = 0;

	if (h->magic != KSU_BL_MANIFEST_MAGIC) {
		pr_warn("branch_link: manifest magic mismatch (0x%08x)\n",
			h->magic);
		return false;
	}
	if (h->schema_version != KSU_BL_MANIFEST_SCHEMA) {
		pr_warn("branch_link: manifest schema %u != %u\n",
			h->schema_version, KSU_BL_MANIFEST_SCHEMA);
		return false;
	}
	if (h->policy_revision != KSU_BL_POLICY_REVISION_VALUE) {
		pr_warn("branch_link: manifest policy revision %u != %u\n",
			h->policy_revision, KSU_BL_POLICY_REVISION_VALUE);
		return false;
	}
	if (h->nonce != KSU_BL_MANIFEST_NONCE) {
		pr_warn("branch_link: manifest nonce 0x%08x != 0x%08x "
			"(stale object/header pairing)\n",
			h->nonce, KSU_BL_MANIFEST_NONCE);
		return false;
	}
	if (h->flags & KSU_BL_MANIFEST_F_BOOTSTRAP) {
		pr_warn("branch_link: bootstrap manifest cannot authorize "
			"patching\n");
		return false;
	}
	if (h->route_count != KSU_BL_ROUTE_COUNT) {
		pr_warn("branch_link: manifest route count %u != %u\n",
			h->route_count, KSU_BL_ROUTE_COUNT);
		return false;
	}
	if (!h->caller_count || !h->target_count || !h->group_count) {
		pr_warn("branch_link: manifest empty tables\n");
		return false;
	}

	for (i = 0; i < h->route_count; i++) {
		const struct ksu_bl_gen_route *r =
			&ksu_bl_manifest_routes[i];

		if (r->id >= KSU_BL_ROUTE_COUNT) {
			pr_warn("branch_link: route %u bad id %u\n", i, r->id);
			return false;
		}
		if (r->kind > KSU_BL_ROUTE_EXEC) {
			pr_warn("branch_link: route %u bad kind %u\n",
				r->id, r->kind);
			return false;
		}
		if (r->group_id >= h->group_count) {
			pr_warn("branch_link: route %u bad group %u\n",
				r->id, r->group_id);
			return false;
		}
		if (r->first_caller + r->caller_count > h->caller_count ||
		    r->first_target + r->target_count > h->target_count) {
			pr_warn("branch_link: route %u slices out of bounds\n",
				r->id);
			return false;
		}
		if (r->kind == KSU_BL_ROUTE_ROUTES &&
		    r->target_count > KSU_BL_MAX_ROUTE_TARGETS) {
			pr_warn("branch_link: route %u target overflow %u\n",
				r->id, r->target_count);
			return false;
		}
		budget += r->census_expected_sites;

		/* caller validation + within-route uniqueness */
		for (j = 0; j < r->caller_count; j++) {
			const struct ksu_bl_gen_caller *c =
				&ksu_bl_manifest_callers[r->first_caller + j];

			if (c->route_id != r->id) {
				pr_warn("branch_link: caller %s route id %u "
					"!= %u\n", c->name, c->route_id,
					r->id);
				return false;
			}
			if (c->classification > KSU_BL_SITE_UNSUPPORTED) {
				pr_warn("branch_link: caller %s bad "
					"classification %u\n", c->name,
					c->classification);
				return false;
			}
			if (c->classification == KSU_BL_SITE_UNSUPPORTED &&
			    c->min_sites != 0) {
				pr_warn("branch_link: unsupported caller %s "
					"has min_sites %u\n", c->name,
					c->min_sites);
				return false;
			}
			if (c->classification != KSU_BL_SITE_UNSUPPORTED &&
			    c->min_sites == 0) {
				pr_warn("branch_link: caller %s has "
					"min_sites 0\n", c->name);
				return false;
			}
			if (c->width > KSU_BL_SCAN_WIDTH_MAX) {
				pr_warn("branch_link: caller %s width "
					"overflow %u\n", c->name, c->width);
				return false;
			}
			if (!c->name || !c->name[0]) {
				pr_warn("branch_link: caller %u empty name\n",
					j);
				return false;
			}
		}
		/* duplicate caller names within one route are invalid */
		for (j = 0; j + 1 < r->caller_count; j++) {
			size_t k;

			for (k = j + 1; k < r->caller_count; k++) {
				if (!strcmp(ksu_bl_manifest_callers[
						r->first_caller + j].name,
					    ksu_bl_manifest_callers[
						r->first_caller + k].name)) {
					pr_warn("branch_link: route %u "
						"duplicate caller %s\n",
						r->id,
						ksu_bl_manifest_callers[
							r->first_caller + j]
								.name);
					return false;
				}
			}
		}
	}

	for (i = 0; i < h->target_count; i++) {
		const struct ksu_bl_gen_target *t =
			&ksu_bl_manifest_targets[i];

		if (!t->name || !t->name[0]) {
			pr_warn("branch_link: target %u empty name\n", i);
			return false;
		}
		if (t->hook_id >= KSU_BL_HOOK_COUNT) {
			pr_warn("branch_link: target %s bad hook %u\n",
				t->name, t->hook_id);
			return false;
		}
		if (t->fn_slot_id != KSU_BL_SLOT_NONE &&
		    t->fn_slot_id >= KSU_BL_SLOT_COUNT) {
			pr_warn("branch_link: target %s bad slot %u\n",
				t->name, t->fn_slot_id);
			return false;
		}
		if (t->binding > KSU_BL_BINDING_REALBODY) {
			pr_warn("branch_link: target %s bad binding %u\n",
				t->name, t->binding);
			return false;
		}
	}

	if (budget > KSU_BL_MAX_RECORDS) {
		pr_warn("branch_link: manifest budget %u > capacity %d\n",
			budget, KSU_BL_MAX_RECORDS);
		return false;
	}

	return true;
}

bool ksu_bl_generated_manifest_ready(void)
{
	return ksu_bl_manifest_valid;
}

const struct ksu_bl_gen_route *ksu_bl_generated_route(u16 id)
{
	if (!ksu_bl_manifest_valid || id >= KSU_BL_ROUTE_COUNT)
		return NULL;
	return &ksu_bl_manifest_routes[id];
}

const struct ksu_bl_gen_caller *ksu_bl_generated_callers(
	const struct ksu_bl_gen_route *route, u16 *count)
{
	if (!route || !ksu_bl_manifest_valid)
		return NULL;
	*count = route->caller_count;
	return &ksu_bl_manifest_callers[route->first_caller];
}

const struct ksu_bl_gen_target *ksu_bl_generated_targets(
	const struct ksu_bl_gen_route *route, u16 *count)
{
	if (!route || !ksu_bl_manifest_valid)
		return NULL;
	*count = route->target_count;
	return &ksu_bl_manifest_targets[route->first_target];
}

const char *ksu_bl_generated_group_name(u16 group_id)
{
	if (!ksu_bl_manifest_valid ||
	    group_id >= ksu_bl_manifest_header.group_count)
		return "?";
	return ksu_bl_manifest_groups[group_id];
}

void ksu_bl_manifest_init(void)
{
	ksu_bl_manifest_valid = ksu_bl_manifest_validate();
	if (ksu_bl_manifest_valid) {
		pr_info("branch_link: generated manifest accepted "
			"(schema %u, routes %u, callers %u, nonce 0x%08x)\n",
			ksu_bl_manifest_header.schema_version,
			ksu_bl_manifest_header.route_count,
			ksu_bl_manifest_header.caller_count,
			ksu_bl_manifest_header.nonce);
	} else {
		pr_warn("branch_link: generated manifest REJECTED -- "
			"branch-link subsystem disabled (fail-closed)\n");
	}
}
