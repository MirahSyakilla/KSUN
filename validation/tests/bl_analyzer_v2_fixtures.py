#!/usr/bin/env python3
"""Permanent fixture-level assertions for bl_analyzer_v2 (Phase 17)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools", "bl-analyzer"))
import bl_analyzer_v2 as A  # noqa: E402

F = os.path.join(HERE, "..", "audit", "phase17", "fixtures", "%s.elf")
PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name, detail)


def bl_sites(elf, target):
    st = A.SymbolTable(A.read_symbols(elf, "nm"))
    ss = A.read_exec_sections(elf, "readelf")
    return A.census_targets(elf, st, ss, [target], None)


sites, rej, ta = bl_sites(F % "valid", "target_fn")
check("valid_single_site", len(sites) == 1 and sites[0]["caller"] == "_start",
      str(sites))

sites, rej, ta = bl_sites(F % "two", "target_fn")
rows = A.aggregate_callers(sites)
check("two_sites_one_row",
      len(sites) == 2 and len(rows) == 1 and rows[0]["site_count"] == 2,
      str((sites, rows)))

sites, rej, ta = bl_sites(F % "pad", "target_fn")
check("pad_out_of_function_rejected",
      any("no containing" in r[1] for r in rej), str(rej))

sites, rej, ta = bl_sites(F % "notarget", "nowhere_fn")
check("missing_target_zero_sites", sites == [], str(sites))

sites, rej, ta = bl_sites(F % "recurse", "target_fn")
check("recurse_self_call_attributed",
      "target_fn" in {s["caller"] for s in sites}, str(sites))

sites, rej, ta = bl_sites(F % "blronly", "target_fn")
check("blr_zero_direct_sites", len(sites) == 0, str(sites))

sites, rej, ta = bl_sites(F % "veneer", "target_fn")
check("veneer_no_direct_start_site",
      "_start" not in {s["caller"] for s in sites}, str(sites))

print("PASS=%d FAIL=%d" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
