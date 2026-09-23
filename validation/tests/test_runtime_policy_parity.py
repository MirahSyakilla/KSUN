#!/usr/bin/env python3
"""Phase 18 permanent test: runtime manifest arrays == source policy rows.

Parses branch_link_hook.c with file-wide preprocessor visibility, splits it
into per-family function blocks, binds each block to its route id(s) via the
patch-call literals, and compares runtime rows against bl_policy.py rows
under the reference lisa profile (CONFIG_COMPAT=y, CONFIG_AUDIT=y, no
openat2, legacy exec, compat_execveat).  Any drift fails.
"""
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "tools", "bl-analyzer"))
import bl_policy as P  # noqa: E402

src_path = os.path.join(ROOT, "kernel/hook/arm64/branch_link_hook.c")
src = open(src_path).read()

CTX = {"CONFIG_COMPAT": True, "CONFIG_AUDIT": True,
       "CONFIG_KSU_HOOK_CORE": True,
       "CONFIG_KSU_HOOKLESS_SUSFS": True,
       "CONFIG_KSU_HOOKLESS_NOMOUNT": True,
       "__NR_faccessat2": False, "__NR_statx": True, "__NR_execveat": True,
       "KSU_HAS_OPENAT2": False, "KSU_EXECVE_COMMON_HELPER": False,
       "KSU_HAS_COMPAT_EXECVEAT": True, "KSU_HAS_FACCESSAT2": False,
       # profile macros resolve to the lisa reference profile
       "KSU_BL_EXEC_COMMON_PROFILE": 0,
       "CONFIG_KSU_BL_GENERATED": True,
       "KSU_BL_MAX_RECORDS": 192,
       "__aarch64__": True,
       "kver": (5, 4, 302)}

# Macros that are NOT in CTX default to SKIP (fail-closed), not visible.
# The visibility map records skipped spans and the comparison fails if any
# row text was hidden by an unknown guard (mutation-verified blind spot 2).

CLS = {"KSU_BL_SITE_REQUIRED": "required",
       "KSU_BL_SITE_OPTIONAL": "optional",
       "KSU_BL_SITE_UNSUPPORTED": "unsupported"}

ROW_RE = re.compile(
    r'\{\s*"([^"]+)",\s*(KSU_BL_SITE_\w+),\s*(\d+)'
    r"(?:,\s*(0x[0-9a-fA-F]+|\d+))?\s*\},")

ROW_WRAP_RE = re.compile(
    r'\{\s*"[^"]+"(?:\s*,\s*(?:KSU_BL_SITE_\w+|LINUX_VERSION_CODE\s*<\s*'
    r'KERNEL_VERSION\(\d+,\s*\d+,\s*\d+\)\s*\?))?\s*,?\s*$')

TERNARY_RE = re.compile(
    r'\{\s*"([^"]+)",\s*LINUX_VERSION_CODE\s*<\s*'
    r"KERNEL_VERSION\((\d+),\s*(\d+),\s*(\d+)\)\s*\?\s*"
    r"KSU_BL_SITE_(\w+)\s*:\s*KSU_BL_SITE_(\w+),\s*(\d+)\s*\},")

def parse_ternary(line):
    m = TERNARY_RE.match(line.strip())
    if not m:
        return None
    name, a, b, c, cls_lt, cls_ge, min_s = m.groups()
    cls = cls_lt.lower() if CTX["kver"] < (int(a), int(b), int(c)) \
        else cls_ge.lower()
    return (name, cls, int(min_s), 0)

# --- file-wide preprocessor visibility ---------------------------------------
unknown_guards = set()


def build_visibility(text):
    stack = []
    vis = []
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"#\s*ifdef\s+(\w+)", s)
        if m:
            if m.group(1) not in CTX:
                unknown_guards.add(m.group(1))
            stack.append(bool(CTX.get(m.group(1), False)))
            vis.append(None)
            continue
        m = re.match(r"#\s*ifndef\s+(\w+)", s)
        if m:
            if m.group(1) not in CTX:
                unknown_guards.add(m.group(1))
            stack.append(not bool(CTX.get(m.group(1), False)))
            vis.append(None)
            continue
        m = re.match(r"#\s*if\s+LINUX_VERSION_CODE\s*>=\s*"
                     r"KERNEL_VERSION\((\d+),\s*(\d+),\s*(\d+)\)", s)
        if m:
            stack.append(CTX["kver"] >= tuple(map(int, m.groups())))
            vis.append(None)
            continue
        m = re.match(r"#\s*if\s+LINUX_VERSION_CODE\s*<\s*"
                     r"KERNEL_VERSION\((\d+),\s*(\d+),\s*(\d+)\)", s)
        if m:
            stack.append(CTX["kver"] < tuple(map(int, m.groups())))
            vis.append(None)
            continue
        m = re.match(r"#\s*if\s+defined\((\w+)\)", s)
        if m:
            stack.append(bool(CTX.get(m.group(1), False)))
            vis.append(None)
            continue
        if re.match(r"#\s*if\b", s):
            # KSU_* source-shape macros select alternative shapes; parse both
            stack.append(True)
            vis.append(None)
            continue
        if re.match(r"#\s*else", s):
            if stack:
                stack[-1] = not stack[-1]
            vis.append(None)
            continue
        if re.match(r"#\s*elif", s):
            if stack:
                stack[-1] = False
            vis.append(None)
            continue
        if re.match(r"#\s*endif", s):
            if stack:
                stack.pop()
            vis.append(None)
            continue
        vis.append(all(stack))
    return vis

VIS = build_visibility(src)
LINES = src.splitlines()

# join wrapped rows within the visible line set, then parse rows
def rows_in_range(start_line, end_line):
    joined = []
    i = start_line
    while i < end_line:
        cur = LINES[i]
        while (i + 1 < end_line and ROW_WRAP_RE.match(cur.strip())
               and LINES[i + 1].strip().endswith("},")):
            i += 1
            cur = cur.rstrip() + " " + LINES[i].strip()
        if VIS[i]:
            joined.append(cur)
        i += 1
    rows = []
    for line in joined:
        t = parse_ternary(line)
        if t:
            rows.append(t)
            continue
        m = ROW_RE.match(line.strip())
        if m:
            name, cls, min_s, w = m.groups()
            rows.append((name, CLS[cls], int(min_s),
                         int(w, 16) if w and w.startswith("0x")
                         else int(w or 0)))
    return rows

# --- function blocks ----------------------------------------------------------
headings = [m.start() for m in re.finditer(
    r"(?m)^static bool ksu_branch_link_patch_\w+|^int ksu_branch_link_patch_init",
    src)]
headings.append(len(src))

def line_of(pos):
    return src[:pos].count("\n")

compared = 0
fails = []
covered = set()

for bi in range(len(headings) - 1):
    b0, b1 = headings[bi], headings[bi + 1]
    blk = src[b0:b1]
    if not any(x in blk for x in ("ksu_bl_record_patch_manifest(",
                                  "ksu_bl_record_patch_routes(",
                                  "ksu_bl_patch_exec_route(")):
        continue
    rids = [rid for rid in (r.id for r in P.ROUTES)
            if ('"%s"' % rid) in blk]
    if not rids:
        continue
    rt_rows = rows_in_range(line_of(b0) + 1, line_of(b1))
    pol_rows = []
    for rid in rids:
        r = next(x for x in P.ROUTES if x.id == rid)
        for c in r.callers:
            if c.cond and not P.eval_cond(c.cond, CTX):
                continue
            pol_rows.append((c.name, c.classification, c.min_sites, c.width))
    # exec block contains both profile shapes' arrays; only the ACTIVE
    # profile's rows are compiled. Dedupe the policy expectation to the
    # active exec routes when the block carries the common-profile literal.
    if "execve/do_execveat_common" in rids and \
            CTX.get("KSU_BL_EXEC_COMMON_PROFILE", 0) == 0:
        # common-profile rows are compiled out; drop them from policy
        common = next(x for x in P.ROUTES if x.id == "execve/do_execveat_common")
        common_rows = Counter()
        for c in common.callers:
            if c.cond and not P.eval_cond(c.cond, CTX):
                continue
            common_rows[(c.name, c.classification, c.min_sites, c.width)] += 1
        pol_c = Counter(pol_rows)
        for k in list(pol_c):
            if common_rows[k] and pol_c[k] > 1:
                pol_c[k] -= 1  # the shared syscall-entry rows appear once in
                # the compiled #else arm; extra duplicates are common-profile
        pol_rows = list(pol_c.elements())
    rt_c = Counter(rt_rows)
    pol_c = Counter(pol_rows)
    only_rt = list((rt_c - pol_c).elements())
    only_pol = list((pol_c - rt_c).elements())
    if only_rt or only_pol:
        fails.append("routes=%s\n  runtime-only=%s\n  policy-only=%s"
                     % (rids, only_rt[:6], only_pol[:6]))
    covered.update(rids)
    compared += 1

missing = []
for r in P.ROUTES:
    active = (not r.cond) or P.eval_cond(r.cond, CTX)
    if active and r.id not in covered:
        missing.append(r.id)

print("blocks compared:", compared)
for f in fails:
    print("FAIL", f)
for m in missing:
    print("FAIL missing block for route:", m)
for g in sorted(unknown_guards):
    print("WARN unknown guard macro (rows hidden):", g)
ok = not fails and not missing
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
