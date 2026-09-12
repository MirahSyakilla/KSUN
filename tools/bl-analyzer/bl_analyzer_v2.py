#!/usr/bin/env python3
"""KernelSU-Next Branch-Link offline site analyzer v2 (Phase 17).

Fail-closed, policy-driven direct-BL census for AArch64 vmlinux.

  exit 0   -> every active policy route is fully accounted for; stamp + JSON written atomically
  exit !=0 -> failure; NO consumable manifest output is written

Outputs (only on success, atomic rename):
  --output-json   census JSON with identity stamp
  --output-c      C initializer rows (one row per caller; audit artifact)

Exit codes:
  0  success
  16 identity mismatch (stale inputs/version binding)
  32 input error (ELF/arch/type/map/paths)
  48 symbol error (missing/ambiguous target, containment, invalid BL)
  64 policy drift (required coverage lost/changed)
  80 generated-data error (width overflow, duplicates, malformed)
  96 internal error
"""

import argparse
import bisect
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bl_policy as P
from bl_policy import ConditionError

EX_USAGE = 2
EX_INTERNAL = 96

EXIT_INPUT = 32
EXIT_SYMBOL = 48
EXIT_DRIFT = 64
EXIT_MANIFEST = 80

ARM64_EM = 183          # EM_AARCH64
ET_EXEC = 2
ET_DYN = 3
ET_REL = 1

SHF_EXECINSTR = 0x4
SHT_NOBITS = 8

# ARM64 BL: | 100101 | imm26 |
BL_OPCODE = 0x94000000
BL_MASK = 0xFC000000


class Fail(Exception):
    def __init__(self, code, cls, msg):
        super().__init__(msg)
        self.code = code
        self.cls = cls
        self.msg = msg


def log(msg):
    sys.stderr.write("bl_analyzer: %s\n" % msg)


def run_tool(argv, what):
    try:
        r = subprocess.run(argv, capture_output=True, text=True)
    except FileNotFoundError:
        raise Fail(EXIT_INPUT, "TOOL_MISSING",
                   "%s not found: %s" % (what, argv[0]))
    if r.returncode != 0:
        raise Fail(EXIT_INPUT, "TOOL_FAILED",
                   "%s failed rc=%d: %s"
                   % (what, r.returncode, r.stderr.strip()[:400]))
    return r.stdout


def sha256_file(path):
    if not os.path.exists(path):
        raise Fail(EXIT_INPUT, "INPUT_MISSING", path)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def read_build_id(vmlinux, readelf):
    out = run_tool([readelf, "-n", "--", vmlinux], "readelf -n")
    m = re.search(r"Build ID:\s*([0-9a-fA-F]+)", out)
    return m.group(1) if m else ""


def read_elf_header(vmlinux, readelf):
    out = run_tool([readelf, "-h", "--", vmlinux], "readelf -h")
    h = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\w[^:]*):\s*(.+?)\s*$", line)
        if m:
            h[m.group(1)] = m.group(2)
    return h


def validate_elf(h, vmlinux):
    if "Class" not in h:
        raise Fail(EXIT_INPUT, "ELF_HEADER", "unparseable ELF header: %s" % vmlinux)
    if h.get("Class") != "ELF64":
        raise Fail(EXIT_INPUT, "ELF_CLASS",
                   "expected ELF64, got %s" % h.get("Class"))
    if h.get("Data") != "2's complement, little endian":
        raise Fail(EXIT_INPUT, "ELF_ENDIAN",
                   "expected little endian, got %s" % h.get("Data"))
    mach = h.get("Machine", "")
    if "AArch64" not in mach:
        raise Fail(EXIT_INPUT, "ELF_MACHINE",
                   "expected AArch64, got %s" % mach)
    etype = h.get("Type", "")
    if etype not in ("EXEC (Executable file)", "DYN (Shared object file)"):
        raise Fail(EXIT_INPUT, "ELF_TYPE",
                   "ET_REL/relocatable or unsupported type rejected: %s" % etype)


# ---------------------------------------------------------------------------
# Sections / symbols
# ---------------------------------------------------------------------------

def read_exec_sections(vmlinux, readelf):
    """Return [(name, addr, offset, size)] for PROGBITS+EXEC sections."""
    out = run_tool([readelf, "-SW", "--", vmlinux], "readelf -S")
    secs = []
    # Wide format: [Nr] Name Type Address Off Size ES Flg Lk Inf Al
    for line in out.splitlines():
        parts = line.split()
        # locate the "[N]" token (parts like "[", "1]")
        idx = None
        for j, p in enumerate(parts):
            if p == "]" or (p.endswith("]") and p[:-1].isdigit()):
                idx = j
                break
        if idx is None or len(parts) < idx + 8:
            continue
        name, typ, addr_s, off_s, size_s, _es, flg = parts[idx + 1:idx + 8]
        if typ != "PROGBITS" or "X" not in flg:
            continue
        try:
            secs.append((name, int(addr_s, 16), int(off_s, 16),
                         int(size_s, 16)))
        except ValueError:
            continue
    return secs


def read_symbols(vmlinux, nm):
    """Return list of (addr, size, type, name) for defined text symbols."""
    out = run_tool([nm, "-S", "--defined-only", "--", vmlinux], "nm -S")
    syms = []
    for line in out.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            addr_s, size_s, typ, name = parts
            addr = int(addr_s, 16)
            size = int(size_s, 16)
        elif len(parts) == 3:
            addr_s, typ, name = parts
            addr = int(addr_s, 16)
            size = 0
        else:
            continue
        if typ in ("t", "T", "W", "w"):
            syms.append((addr, size, typ, name))
    syms.sort(key=lambda s: (s[0], s[1]))
    return syms


class SymbolTable:
    """Positive-size function symbols with containment-safe lookup."""

    def __init__(self, raw):
        self.funcs = [s for s in raw if s[1] > 0]
        # index by start address; for duplicate addresses keep the largest size
        by_addr = {}
        for addr, size, typ, name in self.funcs:
            cur = by_addr.get(addr)
            if cur is None or size > cur[1]:
                by_addr[addr] = (addr, size, typ, name)
        self.starts = sorted(by_addr)
        self.by_addr = by_addr
        self.by_name = {}
        for addr, size, typ, name in self.funcs:
            self.by_name.setdefault(name, []).append((addr, size, typ, name))

    def lookup(self, va):
        """Return the unique function containing va, or None if ambiguous."""
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0:
            return None
        sym = self.by_addr[self.starts[i]]
        addr, size, typ, name = sym
        if not (addr <= va < addr + size):
            return None            # in padding/gap: fail-closed (no caller)
        return sym

    def find_unique(self, name):
        cands = self.by_name.get(name, [])
        if not cands:
            return None, "missing"
        addrs = {c[0] for c in cands}
        if len(addrs) > 1:
            return None, "ambiguous:%d" % len(addrs)
        return cands[0], None


# ---------------------------------------------------------------------------
# Census
# ---------------------------------------------------------------------------

def scan_section_for_bl(sec_addr, data, target_addrs):
    """Yield (site_va, raw, dest) for BLs whose dest is in target_addrs."""
    targets = set(target_addrs)
    hits = []
    n = len(data)
    if n < 4:
        return hits
    for off in range(0, n - 3, 4):
        raw = struct.unpack_from("<I", data, off)[0]
        if (raw & BL_MASK) != BL_OPCODE:
            continue
        imm = raw & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        dest = sec_addr + off + imm * 4
        if dest in targets:
            hits.append((sec_addr + off, raw, dest))
    return hits


def census_targets(vmlinux, symtab, sections, target_names, text_ok=None):
    """Census BL sites for a set of (name -> addr) targets.

    Returns (sites, rejected, target_addr_by_name) where sites is a list of
    dicts with caller attribution via containment-checked lookup.

    Census matches REAL-BODY addresses only: BL immediates in the callers'
    text encode the real function body, exactly like the runtime patcher's'''"'"'
    ksu_bl_lookup().  Canonical/CFI indirect addresses are a runtime
    function-pointer concern and are deliberately not part of the census.
    """
    target_addrs = {}
    for name in target_names:
        sym, err = symtab.find_unique(name)
        if err == "missing":
            continue
        if err:
            raise Fail(EXIT_SYMBOL, "TARGET_AMBIGUOUS",
                       "target %s: %s" % (name, err))
        target_addrs[name] = [sym[0]]

    all_addrs = [a for lst in target_addrs.values() for a in lst]
    if not all_addrs:
        return [], [], target_addrs

    sites = []
    rejected = []
    for sec_name, addr, off, size in sections:
        if text_ok is not None and sec_name not in text_ok:
            continue
        if size == 0:
            continue
        with open(vmlinux, "rb") as f:
            f.seek(off)
            data = f.read(size)
        if len(data) != size:
            raise Fail(EXIT_INPUT, "SECTION_SHORT_READ",
                       "%s: read %d of %d bytes" % (sec_name, len(data), size))
        for va, raw, dest in scan_section_for_bl(addr, data, all_addrs):
            sym = symtab.lookup(va)
            if sym is None:
                rejected.append((va, "no containing function"))
                continue
            sites.append({
                "caller": sym[3],
                "caller_addr": "0x%x" % sym[0],
                "site_va": "0x%x" % va,
                "raw": "0x%08x" % raw,
                "section": sec_name,
            })
    return sites, rejected, target_addrs


def caller_width(symtab, caller_addr, caller_size):
    """Width auto-derived from the function's own ELF size."""
    w = max(caller_size, P.SCAN_WIDTH)
    if w > P.WIDTH_FIELD_MAX:
        raise Fail(EXIT_MANIFEST, "WIDTH_OVERFLOW",
                   "caller 0x%x width 0x%x > u16" % (caller_addr, w))
    return w


def aggregate_callers(sites):
    """One row per caller, preserving per-caller site count."""
    order = []
    counts = {}
    widths = {}
    for s in sites:
        c = s["caller"]
        if c not in counts:
            counts[c] = 0
            order.append(c)
        counts[c] += 1
    rows = []
    for c in order:
        rows.append({
            "caller": c,
            "site_count": counts[c],
        })
    return rows


# ---------------------------------------------------------------------------
# Policy join
# ---------------------------------------------------------------------------

def derive_nr_booleans(srctree):
    """Derive __NR_* existence from UAPI headers, mirroring runtime Kbuild probes."""
    import glob
    flags = {}
    patterns = [
        "include/uapi/asm-generic/unistd.h",
        "arch/arm64/include/uapi/asm/unistd.h",
        "arch/arm64/include/asm/unistd32.h",
    ]
    text = ""
    for rel in patterns:
        path = os.path.join(srctree, rel)
        if os.path.exists(path):
            try:
                with open(path, "r", errors="replace") as f:
                    text += f.read()
            except OSError:
                pass
    for name in ("__NR_faccessat2", "__NR_statx", "__NR_execveat"):
        flags[name] = bool(re.search(r"#define\s+%s\s+\d+" % name, text))
    flags["_readable_headers"] = 1 if text else 0
    return flags


def derive_kver(srctree, objtree=None):
    """Read version from utsrelease.h (objtree first, then srctree)."""
    candidates = []
    if objtree:
        candidates.append(os.path.join(objtree, "include", "generated",
                                       "utsrelease.h"))
    candidates.append(os.path.join(srctree, "include", "generated",
                                   "utsrelease.h"))
    path = candidates[0]
    for c in candidates:
        if os.path.exists(c):
            path = c
            break
    try:
        with open(path, "r", errors="replace") as f:
            import re as _re
            m = _re.search(r'"([0-9]+)\.([0-9]+)\.([0-9]+)', f.read())
        if m:
            return tuple(int(g) for g in m.groups())
    except OSError:
        pass
    return None


def build_context(args):
    srctree = args.srctree or os.path.dirname(os.path.dirname(
        os.path.abspath(args.config)))
    cfg = {}
    try:
        with open(args.config, "r", errors="replace") as f:
            for line in f:
                m = re.match(r"^(CONFIG_\w+)=(.*)$", line.strip())
                if m:
                    k, v = m.group(1), m.group(2)
                    if v == "y":
                        cfg[k] = True
                    elif v.startswith('"') and v.endswith('"'):
                        cfg[k] = v[1:-1]
                    elif re.fullmatch(r"\d+", v):
                        cfg[k] = int(v)  # int("0") is falsy: correct
                    else:
                        cfg[k] = v
                else:
                    m2 = re.match(r"^# (CONFIG_\w+) is not set", line.strip())
                    if m2:
                        cfg[m2.group(1)] = False
    except FileNotFoundError:
        raise Fail(EXIT_INPUT, "CONFIG_MISSING", args.config)
    except IsADirectoryError:
        raise Fail(EXIT_INPUT, "CONFIG_NOT_A_FILE", args.config)
    kver = None
    if args.kver:
        import re as _re
        m = _re.match(r"(\d+)\.(\d+)\.(\d+)", args.kver)
        if not m:
            raise Fail(EXIT_INPUT, "KVER_FORMAT", args.kver)
        kver = tuple(int(g) for g in m.groups())
    else:
        objtree = os.path.dirname(os.path.abspath(args.config))
        kver = derive_kver(srctree, objtree)
        if kver is None:
            raise Fail(EXIT_INPUT, "KVER_DERIVE",
                       "cannot derive kernel version; pass --kver")
    ctx = dict(cfg)
    ctx["kver"] = tuple(kver)
    # __NR_* derived from the vendor UAPI headers
    nr = derive_nr_booleans(srctree)
    if not nr.pop("_readable_headers", 0):
        raise Fail(EXIT_INPUT, "SRCTREE_HEADERS_MISSING",
                   "no UAPI unistd headers under %s; __NR_* conditions would "
                   "silently disable required callers" % srctree)
    ctx.update(nr)
    # source-shape probes (CLI-supplied)
    ctx["KSU_HAS_OPENAT2"] = bool(args.has_openat2)
    ctx["KSU_EXECVE_COMMON_HELPER"] = bool(args.exec_common)
    ctx["KSU_HAS_COMPAT_EXECVEAT"] = bool(args.compat_execveat)
    ctx["KSU_HAS_FACCESSAT2"] = bool(args.has_faccessat2)
    return ctx


def sysmap_symbols(path):
    syms = {}
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) >= 3:
                    try:
                        syms.setdefault(p[2], int(p[0], 16))
                    except ValueError:
                        continue
    except FileNotFoundError:
        raise Fail(EXIT_INPUT, "SYSMAP_MISSING", path)
    if not syms:
        raise Fail(EXIT_INPUT, "SYSMAP_EMPTY", path)
    return syms


def crosscheck_sysmap(symtab, sysmap):
    """Two-way symbol binding with System.map.

    (a) every symbol present in both sources must agree on address;
    (b) required targets: every ELF function symbol that any active route
        needs must ALSO be present in System.map at the same address -- a
        truncated/unrelated map cannot pass by being merely a subset.
    """
    mism = []
    checked = 0
    for name, syms in symtab.by_name.items():
        if name not in sysmap:
            continue
        checked += 1
        addr = sysmap[name]
        if all(c[0] != addr for c in syms):
            mism.append((name, [hex(c[0]) for c in syms], hex(addr)))
    if mism:
        sample = "; ".join("%s elf=%s map=%s" % m for m in mism[:5])
        raise Fail(EXIT_INPUT, "SYSMAP_MISMATCH",
                   "%d/%d checked symbols disagree; e.g. %s"
                   % (len(mism), checked, sample))


def require_sysmap_targets(symtab, sysmap, target_names):
    """Every route target name must exist in System.map at the ELF address."""
    missing = []
    for name in target_names:
        sym, err = symtab.find_unique(name)
        if err == "missing":
            continue                 # ELF-missing handled by policy drift
        if err:
            continue
        map_addr = sysmap.get(name)
        if map_addr is None:
            missing.append(name)
        elif map_addr != sym[0]:
            missing.append("%s(addr %s != %s)"
                           % (name, hex(sym[0]), hex(map_addr)))
    if missing:
        raise Fail(EXIT_INPUT, "SYSMAP_TARGET_MISSING",
                   "System.map does not bind route targets: %s"
                   % ", ".join(missing[:8]))


# ---------------------------------------------------------------------------
# Output (atomic)
# ---------------------------------------------------------------------------

def atomic_write_json(path, obj):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".bl_manifest.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def c_escape(name):
    if not re.fullmatch(r"[A-Za-z0-9_$]+", name):
        raise Fail(EXIT_MANIFEST, "C_ESCAPE",
                   "symbol name not C-safe: %r" % name)
    return name


def emit_c(routes_result, stamp):
    lines = []
    lines.append("/* AUTO-GENERATED by bl_analyzer_v2.py -- DO NOT EDIT */")
    lines.append("/* payload: %s */" % stamp["payload_sha256"])
    lines.append("/* vmlinux: %s */" % stamp["inputs"]["vmlinux_sha256"])
    lines.append("")
    for r in routes_result:
        lines.append("/* %s: %d sites, drift=%s */"
                     % (r["route"], r["total_sites"], r["drift"]))
        for row in r["rows"]:
            w = row.get("width", 0)
            lines.append('\t\t{ "%s", KSU_BL_SITE_%s, %d, %s },'
                         % (c_escape(row["caller"]),
                            row["classification"].upper(),
                            row["min_sites"],
                            ("0x%x" % w) if w and w != P.SCAN_WIDTH else "0"))
        lines.append("")
    return "\n".join(lines) + "\n"


def atomic_write_text(path, text):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".bl_manifest.", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze(args):
    readelf = args.readelf or "readelf"
    nm = args.nm or "nm"

    if os.path.exists(args.vmlinux) is False:
        raise Fail(EXIT_INPUT, "VMLINUX_MISSING", args.vmlinux)

    # output/input aliasing guard
    input_abs = {os.path.abspath(x) for x in
                 (args.vmlinux, args.sysmap, args.config) if x}
    outpaths = [p for p in (args.output_json, args.output_c,
                            args.report_on_fail) if p]
    for p in outpaths:
        pabs = os.path.abspath(p)
        if pabs in input_abs:
            raise Fail(EXIT_INPUT, "OUTPUT_ALIAS",
                       "output path collides with input: %s" % p)
    named_out = [p for p in (args.output_json, args.output_c) if p]
    if len({os.path.abspath(p) for p in named_out}) != len(named_out):
        raise Fail(EXIT_INPUT, "OUTPUT_ALIAS",
                   "--output-json/--output-c/--report-on-fail collide")

    h = read_elf_header(args.vmlinux, readelf)
    validate_elf(h, args.vmlinux)
    build_id = read_build_id(args.vmlinux, readelf)

    vmlinux_sha = sha256_file(args.vmlinux)
    sysmap_sha = sha256_file(args.sysmap)

    sections = read_exec_sections(args.vmlinux, readelf)
    if not sections:
        raise Fail(EXIT_INPUT, "NO_EXEC_SECTIONS", args.vmlinux)
    raw_syms = read_symbols(args.vmlinux, nm)
    if not raw_syms:
        raise Fail(EXIT_INPUT, "NO_SYMBOLS", args.vmlinux)
    symtab = SymbolTable(raw_syms)

    sysmap = sysmap_symbols(args.sysmap)
    crosscheck_sysmap(symtab, sysmap)

    ctx = build_context(args)
    ctx["kver"] = tuple(ctx["kver"])

    # every active-route target must be bound in System.map at the ELF address
    active_target_names = set()
    for route in P.enabled_routes(ctx):
        for t in route.targets:
            if t.cond and not P.eval_cond(t.cond, ctx):
                continue
            active_target_names.add(t.symbol)
    require_sysmap_targets(symtab, sysmap, sorted(active_target_names))

    config_sha = sha256_file(args.config) if os.path.exists(args.config) else ""
    image_sha = ""
    if args.image and os.path.exists(args.image):
        image_sha = sha256_file(args.image)
    elif args.image:
        raise Fail(EXIT_INPUT, "IMAGE_MISSING", args.image)

    routes_result = []
    any_drift = False
    for route in P.enabled_routes(ctx):
        target_names = []
        for t in route.targets:
            if t.cond and not P.eval_cond(t.cond, ctx):
                continue
            target_names.append(t.symbol)
        if not target_names:
            routes_result.append({
                "route": route.id, "total_sites": 0,
                "drift": "DRIFT_TARGET_MISSING",
                "rows": [], "targets": [], "callers": [],
            })
            raise Fail(EXIT_SYMBOL, "TARGET_MISSING",
                       "route %s: no enabled target resolved" % route.id)

        sites, rejected, taddr = census_targets(
            args.vmlinux, symtab, sections, target_names,
            set(P.ALLOWED_TEXT_SECTIONS))

        # per-caller aggregation
        by_caller = {}
        order = []
        for s in sites:
            c = s["caller"]
            if c not in by_caller:
                by_caller[c] = []
                order.append(c)
            by_caller[c].append(s)

        rows = []
        route_fail = []
        seen_names = set()
        for pc in route.callers:
            if pc.cond and not P.eval_cond(pc.cond, ctx):
                continue
            if pc.name in seen_names:
                raise Fail(EXIT_MANIFEST, "POLICY_DUP",
                           "duplicate policy caller %s in %s"
                           % (pc.name, route.id))
            seen_names.add(pc.name)
            found = by_caller.get(pc.name, [])
            n = len(found)
            if pc.classification == P.UNSUPPORTED:
                if n:
                    route_fail.append(
                        "unsupported caller %s has %d sites" % (pc.name, n))
                rows.append({
                    "caller": pc.name, "classification": pc.classification,
                    "min_sites": 0, "width": 0, "sites": n,
                    "owner": pc.owner,
                })
                continue
            sym, err = symtab.find_unique(pc.name)
            if err == "missing":
                if pc.classification == P.REQUIRED and not pc.acknowledged:
                    route_fail.append("required caller %s missing" % pc.name)
                rows.append({
                    "caller": pc.name, "classification": pc.classification,
                    "min_sites": pc.min_sites, "width": 0, "sites": 0,
                    "owner": pc.owner, "acknowledged": pc.acknowledged,
                })
                continue
            if err:
                route_fail.append("caller %s: %s" % (pc.name, err))
                continue
            # width from function size when explicit policy width is 0
            width = pc.width
            if width == 0:
                width = caller_width(symtab, sym[0], sym[1])
            elif width > P.WIDTH_FIELD_MAX:
                raise Fail(EXIT_MANIFEST, "WIDTH_OVERFLOW",
                           "policy width 0x%x for %s exceeds u16"
                           % (width, pc.name))
            if pc.classification == P.REQUIRED and n < pc.min_sites \
                    and not pc.acknowledged:
                route_fail.append(
                    "required caller %s has %d sites < min %d"
                    % (pc.name, n, pc.min_sites))
            elif pc.classification == P.REQUIRED and n < pc.min_sites \
                    and pc.acknowledged:
                log("ACK %s/%s: %d sites < min %d (acknowledged)"
                    % (route.id, pc.name, n, pc.min_sites))
            rows.append({
                "caller": pc.name, "classification": pc.classification,
                "min_sites": pc.min_sites, "width": width, "sites": n,
                "owner": pc.owner, "acknowledged": pc.acknowledged,
            })

        # unexpected policy-external callers.
        # For exec routes (kind=exec) multiple logical routes share one
        # physical target (__do_execve_file), so each route's census contains
        # the other routes' callers plus wrapper-internal BL paths. Scope the
        # check to "every census caller must be covered by SOME exec route"
        # instead of per-route lists.
        exec_sibling_callers = set()
        if route.kind == "exec":
            for other in P.enabled_routes(ctx):
                if other.kind != "exec":
                    continue
                for pc2 in other.callers:
                    if pc2.cond and not P.eval_cond(pc2.cond, ctx):
                        continue
                    exec_sibling_callers.add(pc2.name)
        unlisted = []
        for c in order:
            if c in seen_names:
                continue
            if route.kind == "exec" and c in exec_sibling_callers:
                continue
            unlisted.append(c)
        if unlisted:
            if route.acknowledge_unlisted:
                log("WARN %s: census callers without policy rows "
                    "(acknowledged coverage gap): %s"
                    % (route.id, ", ".join(sorted(unlisted)[:8])))
            else:
                route_fail.append("unexpected callers (no policy row): %s"
                                  % ", ".join(sorted(unlisted)[:8]))

        # census expectation (two-sided check)
        if route.census_expected_sites and len(sites) != route.census_expected_sites:
            route_fail.append(
                "census mismatch: expected %d sites, found %d"
                % (route.census_expected_sites, len(sites)))

        drift = "DRIFT_NONE" if not route_fail else "DRIFT_POLICY_FAIL"
        if route_fail:
            any_drift = True
            for f in route_fail[:10]:
                log("%s: %s" % (route.id, f))
        policy_sites = sum(r["sites"] for r in rows
                           if r["classification"] != P.UNSUPPORTED
                           and not r.get("acknowledged"))
        routes_result.append({
            "route": route.id,
            "targets": [t for t in target_names],
            "target_addrs": {k: [hex(x) for x in v] for k, v in taddr.items()},
            "total_sites": policy_sites,
            "census_sites": len(sites),
            "drift": drift,
            "rows": rows,
            "rejected": [{"va": "0x%x" % va, "reason": rsn}
                         for va, rsn in rejected],
        })

    # runtime record-capacity budget (KSU_BL_MAX_RECORDS).  Only rows the
    # runtime would actually commit count: acknowledged rows document known
    # census/runtime divergences that the current runtime does NOT install.
    budget = sum(r["total_sites"] for r in routes_result
                 if "total_sites" in r)
    projected = 0
    for r in routes_result:
        for row in r.get("rows", []):
            if row["classification"] == P.UNSUPPORTED:
                continue
            if row.get("sites", 0) == 0:
                continue
            if row.get("acknowledged"):
                projected += row.get("sites", 0)
    if budget > P.MAX_RECORDS:
        raise Fail(EXIT_MANIFEST, "RECORD_BUDGET",
                   "committed policy census %d sites exceeds runtime "
                   "capacity %d" % (budget, P.MAX_RECORDS))
    if projected:
        log("projected budget if acknowledged gaps adopted: %d/%d "
            "(capacity increase required)"
            % (budget + projected, P.MAX_RECORDS))

    if any_drift:
        raise Fail(EXIT_DRIFT, "POLICY_DRIFT",
                   "%d route(s) failed policy validation" %
                   sum(1 for r in routes_result if r["drift"] != "DRIFT_NONE"))

    stamp = {
        "schema_version": P.SCHEMA_VERSION,
        "policy_revision": P.POLICY_REVISION,
        "policy_id": P.POLICY_ID,
        "policy_sha256": P.policy_digest(),
        "analyzer_version": "2",
        # no wall-clock timestamp: outputs must be byte-deterministic
        "inputs": {
            "vmlinux_sha256": vmlinux_sha,
            "image_sha256": image_sha,
            "system_map_sha256": sysmap_sha,
            "config_sha256": config_sha,
            "vmlinux_build_id": build_id,
            "elf_type": h.get("Type", ""),
            "elf_machine": h.get("Machine", ""),
        },
    }
    payload = json.dumps(routes_result, sort_keys=True, indent=1)
    stamp["payload_sha256"] = hashlib.sha256(
        payload.encode()).hexdigest()
    return stamp, routes_result, payload


def main():
    ap = argparse.ArgumentParser(
        description="KSU branch-link offline analyzer v2 (fail-closed)")
    ap.add_argument("--vmlinux", required=True)
    ap.add_argument("--sysmap", required=True)
    ap.add_argument("--config", help="active .config for condition evaluation")
    ap.add_argument("--image", help="raw Image to bind in identity (optional)")
    ap.add_argument("--output-json")
    ap.add_argument("--output-c")
    ap.add_argument("--nm", help="nm binary (default: nm)")
    ap.add_argument("--readelf", help="readelf binary (default: readelf)")
    ap.add_argument("--srctree", help="kernel source tree for __NR_* derivation")
    ap.add_argument("--kver", help="kernel version x.y.z (default: derived "
                                    "from <srctree>/include/generated/utsrelease.h)")
    ap.add_argument("--report-on-fail",
                    help="write failure-report JSON to this path on failure")
    # source-shape probe overrides
    ap.add_argument("--has-openat2", action="store_true")
    ap.add_argument("--exec-common", action="store_true")
    ap.add_argument("--compat-execveat", action="store_true")
    ap.add_argument("--has-faccessat2", action="store_true")
    args = ap.parse_args()

    try:
        stamp, routes_result, payload = analyze(args)
    except Fail as e:
        log("%s/%s: %s" % (e.code, e.cls, e.msg))
        if args.report_on_fail:
            try:
                atomic_write_json(args.report_on_fail, {
                    "status": "failure", "exit": e.code, "class": e.cls,
                    "detail": e.msg, "analyzer_version": "2",
                })
            except OSError as oe:
                log("report-on-fail write failed: %s" % oe)
        sys.exit(e.code)
    except ConditionError as e:
        log("%d/POLICY_COND: %s" % (EXIT_MANIFEST, e))
        sys.exit(EXIT_MANIFEST)
    except Exception as e:                       # noqa: BLE001
        log("%d/INTERNAL: unhandled: %r" % (EX_INTERNAL, e))
        sys.exit(EX_INTERNAL)

    if args.output_json:
        atomic_write_json(args.output_json, {
            "stamp": stamp,
            "routes": routes_result,
        })
    if args.output_c:
        atomic_write_text(args.output_c, emit_c(routes_result, stamp))
    total = sum(r["total_sites"] for r in routes_result)
    log("OK: %d routes, %d sites, payload %s"
        % (len(routes_result), total, stamp["payload_sha256"][:16]))
    sys.exit(0)


if __name__ == "__main__":
    main()
