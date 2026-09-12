#!/usr/bin/env python3
"""
KernelSU-Next Branch-Link Offline Site Discovery Analyzer.

Reads a compiled vmlinux ELF + System.map, discovers all direct BL call
sites for each hook family's semantic target, and generates a C header
containing the validated per-caller manifest for the runtime patcher.

Usage:
    ./bl_discover.py --vmlinux VMLINUX --sysmap SYSMAP --output HEADER.c
    ./bl_discover.py --vmlinux VMLINUX --sysmap SYSMAP --json OUTPUT.json

The analyzer operates ONLY on build artifacts.  The runtime BL patcher
performs the actual safe text modification using its existing
stop_machine/compare-and-swap infrastructure.
"""

import argparse
import bisect
import hashlib
import json
import struct
import subprocess
import sys
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Hook family definitions (source-level policy)
# ---------------------------------------------------------------------------

@dataclass
class HookFamily:
    name: str
    target_symbol: str
    policy: str          # "ALL_DIRECT_CALLERS" or "MANIFEST_CALLERS"
    required: bool
    wrapper_symbol: str
    min_sites: int
    # For MANIFEST_CALLERS: explicit caller list
    explicit_callers: List[str] = field(default_factory=list)
    # For ALL_DIRECT_CALLERS: reject these known non-caller BL sources
    exclude_callers: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# ARM64 instruction decoding
# ---------------------------------------------------------------------------

def is_bl(raw: int) -> bool:
    """Check if a 32-bit ARM64 instruction is a BL (opcode 100101)."""
    return (raw >> 26) == 0b100101

def bl_target(site_va: int, raw: int) -> int:
    """Decode a BL instruction's target address."""
    imm26 = raw & 0x3FFFFFF
    if imm26 & 0x2000000:
        imm26 -= 0x4000000
    return site_va + imm26 * 4

# ---------------------------------------------------------------------------
# ELF vmlinux reader
# ---------------------------------------------------------------------------

@dataclass
class Symbol:
    name: str
    addr: int
    size: int
    type: str  # 't', 'T', 'w', 'W', etc.
    section: str

@dataclass
class SymbolTable:
    symbols: List[Symbol]
    addrs: List[int]

    def lookup(self, addr: int) -> Optional[Symbol]:
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0:
            return None
        return self.symbols[i]

    def find_by_name(self, name: str) -> Optional[Symbol]:
        for s in self.symbols:
            if s.name == name:
                return s
        return None

def read_vmlinux_symbols(vmlinux_path: str) -> SymbolTable:
    """Read function symbols from a vmlinux ELF using nm."""
    result = subprocess.run(
        ["nm", "-S", "--defined-only", vmlinux_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"nm failed: {result.stderr}")
    symbols = []
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            addr = int(parts[0], 16)
            size = int(parts[1], 16) if parts[1] != '' else 0
            stype = parts[2]
            name = parts[3]
            if stype in ('t', 'T', 'W', 'w') and size > 0:
                symbols.append(Symbol(name, addr, size, stype, ".text"))
        elif len(parts) == 3:
            addr = int(parts[0], 16)
            stype = parts[1]
            name = parts[2]
            if stype in ('t', 'T', 'W', 'w'):
                symbols.append(Symbol(name, addr, 0, stype, ".text"))
    symbols.sort(key=lambda s: s.addr)
    return SymbolTable(symbols, [s.addr for s in symbols])

def read_text_section(vmlinux_path: str) -> Tuple[int, bytes]:
    """Read the .text section from vmlinux ELF."""
    result = subprocess.run(
        ["readelf", "-S", "--wide", vmlinux_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"readelf failed: {result.stderr}")
    for line in result.stdout.splitlines():
        # Format: [ N] .text PROGBITS ADDR OFF SIZE ...
        # Find the .text section (exact match, not .text.foo)
        parts = line.split()
        for i, p in enumerate(parts):
            if p == ".text" and i > 0 and i + 3 < len(parts):
                # The section name is at index i; PROGBITS at i+1;
                # ADDR at i+2; OFF at i+3; SIZE at i+4
                if i + 1 < len(parts) and parts[i+1] == "PROGBITS":
                    addr = int(parts[i+2], 16)
                    offset = int(parts[i+3], 16)
                    size = int(parts[i+4], 16)
                    with open(vmlinux_path, "rb") as f:
                        f.seek(offset)
                        data = f.read(size)
                    return addr, data
    raise RuntimeError(".text section not found")

# ---------------------------------------------------------------------------
# Site discovery
# ---------------------------------------------------------------------------

@dataclass
class DiscoveredSite:
    caller_symbol: str
    caller_addr: int
    site_va: int
    site_offset: int
    raw_instruction: int
    target_va: int
    target_symbol: str

@dataclass
class FamilyResult:
    family: HookFamily
    target_found: bool
    target_va: Optional[int]
    sites: List[DiscoveredSite]
    rejected: List[Tuple[int, str]]  # (site_va, reason)
    drift: str  # drift classification
    manifest_lines: List[str]  # generated C code lines

def discover_family(
    family: HookFamily,
    symtab: SymbolTable,
    text_addr: int,
    text_data: bytes,
) -> FamilyResult:
    result = FamilyResult(family, False, None, [], [], "DRIFT_UNSUPPORTED", [])

    # 1. Resolve target symbol
    target_sym = symtab.find_by_name(family.target_symbol)
    if not target_sym:
        result.drift = "DRIFT_TARGET_MISSING"
        return result
    result.target_va = target_sym.addr
    result.target_found = True

    # 2. Scan text for BL-to-target
    target = target_sym.addr
    text_size = len(text_data)

    # Build sorted symbol address index for caller attribution
    func_addrs = [s.addr for s in symtab.symbols if s.size > 0]

    for off in range(0, text_size - 3, 4):
        raw = struct.unpack_from("<I", text_data, off)[0]
        if not is_bl(raw):
            continue
        va = text_addr + off
        dest = bl_target(va, raw)
        if dest != target:
            continue

        # Attribute caller
        caller = symtab.lookup(va)
        if not caller:
            result.rejected.append((va, "no caller symbol"))
            continue

        # Skip KSU's own text (wrapper functions)
        if caller.name.startswith("ksu_"):
            result.rejected.append((va, f"KSU internal ({caller.name})"))
            continue

        # Check exclude list
        if caller.name in family.exclude_callers:
            result.rejected.append((va, f"excluded caller {caller.name}"))
            continue

        site_offset = va - caller.addr
        result.sites.append(DiscoveredSite(
            caller.name, caller.addr, va, site_offset, raw,
            target, family.target_symbol
        ))

    # 3. Deduplicate by caller
    seen_callers = {}
    deduped = []
    for s in result.sites:
        if s.caller_symbol in seen_callers:
            seen_callers[s.caller_symbol] += 1
            deduped.append(s)
        else:
            seen_callers[s.caller_symbol] = 1
            deduped.append(s)
    result.sites = deduped

    # 4. Drift classification
    site_count = len(result.sites)
    caller_count = len(set(s.caller_symbol for s in result.sites))

    if site_count == 0:
        result.drift = "DRIFT_TARGET_MISSING"
    elif site_count < family.min_sites:
        result.drift = "DRIFT_REMOVED_SITE"
    elif family.policy == "ALL_DIRECT_CALLERS":
        result.drift = "DRIFT_NONE"
    else:
        result.drift = "DRIFT_NONE"

    # 5. Generate manifest lines
    for s in result.sites:
        # Calculate width: distance to next symbol
        idx = bisect.bisect_right(symtab.addrs, s.caller_addr)
        if idx < len(symtab.addrs):
            next_addr = symtab.addrs[idx]
            width = next_addr - s.caller_addr
        else:
            width = 0x400
        width = max(width, 0x400)  # minimum window
        result.manifest_lines.append(
            f'\t\t{{ "{s.caller_symbol}", KSU_BL_SITE_REQUIRED, '
            f'{len([x for x in result.sites if x.caller_symbol == s.caller_symbol])}, '
            f'{hex(width) if width > 0x400 else "0" } }},'
        )

    return result

# ---------------------------------------------------------------------------
# Family definitions (the project's hook families)
# ---------------------------------------------------------------------------

FAMILIES = [
    HookFamily(
        name="avc/slow_avc_audit",
        target_symbol="slow_avc_audit",
        policy="ALL_DIRECT_CALLERS",
        required=True,
        wrapper_symbol="ksu_do_slow_avc_audit",
        min_sites=7,
    ),
    HookFamily(
        name="permission/inode_permission",
        target_symbol="inode_permission",
        policy="ALL_DIRECT_CALLERS",
        required=True,
        wrapper_symbol="ksu_do_inode_permission",
        min_sites=35,
    ),
    HookFamily(
        name="dpath/d_path",
        target_symbol="d_path",
        policy="ALL_DIRECT_CALLERS",
        required=True,
        wrapper_symbol="ksu_do_dpath",
        min_sites=19,
    ),
]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="BL site discovery analyzer")
    parser.add_argument("--vmlinux", required=True)
    parser.add_argument("--sysmap", required=True)
    parser.add_argument("--output-c", help="Generate C header")
    parser.add_argument("--output-json", help="Generate JSON report")
    args = parser.parse_args()

    # Hash the Image for binding
    image_path = args.vmlinux
    with open(image_path, "rb") as f:
        image_hash = hashlib.sha256(f.read(0x1000000)).hexdigest()[:16]

    print(f"[+] Analyzing {image_path}")
    print(f"[+] Image hash (first 16MB): {image_hash}")

    symtab = read_vmlinux_symbols(args.vmlinux)
    print(f"[+] Loaded {len(symtab.symbols)} function symbols")

    text_addr, text_data = read_text_section(args.vmlinux)
    print(f"[+] .text section: {hex(text_addr)} ({len(text_data)} bytes)")

    results = []
    for family in FAMILIES:
        print(f"\n[+] Family: {family.name}")
        print(f"    Target: {family.target_symbol}")
        print(f"    Policy: {family.policy}")
        r = discover_family(family, symtab, text_addr, text_data)
        results.append(r)
        print(f"    Target found: {r.target_found} @ {hex(r.target_va) if r.target_va else 'N/A'}")
        print(f"    Sites discovered: {len(r.sites)}")
        print(f"    Rejected: {len(r.rejected)}")
        print(f"    Drift: {r.drift}")
        for s in r.sites:
            print(f"      {s.caller_symbol} +0x{s.site_offset:x} -> {family.target_symbol}")

    # Generate outputs
    if args.output_c:
        with open(args.output_c, "w") as f:
            f.write(f"/* AUTO-GENERATED by bl_discover.py -- DO NOT EDIT */\n")
            f.write(f"/* Image hash: {image_hash} */\n\n")
            for r in results:
                if not r.manifest_lines:
                    continue
                f.write(f"/* {r.family.name}: {len(r.sites)} sites, drift={r.drift} */\n")
                for line in r.manifest_lines:
                    f.write(line + "\n")
                f.write("\n")

    if args.output_json:
        data = []
        for r in results:
            data.append({
                "family": r.family.name,
                "target": r.family.target_symbol,
                "target_va": hex(r.target_va) if r.target_va else None,
                "policy": r.family.policy,
                "drift": r.drift,
                "sites": [{
                    "caller": s.caller_symbol,
                    "caller_va": hex(s.caller_addr),
                    "site_va": hex(s.site_va),
                    "site_offset": hex(s.site_offset),
                    "raw": hex(s.raw_instruction),
                } for s in r.sites],
                "rejected": [{"va": hex(va), "reason": reason} for va, reason in r.rejected],
            })
        with open(args.output_json, "w") as f:
            json.dump(data, f, indent=2)

    print(f"\n[+] Analysis complete: {len(results)} families")

if __name__ == "__main__":
    main()
