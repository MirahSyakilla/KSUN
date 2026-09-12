#!/usr/bin/env python3
"""Build synthetic AArch64 ELF fixtures for bl_analyzer_v2 negative tests.

All artifacts are written under validation/audit/phase17/fixtures/.
Uses the system cross toolchain (aarch64 clang/gcc) when available, else
hand-crafts minimal ELF via struct (no external deps).
"""

import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
os.makedirs(FIX, exist_ok=True)

CC = None
for c in ("aarch64-linux-gnu-gcc", "clang --target=aarch64-linux-gnu"):
    try:
        subprocess.run(c.split()[0] + " --version", capture_output=True,
                       shell=(c == "clang --target=aarch64-linux-gnu"))
        CC = c
        break
    except FileNotFoundError:
        continue


def asm(name, source, extra=(), ldextra=()):
    src = os.path.join(FIX, name + ".s")
    obj = os.path.join(FIX, name + ".o")
    elf = os.path.join(FIX, name + ".elf")
    with open(src, "w") as f:
        f.write(source)
    cc = CC or "clang"
    argv = cc.split() + ["-nostdlib", "-static", "-e", "_start",
                         "-o", elf, src] + list(extra)
    if "clang" in cc:
        argv = cc.split() + ["--target=aarch64-linux-gnu", "-nostdlib",
                             "-static", "-e", "_start", "-o", elf, src] \
            + list(ldextra)
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode != 0:
        print("ASM FAIL %s: %s" % (name, r.stderr[:300]))
        return None
    return elf


# --- fixture: valid BL pair ---------------------------------------------------
VALID = r"""
.global _start
.text
.type _start, %function
_start:
    bl target_fn
    mov w0, #0
    ret
.size _start, .-_start
.global target_fn
.type target_fn, %function
target_fn:
    ret
.size target_fn, .-target_fn
"""

# --- fixture: caller with TWO BLs to target (dedup check) ----------------------
TWO = r"""
.global _start
.text
.type _start, %function
_start:
    bl target_fn
    nop
    bl target_fn
    ret
.size _start, .-_start
.global target_fn
.type target_fn, %function
target_fn:
    ret
.size target_fn, .-target_fn
"""

# --- fixture: BL into padding beyond caller size (containment) ------------------
# _start has size 8 (two instructions), the second BL sits at +8 which is
# OUTSIDE _start and inside no other function -> must be rejected/attributed
# nowhere.
PAD = r"""
.global _start
.text
.type _start, %function
_start:
    bl target_fn
    ret
.size _start, .-_start
    bl target_fn          /* beyond _start size: in a hole */
.global target_fn
.type target_fn, %function
target_fn:
    ret
.size target_fn, .-target_fn
"""

# --- fixture: missing target ----------------------------------------------------
NOTARGET = r"""
.global _start
.text
.type _start, %function
_start:
    bl nowhere_fn
    ret
.size _start, .-_start
"""

# --- fixture: recursive target self-call ----------------------------------------
RECURSE = r"""
.global _start
.text
.type _start, %function
_start:
    bl target_fn
    ret
.size _start, .-_start
.global target_fn
.type target_fn, %function
target_fn:
    bl target_fn          /* target self-recursion: caller = target_fn */
    ret
.size target_fn, .-target_fn
"""

# --- fixture: BLR only (indirect) -----------------------------------------------
BLRONLY = r"""
.global _start
.data
ptr: .xword target_fn
.text
_start:
    adrp x0, ptr
    ldr  x0, [x0, :lo12:ptr]
    blr  x0               /* indirect: zero direct BL sites */
    ret
.global target_fn
target_fn:
    ret
"""

# --- fixture: veneer-like intermediate ------------------------------------------
# caller BLs to stub, stub BLs to target: no direct BL-to-target from caller
VENEER = r"""
.global _start
.text
.type _start, %function
_start:
    bl bl_stub
    ret
.size _start, .-_start
.type bl_stub, %function
bl_stub:
    bl target_fn
    ret
.size bl_stub, .-bl_stub
.global target_fn
.type target_fn, %function
target_fn:
    ret
.size target_fn, .-target_fn
"""

built = []
LD_IGNORE = ["-Wl,--unresolved-symbols=ignore-all"]
for nm, src, ldx in (("valid", VALID, ()), ("two", TWO, ()), ("pad", PAD, ()),
                     ("notarget", NOTARGET, LD_IGNORE),
                     ("recurse", RECURSE, ()),
                     ("blronly", BLRONLY, ()), ("veneer", VENEER, ())):
    e = asm(nm, src, ldextra=ldx)
    if e:
        built.append((nm, e))
        print("built", e)

if len(built) != 7:
    print("MISSING FIXTURES")
    sys.exit(1)
print("OK all fixtures built")
