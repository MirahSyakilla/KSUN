#!/usr/bin/env bash
# Build the SUSFS guard LKM (susfs_guard_lkm.ko) for arm64.
#
# The module lives in kernel/susfs_lkm/ and is upstream KernelSU-Next's SUSFS
# implementation, built here as a standalone external kbuild module.  It is an
# ALTERNATIVE to this fork's in-tree hookless SUSFS (kernel/susfs/, compiled
# into kernelsu.ko under CONFIG_KSU_HOOKLESS_SUSFS) - the two are mutually
# exclusive, see kernel/Kconfig (CONFIG_KSU_SUSFS_LKM).
#
# The module is loaded through a loader that resolves its imports from
# /proc/kallsyms before init_module() (`ksud insmod`, `ksud susfs load`), so a
# plain `insmod` is not enough - see kernel/susfs_lkm/imports_guard.c.
#
# Usage: build_susfs_lkm.sh [kernel-source-dir]
#
# The kernel source dir is taken from (in order):
#   $KDIR, the first argument, the repository's parent directory when that
#   parent is a kernel tree, $HOME/lisa_kernel, /lib/modules/$(uname -r)/build.
#
# The compiler is the ZyC clang in $TOOLCHAIN_HOME (default $HOME/bin/zyc-clang):
# the module carries the kernel's symbol CRCs, so it has to be built with the
# same compiler the kernel was built with.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODULE_DIR="${REPO_DIR}/kernel/susfs_lkm"
MODULE_NAME="susfs_guard_lkm"

ARCH=arm64
JOBS="$(nproc 2>/dev/null || echo 4)"

# ---------------------------------------------------------------- toolchain --
TOOLCHAIN_HOME="${TOOLCHAIN_HOME:-$HOME/bin/zyc-clang}"
if [ -x "${TOOLCHAIN_HOME}/bin/clang" ]; then
    CLANG_BIN="${TOOLCHAIN_HOME}/bin"
elif command -v clang >/dev/null 2>&1; then
    CLANG_BIN="$(dirname "$(command -v clang)")"
else
    echo "error: no clang found; set TOOLCHAIN_HOME to the toolchain directory" >&2
    exit 1
fi
export PATH="${CLANG_BIN}:${PATH}"

# ------------------------------------------------------------- kernel tree --
# A kernel tree looks like a directory with a top-level Makefile and an arch/
# directory; anything else is not one.
is_kernel_tree() {
    [ -f "$1/Makefile" ] && [ -d "$1/arch" ]
}

KDIR="${KDIR:-${1:-}}"
if [ -z "${KDIR}" ]; then
    # The repository usually lives inside the kernel tree it is built for.
    if is_kernel_tree "$(dirname "${REPO_DIR}")"; then
        KDIR="$(dirname "${REPO_DIR}")"
    elif is_kernel_tree "${HOME}/lisa_kernel"; then
        KDIR="${HOME}/lisa_kernel"
    elif is_kernel_tree "/lib/modules/$(uname -r)/build"; then
        KDIR="/lib/modules/$(uname -r)/build"
    else
        echo "error: no kernel tree found; pass one as an argument or set KDIR" >&2
        exit 1
    fi
fi

if ! is_kernel_tree "${KDIR}"; then
    echo "error: ${KDIR} is not a kernel tree (no Makefile/arch)" >&2
    exit 1
fi
KDIR="$(cd "${KDIR}" && pwd)"

# Out-of-tree builds keep the generated headers and Module.symvers in a separate
# output directory; use it when the tree has one, so the module is compiled
# against the headers the kernel was actually built with.
OBJ_ARGS=()
OBJTREE="${KDIR}"
if [ ! -f "${KDIR}/.config" ] && [ -f "${KDIR}/out/.config" ]; then
    OBJTREE="${KDIR}/out"
    OBJ_ARGS=("O=${OBJTREE}")
fi

if [ ! -f "${OBJTREE}/.config" ]; then
    echo "error: ${KDIR} has no kernel configuration (.config, or out/.config for an" >&2
    echo "       O= build).  The module is compiled against the headers the kernel" >&2
    echo "       was built with, so the tree has to be configured and built first:" >&2
    echo "         make -C ${KDIR} O=${OBJTREE} ARCH=arm64 LLVM=1 LLVM_IAS=1 olddefconfig" >&2
    echo "         make -C ${KDIR} O=${OBJTREE} ARCH=arm64 LLVM=1 LLVM_IAS=1 modules" >&2
    exit 1
fi

# ------------------------------------------------------- build prerequisites --
# The kernel build writes scripts/module.lds into the output directory.  Some
# trees (a "dist" build, or one that was cleaned) do not have it, and the
# module link then fails with "No rule to make target 'scripts/module.lds'".
# Generate it the same way the kernel does: preprocess scripts/module.lds.S.
if [ ! -f "${OBJTREE}/scripts/module.lds" ] && [ -f "${KDIR}/scripts/module.lds.S" ]; then
    echo "generating ${OBJTREE}/scripts/module.lds"
    mkdir -p "${OBJTREE}/scripts"
    clang -E -D__KERNEL__ \
        -I"${KDIR}/arch/${ARCH}/include" \
        -I"${OBJTREE}/arch/${ARCH}/include/generated" \
        -I"${KDIR}/include" \
        -I"${OBJTREE}/include" \
        -I"${KDIR}/arch/${ARCH}/include/uapi" \
        -I"${OBJTREE}/arch/${ARCH}/include/generated/uapi" \
        -I"${KDIR}/include/uapi" \
        -I"${OBJTREE}/include/generated/uapi" \
        -include "${KDIR}/include/linux/compiler-version.h" \
        -include "${KDIR}/include/linux/kconfig.h" \
        -P -U"${ARCH}" -D__ASSEMBLY__ -DLINKER_SCRIPT \
        -o "${OBJTREE}/scripts/module.lds" \
        "${KDIR}/scripts/module.lds.S"
fi

# modversions: the module has to carry the CRCs of the kernel it is loaded on,
# and they come from the kernel's own Module.symvers.  A tree that only has
# vmlinux.symvers (a kernel with no in-tree modules) is the same table.
if [ ! -f "${OBJTREE}/Module.symvers" ] && [ -f "${OBJTREE}/vmlinux.symvers" ]; then
    echo "staging ${OBJTREE}/Module.symvers from vmlinux.symvers"
    cp "${OBJTREE}/vmlinux.symvers" "${OBJTREE}/Module.symvers"
fi

# ------------------------------------------------------------------- build --
# KBUILD_MODPOST_WARN=1: this module imports a handful of kernel symbols the
# kernel does not export (saved_boot_config, task_work_add, init_mm,
# copy_to_kernel_nofault, __set_fixmap).  That is by design - they are resolved
# from /proc/kallsyms by the loader, and imports_guard.c refuses the load if
# any of them did not get a real kernel address.  modpost would otherwise abort
# the build on them.
echo "building ${MODULE_NAME}.ko"
echo "  kernel:   ${KDIR}${OBJ_ARGS[*]:+ ${OBJ_ARGS[*]}}"
echo "  module:   ${MODULE_DIR}"
echo "  compiler: $("${CLANG_BIN}/clang" --version | head -1)"

make -C "${KDIR}" \
    M="${MODULE_DIR}" \
    "${OBJ_ARGS[@]}" \
    ARCH="${ARCH}" \
    CC=clang \
    LD=ld.lld \
    LLVM=1 \
    LLVM_IAS=1 \
    KBUILD_MODPOST_WARN=1 \
    modules -j"${JOBS}"

KO="${MODULE_DIR}/${MODULE_NAME}.ko"
if [ ! -f "${KO}" ]; then
    echo "error: ${KO} was not produced" >&2
    exit 1
fi

echo "built ${KO} ($(stat -c%s "${KO}") bytes)"
