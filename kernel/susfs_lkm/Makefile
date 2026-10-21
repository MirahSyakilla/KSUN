# susfs_guard_lkm - SUSFS loadable kernel module (LKM)
#
# This is upstream KernelSU-Next's SUSFS implementation, kept VERBATIM under
# kernel/susfs_lkm/ and built as a standalone external kbuild module.  It is an
# ALTERNATIVE to this fork's in-tree hookless SUSFS (kernel/susfs/, compiled
# into kernelsu.ko under CONFIG_KSU_HOOKLESS_SUSFS) - the two are mutually
# exclusive, see kernel/Kconfig (CONFIG_KSU_SUSFS_LKM) and kernel/Kbuild.
#
# The module is self-contained: it includes no KernelSU header and imports no
# KernelSU symbol.  The two KernelSU entry points it wants
# (__ksu_is_allow_uid_for_current and ksu_uid_should_umount) are looked up BY
# NAME through kallsyms at load time (ksu_allow_gate.c / ksu_umount_gate.c),
# and every kernel symbol it needs is resolved the same way by
# kernel/symbol_resolver.c.
#
# Build against a prepared kernel tree (the same image that builds kernelsu.ko):
#   make -C $KDIR M=$PWD ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
#
# Only the shipping module is built, and this objs list is the whole of it: the probe/test
# modules that were used while working the hooks out are not in this tree any more.

obj-m += susfs_guard_lkm.o

susfs_guard_lkm-objs := susfs_main.o patch_memory.o symbol_resolver.o lsm_hook.o \
              susfs_uname.o susfs_kstat.o sus_map.o sus_path.o sus_mount.o \
              spoof_cmdline.o susfs_open_redirect.o susfs_enable_log.o \
              susfs_avc_spoof.o susfs_supercall.o susfs_hide_syms.o imports_guard.o \
              ksu_umount_gate.o ksu_allow_gate.o susfs_fp_hook.o susfs_opath.o susfs_or_entry.o \
              fsnotify_lifetime.o btf_layout.o sus_dirent.o

# The dcache/icache flush helper is NOT picked at build time any more: which spelling a kernel
# carries is not decided by its version number (a vendor kernel can keep the pre-5.14 name, measured
# on a Samsung 5.x kernel), so kernel/patch_memory.c resolves it by name at run time.  Building with
# 5.14+ headers used to leave an undefined dcache_clean_inval_poc that such a kernel then refused to
# resolve, i.e. the module could not load at all.
#
# `srctree` is set only when kbuild reaches this file (make -C $KDIR M=$PWD ...).  The check for
# it used to be a parse-time $(error), which aborted make before any goal was chosen and so made
# the `all:` entry point below - and KDIR's default - unreachable.  It now lives in the `all:`
# recipe, i.e. it fires when the build is actually attempted.
KSU_SRCTREE_MISSING := $(if $(srctree),0,1)

# Match SukiSU's build flags: upstream code declares after statements and
# casts symbol addresses (unsigned long) to function pointers.
ccflags-y += -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat -Wno-missing-prototypes
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function -Wno-unused-variable

# fs/mount.h (struct mount + real_mount) is a private header; its includes are
# all public, so -I$(srctree)/fs is enough to reach it via #include "mount.h".
ccflags-y += -I$(srctree)/fs

# Stack protector: arm64 got its per-task canary (read from sp_el0, no symbol involved) in 5.11,
# and the module inherits the kernel's mode.  Below that the kernel uses the global
# __stack_chk_guard, which the module then references - and that is the name `ksud insmod` cannot
# resolve (its kallsyms walk stops at the first record that is not three fields, while the bundled
# susfs_insmod reads the file to the end and does find it), so the load dies with
# "Unknown symbol __stack_chk_guard".  Nothing is lost where the kernel predates the canary: the
# guard would only protect this module's own stack.
KSU_KERNEL_HAS_PER_TASK_GUARD := $(shell [ "$(VERSION)" -gt 5 ] && echo yes)
ifeq ($(VERSION),5)
KSU_KERNEL_HAS_PER_TASK_GUARD := $(shell [ "$(PATCHLEVEL)" -ge 11 ] && echo yes)
endif
ifneq ($(KSU_KERNEL_HAS_PER_TASK_GUARD),yes)
ccflags-y += -fno-stack-protector
endif

# SELinux private headers are not needed: the LSM layer reaches SELinux through the live
# security_hook_heads / static_calls_table (see kernel/lsm_hook.c), not through ss/ or flask.h,
# so the -I lines that used to sit here "for when the feature lands" are gone with it.

# This fork's hookless SUSFS (CONFIG_KSU_HOOKLESS_SUSFS) and this module implement the SAME
# feature on the SAME hooks (the reboot supercall, the LSM slot patcher, the kstat/statx probes).
# Both being live at once is a conflict, not a redundancy.  Kconfig already refuses to let both be
# selected (KSU_HOOKLESS_SUSFS depends on !KSU_SUSFS_LKM) and kernel/Kbuild fails the in-tree
# build if a hand-edited .config ends up with both; this is the third net, for the case where the
# module is built against a kernel tree whose config differs from the running one.
#
# It is a warning and not an error because the module is built OUT of tree: the kernel it is
# compiled against is not necessarily the kernel it is loaded on, and the running kernel is what
# decides.  The running kernel is checked at load time instead - `ksud susfs load` refuses to
# load the module while this fork's hookless SUSFS answers the SUSFS supercall.
ifneq ($(CONFIG_KSU_HOOKLESS_SUSFS),)
$(warning CONFIG_KSU_HOOKLESS_SUSFS=y in the kernel this module is built against: the in-tree hookless SUSFS and susfs_guard_lkm are alternatives, not a pair. Only one of them may be live on the device.)
endif

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
ifeq ($(KSU_SRCTREE_MISSING),1)
	@echo "srctree is not set - build this module through kbuild: make -C \$${KDIR} M=\$${PWD} modules" >&2
	@exit 1
else
	$(MAKE) -C $(KDIR) M=$(PWD) modules
endif

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
