#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>
#include "runtime/ksud.h"

#ifdef CONFIG_KSU_HOOK_CORE
long ksu_adb_root_handle_execve(struct pt_regs *regs);
#endif
#if !defined(CONFIG_KSU_HOOK_CORE) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
long ksu_adb_root_handle_execveat(const char *filename,
				  struct user_arg_ptr *envp);
#endif

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif
