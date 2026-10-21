#ifndef __KSU_H_SYSCALL_EVENT_BRIDGE
#define __KSU_H_SYSCALL_EVENT_BRIDGE

#include <asm/ptrace.h>
#include <linux/types.h>

long ksu_hook_newfstatat(int orig_nr, const struct pt_regs *regs);
long ksu_hook_faccessat(int orig_nr, const struct pt_regs *regs);
long ksu_hook_execve(int orig_nr, const struct pt_regs *regs);
long ksu_hook_execveat(int orig_nr, const struct pt_regs *regs);
long ksu_hook_setresuid(int orig_nr, const struct pt_regs *regs);
long ksu_hook_reboot(int orig_nr, const struct pt_regs *regs);

void ksu_stop_ksud_execve_hook(void);
bool ksu_ksud_execve_hook_enabled(void);

#endif // __KSU_H_SYSCALL_EVENT_BRIDGE
