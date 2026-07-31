#ifndef __KSU_H_SUCOMPAT
#define __KSU_H_SUCOMPAT
#include <asm/ptrace.h>
#include <linux/types.h>

extern bool ksu_su_compat_enabled;
struct cred;
struct filename;

void ksu_sucompat_init(void);
void ksu_sucompat_exit(void);

// Handler functions exported for hook_manager
#ifdef CONFIG_KSU_KPROBES_HOOK
long ksu_handle_faccessat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_stat_sucompat(int orig_nr, struct pt_regs *regs);
long ksu_handle_execve_sucompat(const char __user **filename_user, int orig_nr, struct pt_regs *regs);
#endif
#if !defined(CONFIG_KSU_KPROBES_HOOK) || defined(CONFIG_KSU_HACK_ARM64_BRANCH_LINK)
int ksu_handle_execve(int *fd, const char *filename, void *argv, void *envp, int *flags);
int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr, void *argv, void *envp, int *flags);
#endif
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
const struct cred *ksu_handle_faccessat(int *dfd,
					const char __user **filename_user,
					int *mode, int *flags);
const struct cred *ksu_handle_stat(int *dfd,
				   const char __user **filename_user,
				   int *flags);
const struct cred *ksu_handle_faccessat_su_path(int *dfd,
					const char __user **filename_user,
					int *mode, int *flags);
const struct cred *ksu_handle_stat_su_path(int *dfd,
				   const char __user **filename_user,
				   int *flags);
bool ksu_handle_stat_kernel_filename(char *filename);
#endif

#endif
