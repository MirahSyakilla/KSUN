#ifndef __KSU_H_EXECMEM_COMPAT
#define __KSU_H_EXECMEM_COMPAT

#ifdef CONFIG_KSU_KPROBES_HOOK
void ksu_execmem_compat_init(void);
void ksu_execmem_compat_exit(void);
void ksu_execmem_compat_refresh(void);
#else
static inline void ksu_execmem_compat_init(void) { }
static inline void ksu_execmem_compat_exit(void) { }
static inline void ksu_execmem_compat_refresh(void) { }
#endif

#endif /* __KSU_H_EXECMEM_COMPAT */
