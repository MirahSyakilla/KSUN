#ifndef __KSU_SYMBOL_RESOLVER_H
#define __KSU_SYMBOL_RESOLVER_H

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name);
unsigned long find_kernel_symbol_exact(const char *symbol_name);
void ksu_init_symbol_resolver();

#endif
unsigned long find_kernel_symbol_next_address(unsigned long addr);
int ksu_walk_kernel_symbols(int (*fn)(void *, const char *, unsigned long,
                                      unsigned long),
                            void *data);
