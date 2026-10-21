#include <linux/bsearch.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/version.h>

#include "compiler_compat.h"
#include "infra/symbol_resolver.h"

// https://github.com/torvalds/linux/commit/89245600941e4e0f87d77f60ee269b5e61ef4e49
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define USE_KCFI 1
#else
#define USE_KCFI 0
#endif

#if !USE_KCFI
static const char cfi_suffix[] = ".cfi_jt";
static const size_t cfi_suffix_len = sizeof(cfi_suffix) - 1;
#endif

// It's not guaranteed to have this symbol exist in 5.x kernel
// https://github.com/torvalds/linux/commit/d721def7392a7348ffb9f3583b264239cbd3702c
// https://github.com/gregkh/linux/commit/2aa861ec72908b4bdc20d74725dc1c8c71a8d214
// https://github.com/gregkh/linux/commit/318a206633c248d876ea72f7133d2a2e50ad7e35
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
#define ALWAYS_HAVE_ON_EACH_SYMBOL 1
#else
#define ALWAYS_HAVE_ON_EACH_SYMBOL 0
#endif

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
static int (*kallsyms_on_each_symbol_fn)(int (*fn)(void *, const char *, struct module *, unsigned long),
                                         void *data) = NULL;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_ON_EACH_MATCH_SYMBOL 1
#else
#define HAVE_ON_EACH_MATCH_SYMBOL 0
#endif

// https://github.com/torvalds/linux/commit/4dc533e0f2c04174e1ae4aa98e7cffc1c04b9998
#if HAVE_ON_EACH_MATCH_SYMBOL
static int (*kallsyms_on_each_match_symbol_fn)(int (*fn)(void *, unsigned long), const char *name, void *data) = NULL;
static int find_kernel_symbol_exact_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 0;
}
#endif

struct ksu_lookup_symbol_ctx {
    const char *symbol_name;
    size_t symbol_len;
    void *match;
};

struct next_symbol_ctx {
    unsigned long addr;
    unsigned long next;
};

static int next_symbol_cb(void *data, const char *name, struct module *mod,
                          unsigned long addr)
{
    struct next_symbol_ctx *ctx = data;

    (void)name;
    (void)mod;
    if (addr > ctx->addr && (!ctx->next || addr < ctx->next))
        ctx->next = addr;
    return 0;
}

unsigned long __nocfi find_kernel_symbol_exact(const char *symbol_name)
{
    unsigned long addr = 0;
#if HAVE_ON_EACH_MATCH_SYMBOL
    if (likely(kallsyms_on_each_match_symbol_fn)) {
        kallsyms_on_each_match_symbol_fn(find_kernel_symbol_exact_cb, symbol_name, &addr);
        return addr;
    }
#endif
    char *module_name = NULL;
    char buf[KSYM_SYMBOL_LEN];

    addr = kallsyms_lookup_name(symbol_name);
    // check if it is kernel symbol
    kallsyms_lookup(addr, NULL, NULL, &module_name, buf);
    if (unlikely(module_name)) {
        pr_warn("ignore symbol %s of module %s\n", symbol_name, module_name);
        return 0;
    }
    return addr;
}

static inline bool ksu_symbol_has_suffix(const char *name, size_t name_len, const char *suffix, size_t suffix_len)
{
    return name_len >= suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int lookup_symbol_variant_cb(void *data, const char *name, unsigned long addr)
#else
static int lookup_symbol_variant_cb(void *data, const char *name, struct module *mod, unsigned long addr)
#endif
{
    struct ksu_lookup_symbol_ctx *ctx = data;
    size_t name_len;

    if (!name || !addr)
        return 0;

    name_len = strlen(name);

    if (strcmp(name, ctx->symbol_name) != 0) {
        if (name_len <= ctx->symbol_len || strncmp(name, ctx->symbol_name, ctx->symbol_len) != 0 ||
            (name[ctx->symbol_len] != '.' && name[ctx->symbol_len] != '$'))
            return 0;
    }

#if !USE_KCFI
    if (ksu_symbol_has_suffix(name, name_len, cfi_suffix, cfi_suffix_len)) {
        ctx->match = (void *)addr;
        pr_info("use .cfi_jt variant: %s\n", name);
        return 1;
    }
#endif

    if (!ctx->match) {
        ctx->match = (void *)addr;
        pr_info("found variant: %s\n", name);
#if USE_KCFI
        return 1;
#endif
    }

    return 0;
}

static __nocfi void *resolve_symbol_variant(const char *symbol_name, size_t symbol_len)
{
    struct ksu_lookup_symbol_ctx ctx = {
        .symbol_name = symbol_name,
        .symbol_len = symbol_len,
    };

#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    if (kallsyms_on_each_symbol_fn) {
        kallsyms_on_each_symbol_fn(lookup_symbol_variant_cb, &ctx);
    }
    // TODO: iterate kallsyms by sprint_symbol
#else
    kallsyms_on_each_symbol(lookup_symbol_variant_cb, &ctx);
#endif
    return ctx.match;
}

void *ksu_resolve_symbol_for_functable_hook(const char *symbol_name)
{
    void *addr;
    size_t symbol_len;

    if (!symbol_name || !symbol_name[0])
        return NULL;

    symbol_len = strlen(symbol_name);

    // Prefer find_kernel_symbol_exact since it uses binary search in higher kernel version

#if !USE_KCFI
    // Try .cfi_jt suffix first
    char cfi_name[KSYM_NAME_LEN];
    snprintf(cfi_name, sizeof(cfi_name), "%s.cfi_jt", symbol_name);
    addr = (void *)find_kernel_symbol_exact(cfi_name);
    if (addr)
        return addr;

    addr = resolve_symbol_variant(symbol_name, symbol_len);
    if (addr)
        return addr;

    return (void *)find_kernel_symbol_exact(symbol_name);
#else
    addr = (void *)find_kernel_symbol_exact(symbol_name);
    if (addr)
        return addr;

    return resolve_symbol_variant(symbol_name, symbol_len);
#endif
}

/*
 * Keep the kernel's kallsyms_on_each_symbol alive: with CONFIG_KPROBES=n no
 * in-tree caller remains, so the linker's --gc-sections would otherwise
 * discard it and symbol enumeration (used by the branch-link whole-text
 * discovery) would fail closed.  Referencing it here is a use of an
 * existing kernel API, not a vendor source modification.
 */
static int ksu_keep_kallsyms_on_each_symbol_cb(void *data, const char *name,
					       struct module *mod,
					       unsigned long addr)
{
	(void)data;
	(void)name;
	(void)mod;
	(void)addr;
	return 0;
}

void __init ksu_init_symbol_resolver()
{
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    /*
     * Invoke the walker once with a no-op callback: this is a real call,
     * not just an address reference, so the compiler cannot discard it and
     * the linker keeps the kernel's kallsyms_on_each_symbol alive even on
     * CONFIG_KPROBES=n builds where nothing else calls it.
     */
    kallsyms_on_each_symbol(ksu_keep_kallsyms_on_each_symbol_cb, NULL);
    kallsyms_on_each_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_symbol");
    if (!kallsyms_on_each_symbol_fn) {
        pr_warn("kallsyms_on_each_symbol not found!\n");
    }
#endif
#if HAVE_ON_EACH_MATCH_SYMBOL
    kallsyms_on_each_match_symbol_fn = find_kernel_symbol_exact("kallsyms_on_each_match_symbol");
    if (!kallsyms_on_each_match_symbol_fn) {
        pr_warn("kallsyms_on_each_match_symbol not found!\n");
    }
#endif
}

/*
 * Find the start address of the next kernel symbol strictly after `addr`.
 * Used to bound branch-site scans at function ends: adjacent syscall
 * wrappers can be packed within the fixed scan window, and an unbounded
 * scan from one wrapper would claim the next wrapper's call sites.
 * Returns 0 when no later symbol exists (or on lookup failure), in which
 * case callers keep their default window.
 */
struct ksu_symbol_walk_ctx {
    int (*fn)(void *, const char *, unsigned long, unsigned long);
    void *data;
};

static int symbol_walk_cb(void *data, const char *name, struct module *mod,
                          unsigned long addr)
{
    struct ksu_symbol_walk_ctx *ctx = data;

    (void)mod;
    return ctx->fn(ctx->data, name, addr, 0);
}

/*
 * Walk every kernel symbol in address order, invoking @fn(name, addr, next)
 * where next is the start of the following symbol (0 for the last one).
 * Returns the callback's first nonzero return value, or 0 when the walk
 * completes.  Uses the on_each_symbol table walk (available on <5.19) or
 * falls back to -ENOSYS on kernels where the table walk was removed --
 * callers must fail closed in that case.
 */
int ksu_walk_kernel_symbols(int (*fn)(void *, const char *, unsigned long,
                                      unsigned long),
                            void *data)
{
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
    struct ksu_symbol_walk_ctx ctx = { .fn = fn, .data = data };
    unsigned long prev = 0;
    int err;

    if (kallsyms_on_each_symbol_fn) {
        err = kallsyms_on_each_symbol_fn(symbol_walk_cb, &ctx);
        return err ? err : 0;
    }
    /* No table walk available: sorted-walk via repeated exact lookups is
     * not practical; report unsupported so callers fail closed. */
    return -ENOSYS;
#else
    struct ksu_symbol_walk_ctx ctx = { .fn = fn, .data = data };
    int err;

    err = kallsyms_on_each_symbol(symbol_walk_cb, &ctx);
    return err ? err : 0;
#endif
}

unsigned long find_kernel_symbol_next_address(unsigned long addr)
{
    struct next_symbol_ctx ctx = { .addr = addr, .next = 0 };

    if (!addr)
        return 0;

#if ALWAYS_HAVE_ON_EACH_SYMBOL
    kallsyms_on_each_symbol(next_symbol_cb, &ctx);
#else
    if (kallsyms_on_each_symbol_fn) {
        kallsyms_on_each_symbol_fn(next_symbol_cb, &ctx);
        if (ctx.next)
            return ctx.next;
    }
    /* Fallback when kallsyms_on_each_symbol is unavailable (e.g. stripped
     * from kallsyms under some configurations): derive the boundary from
     * the symbol's own recorded size.  The scanner bounds at function
     * ends; without this the fixed window overruns into the next packed
     * function and steals its call sites. */
    {
        unsigned long symbolsize = 0;
        unsigned long offset = 0;

        if (kallsyms_lookup_size_offset(addr, &symbolsize, &offset) &&
            symbolsize)
            return addr + symbolsize;
    }
#endif
    return ctx.next;
}

struct ksu_batch_entry {
    const char *name;
    unsigned long addr;
    u32 idx;
};

struct ksu_batch_ctx {
    struct ksu_batch_entry *entries; // sorted by name
    u32 count;
    u32 remaining;
    char key[KSYM_NAME_LEN];
};

static int ksu_batch_entry_cmp(const void *a, const void *b)
{
    return strcmp(((const struct ksu_batch_entry *)a)->name, ((const struct ksu_batch_entry *)b)->name);
}

static int ksu_batch_key_cmp(const void *key, const void *elt)
{
    return strcmp(key, ((const struct ksu_batch_entry *)elt)->name);
}

/*
 * Match one kallsyms entry against the requested names. Same rule as
 * ksuinit's /proc/kallsyms walk: the kernel name is cut at the first '$',
 * else at ".llvm.", and the first match in kallsyms order wins.
 * Returns 1 to stop the walk once every name is resolved.
 */
static int ksu_batch_match(struct ksu_batch_ctx *ctx, const char *name, unsigned long addr)
{
    struct ksu_batch_entry *e, *end = ctx->entries + ctx->count;
    const char *cut, *key = name;
    size_t len;

    if (fatal_signal_pending(current))
        return -EINTR;
    if (!name || !addr)
        return 0;

    cut = strchr(name, '$');
    if (!cut)
        cut = strstr(name, ".llvm.");
    if (cut) {
        len = cut - name;
        if (!len || len >= sizeof(ctx->key))
            return 0;
        memcpy(ctx->key, name, len);
        ctx->key[len] = '\0';
        key = ctx->key;
    }

    e = bsearch(key, ctx->entries, ctx->count, sizeof(*e), ksu_batch_key_cmp);
    if (!e)
        return 0;
    // The same name may be requested more than once.
    while (e > ctx->entries && !strcmp(e[-1].name, key))
        e--;
    for (; e < end && !strcmp(e->name, key); e++) {
        if (!e->addr) {
            e->addr = addr;
            ctx->remaining--;
        }
    }
    return ctx->remaining ? 0 : 1;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
static int ksu_batch_cb(void *data, const char *name, unsigned long addr)
{
    return ksu_batch_match(data, name, addr);
}
#else
static int ksu_batch_cb(void *data, const char *name, struct module *mod, unsigned long addr)
{
    // vmlinux symbols come first; like ksuinit, stop at module symbols.
    if (mod)
        return 1;
    return ksu_batch_match(data, name, addr);
}
#endif

#if HAVE_ON_EACH_MATCH_SYMBOL
// Equal names are ordered by address, i.e. kallsyms order: keep the first.
static int ksu_first_match_cb(void *data, unsigned long addr)
{
    *(unsigned long *)data = addr;
    return 1;
}

// Indexed per-name lookups, which also strip ".llvm." where the kernel does.
static __nocfi int ksu_batch_lookup_indexed(struct ksu_batch_ctx *ctx)
{
    u32 i;

    if (!kallsyms_on_each_match_symbol_fn)
        return 0;
    for (i = 0; i < ctx->count && ctx->remaining; i++) {
        struct ksu_batch_entry *e = &ctx->entries[i];

        if (e->addr)
            continue;
        kallsyms_on_each_match_symbol_fn(ksu_first_match_cb, e->name, &e->addr);
        if (!e->addr)
            continue;
        ctx->remaining--;
        // Duplicate requests share the result.
        while (i + 1 < ctx->count && !strcmp(ctx->entries[i + 1].name, e->name)) {
            ctx->entries[++i].addr = e->addr;
            ctx->remaining--;
        }
        if (fatal_signal_pending(current))
            return -EINTR;
    }
    return 0;
}
#endif

/*
 * Resolve @count kernel image symbols. NULL entries in @names are skipped.
 * @addrs[i] is 0 for names that do not resolve. Returns the number of
 * resolved names, or -errno.
 *
 * 6.1+ kernels index kallsyms by name, so names are looked up one by one
 * there; whatever that misses ('$' suffixes, ".llvm." on 6.12+, unknown
 * names) and every name on older kernels, where a lookup by name is a linear
 * scan, is resolved by a single kallsyms walk.
 */
int __nocfi ksu_lookup_kernel_symbols(const char *const *names, unsigned long *addrs, u32 count)
{
    struct ksu_batch_ctx *ctx;
    int ret = 0;
    u32 i, n = 0;

    ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
    if (!ctx)
        return -ENOMEM;
    ctx->entries = kvmalloc_array(count, sizeof(*ctx->entries), GFP_KERNEL);
    if (!ctx->entries) {
        kfree(ctx);
        return -ENOMEM;
    }

    for (i = 0; i < count; i++) {
        addrs[i] = 0;
        if (!names[i])
            continue;
        ctx->entries[n].name = names[i];
        ctx->entries[n].addr = 0;
        ctx->entries[n].idx = i;
        n++;
    }
    ctx->count = n;
    ctx->remaining = n;
    sort(ctx->entries, n, sizeof(*ctx->entries), ksu_batch_entry_cmp, NULL);

#if HAVE_ON_EACH_MATCH_SYMBOL
    if (n)
        ret = ksu_batch_lookup_indexed(ctx);
#endif

    if (ret >= 0 && ctx->remaining) {
#if !ALWAYS_HAVE_ON_EACH_SYMBOL
        if (kallsyms_on_each_symbol_fn) {
            ret = kallsyms_on_each_symbol_fn(ksu_batch_cb, ctx);
        } else {
            // No kallsyms walker: fall back to exact per-name lookups.
            for (i = 0; i < n; i++) {
                if (ctx->entries[i].addr)
                    continue;
                ctx->entries[i].addr = find_kernel_symbol_exact(ctx->entries[i].name);
                if (fatal_signal_pending(current)) {
                    ret = -EINTR;
                    break;
                }
                cond_resched();
            }
        }
#else
        ret = kallsyms_on_each_symbol(ksu_batch_cb, ctx);
#endif
    }

    if (ret >= 0) {
        ret = 0;
        for (i = 0; i < n; i++) {
            addrs[ctx->entries[i].idx] = ctx->entries[i].addr;
            if (ctx->entries[i].addr)
                ret++;
        }
    }

    kvfree(ctx->entries);
    kfree(ctx);
    return ret;
}
