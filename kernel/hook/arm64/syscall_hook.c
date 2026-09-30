#ifdef __aarch64__

#include "../syscall_hook.h"

#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <asm/cacheflush.h>
#include "infra/symbol_resolver.h"
#include "../patch_memory.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep

syscall_fn_t *ksu_syscall_table = NULL;
int ksu_dispatcher_nr = -1;

#ifdef CONFIG_COMPAT
/*
 * The AArch32 compat ABI reaches the same handlers through a second table.
 * The old reboot kprobe hooked the shared handler function, so it caught
 * both ABIs; table tampering must hook both slots to preserve that
 * coverage.  Slots are verified by identity before use: a compat entry that
 * does not currently point at the same handler as the native slot is left
 * untouched (the mapping is a profile property, not a contract).
 */
static syscall_fn_t *ksu_compat_syscall_table;
static int ksu_compat_nr_map[__NR_syscalls];

static syscall_fn_t *ksu_compat_table_resolve(void)
{
    return (syscall_fn_t *)ksu_resolve_symbol_for_functable_hook(
        "compat_sys_call_table");
}
#endif

// Hook registration table — read with READ_ONCE from tracepoint/dispatcher
// context, written with WRITE_ONCE from init/exit context.
static ksu_syscall_hook_fn syscall_hooks[__NR_syscalls];

// Track all hooked syscall entries for restoration.
// Protected by hooked_entries_lock.
struct syscall_hook_entry {
    int nr;
    syscall_fn_t orig;
};

static DEFINE_MUTEX(hooked_entries_lock);
static struct syscall_hook_entry hooked_entries[16];
static int hooked_count = 0;

static int patch_syscall_table(int nr, syscall_fn_t fn)
{
    if (ksu_syscall_table == NULL)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;

    pr_info("patch syscall %d, 0x%lx -> 0x%lx\n", nr,
            (unsigned long)READ_ONCE(ksu_syscall_table[nr]), (unsigned long)fn);

    if (ksu_patch_text(&ksu_syscall_table[nr], &fn, sizeof(fn),
                       KSU_PATCH_TEXT_FLUSH_DCACHE)) {
        pr_err("patch syscall %d failed\n", nr);
        return -EIO;
    }

    return 0;
}

// Direct syscall table patching: overwrite syscall_table[nr] with fn,
// save original to *old, and record for restoration at module exit.
int ksu_syscall_table_hook(int nr, syscall_fn_t fn, syscall_fn_t *old)
{
    syscall_fn_t orig;
    int i, ret, new_index = -1;

    if (ksu_syscall_table == NULL)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls) {
        pr_info("invalid nr: %d\n", nr);
        return -EINVAL;
    }

    mutex_lock(&hooked_entries_lock);

    orig = READ_ONCE(ksu_syscall_table[nr]);

    // Record for later restoration
    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            orig = hooked_entries[i].orig;
            break;
        }
    }
    if (i == hooked_count) {
        if (hooked_count < ARRAY_SIZE(hooked_entries)) {
            new_index = hooked_count;
            hooked_entries[new_index].nr = nr;
            hooked_entries[new_index].orig = orig;
            hooked_count++;
        } else {
            pr_warn(
                "hooked_entries full, cannot track syscall %d for restoration\n",
                nr);
            mutex_unlock(&hooked_entries_lock);
            return -ENOSPC;
        }
    }

    if (old)
        *old = orig;

    ret = patch_syscall_table(nr, fn);
    if (ret && new_index >= 0)
        hooked_entries[new_index] = hooked_entries[--hooked_count];
    mutex_unlock(&hooked_entries_lock);
    return ret;
}

// Restore syscall_table[nr] to its original value and remove from tracking list.
int ksu_syscall_table_unhook(int nr)
{
    int i;
    int ret = -ENOENT;

    if (ksu_syscall_table == NULL)
        return -ENOENT;
    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;

    mutex_lock(&hooked_entries_lock);

    for (i = 0; i < hooked_count; i++) {
        if (hooked_entries[i].nr == nr) {
            ret = patch_syscall_table(nr, hooked_entries[i].orig);
            // Remove entry by swapping with last
            if (!ret)
                hooked_entries[i] = hooked_entries[--hooked_count];
            mutex_unlock(&hooked_entries_lock);
            if (!ret)
                pr_info("unhooked syscall %d\n", nr);
            return ret;
        }
    }

    mutex_unlock(&hooked_entries_lock);
    pr_warn("syscall %d not found in hooked entries\n", nr);
    return ret;
}

syscall_fn_t ksu_get_syscall_invoke_target(int nr)
{
    int i, count;

    if (!ksu_syscall_table || nr < 0 || nr >= __NR_syscalls)
        return NULL;

    count = READ_ONCE(hooked_count);
    for (i = 0; i < count && i < ARRAY_SIZE(hooked_entries); i++) {
        if (READ_ONCE(hooked_entries[i].nr) == nr)
            return READ_ONCE(hooked_entries[i].orig);
    }

    return READ_ONCE(ksu_syscall_table[nr]);
}

static int __init ksu_find_ni_syscall_slots(int *out_slots, int max_slots)
{
    unsigned long ni_syscall;
    int i, count = 0;

    if (!ksu_syscall_table || max_slots <= 0)
        return 0;

    ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook(
        "__arm64_sys_ni_syscall");
    if (!ni_syscall)
        ni_syscall = (unsigned long)ksu_resolve_symbol_for_functable_hook(
            "sys_ni_syscall");

    pr_info("sys_ni_syscall: 0x%lx\n", ni_syscall);

    if (!ni_syscall)
        return 0;

    for (i = 0; i < __NR_syscalls && count < max_slots; i++) {
        if ((unsigned long)ksu_syscall_table[i] == ni_syscall) {
            out_slots[count++] = i;
            pr_info("ni_syscall %d: %d\n", count, i);
        }
    }

    return count;
}

// Unified dispatcher: reads original NR from x8/orig_ax, dispatches to handler.
// Validates that syscallno matches our dispatcher slot (i.e. we redirected it),
// otherwise it's a spurious call — return -ENOSYS.
static long __nocfi ksu_dispatch_syscall(const struct pt_regs *regs)
{
    int orig_nr;

    if (regs->syscallno != ksu_dispatcher_nr)
        return -ENOSYS;

    orig_nr = (int)PT_REGS_ORIG_SYSCALL(regs);

    if (regs->syscallno == orig_nr)
        return -ENOSYS;

    // Restore registers to original state before dispatching
    ((struct pt_regs *)regs)->syscallno = orig_nr;
    PT_REGS_ORIG_SYSCALL((struct pt_regs *)regs) = orig_nr;

    if (likely(orig_nr >= 0 && orig_nr < __NR_syscalls)) {
        ksu_syscall_hook_fn fn = READ_ONCE(syscall_hooks[orig_nr]);
        if (likely(fn))
            return fn(orig_nr, regs);
    }

    return -ENOSYS;
}

static long __nocfi ksu_syscall_dispatcher(KSU_SYSCALL_WRAPPER_ARGS)
{
    return ksu_dispatch_syscall(KSU_SYSCALL_WRAPPER_REGS());
}

#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
static long __nocfi ksu_direct_syscall_dispatcher(KSU_SYSCALL_WRAPPER_ARGS)
{
    const struct pt_regs *call_regs = KSU_SYSCALL_WRAPPER_REGS();
    int orig_nr = call_regs->syscallno;

    if (orig_nr < 0 || orig_nr >= __NR_syscalls)
        orig_nr = (int)PT_REGS_ORIG_SYSCALL(call_regs);

#ifdef CONFIG_COMPAT
    /* Compat tasks carry the AArch32 number; hooks are keyed by the
     * native number.  Translate through the verified compat map. */
    if (unlikely(is_compat_task()) && orig_nr >= 0 &&
        orig_nr < __NR_syscalls) {
        int mapped = READ_ONCE(ksu_compat_nr_map[orig_nr]);

        if (mapped >= 0)
            orig_nr = mapped;
        else
            return -ENOSYS;
    }
#endif

    if (likely(orig_nr >= 0 && orig_nr < __NR_syscalls)) {
        ksu_syscall_hook_fn fn = READ_ONCE(syscall_hooks[orig_nr]);
        if (likely(fn))
            return fn(orig_nr, call_regs);
    }

    return -ENOSYS;
}
#endif

// Register a handler into the dispatcher's routing table.
// Does not modify the syscall table — the dispatcher slot is shared by all hooks.
/*
 * Find the AArch32 slot a 32-bit caller of native syscall @nr lands on.
 *
 * The map built at init only carries the calls whose two tables point at
 * different handlers, so a "common" call listed in arch/arm/tools/syscall.tbl
 * without an oabi column - getpriority and setpriority among them - is reached
 * through one shared handler from both tables and never gets a map entry.
 * Those are found by identity rather than by a hardcoded AArch32 number: the
 * compat entry pointing at the same handler is the one a 32-bit caller
 * reaches.  This is the same table-and-kallsyms basis the rest of this file
 * uses; nothing here installs a probe or a call-site patch.
 *
 * A shared handler is only accepted when it is unambiguous.  If the compat
 * table offers no such slot, or more than one, nothing is found and the
 * syscall stays native-only rather than have a slot guessed at.
 */
static int ksu_compat_find_shared_slot(int nr)
{
    syscall_fn_t want = ksu_get_syscall_invoke_target(nr);
    int found = -1;
    int i;

    if (!ksu_compat_syscall_table || !want)
        return -1;

    for (i = 0; i < __NR_syscalls; i++) {
        if (READ_ONCE(ksu_compat_syscall_table[i]) != want)
            continue;
        if (found >= 0)
            return -1;
        found = i;
    }

    return found;
}

int ksu_register_syscall_hook(int nr, ksu_syscall_hook_fn fn)
{
    int ret = 0;

    if (nr < 0 || nr >= __NR_syscalls)
        return -EINVAL;
    if (READ_ONCE(syscall_hooks[nr])) {
        pr_warn("syscall hook for nr=%d already registered, skip\n", nr);
        return -EEXIST;
    }
    WRITE_ONCE(syscall_hooks[nr], fn);
#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
    ret = ksu_syscall_table_hook(nr,
                                 (syscall_fn_t)ksu_direct_syscall_dispatcher,
                                 NULL);
    if (ret) {
        WRITE_ONCE(syscall_hooks[nr], NULL);
        return ret;
    }
#ifdef CONFIG_COMPAT
    /* Compat mirror: when the compat table's slot currently points at the
     * same handler as the native slot did, replace it too so 32-bit
     * callers take the same hook route.  The map is keyed compat→native
     * (the dispatcher's translation direction); at registration time the
     * compat slot for a native nr is found by scanning the (tiny) map. */
    if (ksu_compat_syscall_table && nr >= 0 && nr < __NR_syscalls) {
        int compat_nr = -1;
        int i;

        for (i = 0; i < __NR_syscalls; i++) {
            if (READ_ONCE(ksu_compat_nr_map[i]) == nr) {
                compat_nr = i;
                break;
            }
        }

        if (compat_nr < 0) {
            /*
             * No init-time entry for this syscall: discover the compat slot
             * by the shared handler and record it, so hooking a second
             * syscall that resolves to the same slot does not search again.
             */
            compat_nr = ksu_compat_find_shared_slot(nr);
            if (compat_nr >= 0)
                WRITE_ONCE(ksu_compat_nr_map[compat_nr], nr);
        }

        if (compat_nr >= 0) {
            syscall_fn_t native_orig = ksu_get_syscall_invoke_target(nr);
            syscall_fn_t compat_cur =
                READ_ONCE(ksu_compat_syscall_table[compat_nr]);

            if (compat_cur == native_orig) {
                if (ksu_patch_text(
                        &ksu_compat_syscall_table[compat_nr],
                        &(syscall_fn_t){ (syscall_fn_t)
                                            ksu_direct_syscall_dispatcher },
                        sizeof(syscall_fn_t),
                        KSU_PATCH_TEXT_FLUSH_DCACHE))
                    pr_warn("compat syscall %d hook failed\n", compat_nr);
                else
                    pr_info("compat syscall %d hooked\n", compat_nr);
            } else {
                pr_info("compat slot %d no longer mirrors native %d; "
                        "not hooked\n", compat_nr, nr);
            }
        }
    }
#endif
#endif
    pr_info("registered syscall hook for nr=%d\n", nr);
    return ret;
}

// Remove a handler from the dispatcher's routing table.
// The syscall table is not touched — only the dispatcher stops routing this nr.
void ksu_unregister_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return;
#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
    if (READ_ONCE(syscall_hooks[nr]))
        ksu_syscall_table_unhook(nr);
#endif
    WRITE_ONCE(syscall_hooks[nr], NULL);
    pr_info("unregistered syscall hook for nr=%d\n", nr);
}

bool ksu_has_syscall_hook(int nr)
{
    if (nr < 0 || nr >= __NR_syscalls)
        return false;
    return READ_ONCE(syscall_hooks[nr]) != NULL;
}

void __init ksu_syscall_hook_init(void)
{
#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
    int ni_slot;
#endif

    memset(syscall_hooks, 0, sizeof(syscall_hooks));

    ksu_syscall_table = (syscall_fn_t *)ksu_resolve_symbol_for_functable_hook("sys_call_table");
    pr_info("sys_call_table=0x%lx", (unsigned long)ksu_syscall_table);

    if (!ksu_syscall_table)
        return;

#ifndef CONFIG_KSU_TAMPER_SYSCALL_TABLE
    // Find one ni_syscall slot for the dispatcher
    if (ksu_find_ni_syscall_slots(&ni_slot, 1) < 1) {
        pr_err("failed to find ni_syscall slot for dispatcher\n");
        return;
    }

    ksu_dispatcher_nr = ni_slot;
    ksu_syscall_table_hook(ksu_dispatcher_nr,
                           (syscall_fn_t)ksu_syscall_dispatcher, NULL);
    pr_info("dispatcher installed at slot %d\n", ksu_dispatcher_nr);
#else
    pr_info("syscall table tamper dispatcher enabled\n");
#endif

#ifdef CONFIG_COMPAT
#ifdef CONFIG_KSU_TAMPER_SYSCALL_TABLE
    /* The dispatcher must translate compat syscall numbers: a compat task
     * enters with the AArch32 number, while hooks and the native table
     * are keyed by the native number. */
    ksu_compat_syscall_table = ksu_compat_table_resolve();
    memset(ksu_compat_nr_map, 0xff, sizeof(ksu_compat_nr_map));
    if (ksu_compat_syscall_table) {
        /* AArch32 reboot is nr 88 (asm/unistd32.h); reboot has no
         * separate compat wrapper, so both tables point at the same
         * __arm64_sys_reboot — verified against the shipped table. */
        const int compat_reboot_nr = 88;

        if (compat_reboot_nr >= 0 &&
            compat_reboot_nr < __NR_syscalls) {
            syscall_fn_t native = READ_ONCE(
                ksu_syscall_table[__NR_reboot]);
            syscall_fn_t compat =
                READ_ONCE(ksu_compat_syscall_table[compat_reboot_nr]);

            if (native == compat) {
                /* Key compat→native: the dispatcher receives the AArch32
                 * number and must translate to the native hook index. */
                ksu_compat_nr_map[compat_reboot_nr] = __NR_reboot;
                pr_info("compat reboot slot %d mirrors native\n",
                        compat_reboot_nr);
            }
        }
    }
#endif
#endif
}

void __exit ksu_syscall_hook_exit(void)
{
    int i;

    if (!ksu_syscall_table)
        goto clear_state;

    // First, restore all patched syscall table entries while the dispatcher
    // and hook table are still intact, so in-flight syscalls see valid state.
    mutex_lock(&hooked_entries_lock);
    for (i = 0; i < hooked_count; i++) {
        int nr = hooked_entries[i].nr;
        syscall_fn_t orig = hooked_entries[i].orig;

        pr_info("restore syscall %d to 0x%lx\n", nr, (unsigned long)orig);
        if (ksu_patch_text(&ksu_syscall_table[nr], &orig, sizeof(orig),
                           KSU_PATCH_TEXT_FLUSH_DCACHE)) {
            pr_err("restore syscall %d failed\n", nr);
        }
    }
    hooked_count = 0;
    mutex_unlock(&hooked_entries_lock);

clear_state:
    // Now that the syscall table is restored, clear internal state.
    // At this point the tracepoint is already unregistered and synchronized
    // (done by ksu_syscall_hook_manager_exit before calling us), so no new
    // dispatches will occur.
    memset(syscall_hooks, 0, sizeof(syscall_hooks));
    ksu_dispatcher_nr = -1;

    pr_info("all syscall hooks restored\n");
}

#endif /* __aarch64__ */
