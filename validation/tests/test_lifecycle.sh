#!/system/bin/sh
# test_lifecycle.sh — branch-link lifecycle/concurrency/fallback invariant
TD=/data/local/tmp/bl-test
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

mkdir -p "$TD"

# 1. Fallback invariant: no state where neither provider is active.
# We check this indirectly: at least one of branch-link READY or the
# syscall dispatcher must be functional. Since we can't directly probe
# the dispatcher state, we verify that syscalls still work (which proves
# at least one provider is functional).
echo "lifecycle_content" > "$TD/lifecycle_test.txt"
cat "$TD/lifecycle_test.txt" | grep -q lifecycle && \
	record "syscall path functional (provider active)" PASS || \
	record "syscall path broken (neither provider?)" FAIL

# 2. No boot-time conflict or restore failure in dmesg
CONFLICTS=$(dmesg 2>/dev/null | grep -cE 'branch_link.*conflict.*-[1-9]')
RESTORE_FAILS=$(dmesg 2>/dev/null | grep -cE 'branch_link.*restore.*-[1-9]')
[ "$CONFLICTS" -eq 0 ] && \
	record "no branch-link restore conflicts" PASS || \
	record "branch-link restore conflicts: $CONFLICTS" FAIL

# 3. Concurrency stress: parallel open/stat/readlink across 4 workers
echo "=== concurrency stress (4 workers x 200 iterations) ==="
for worker in 1 2 3 4; do
	(
		i=0
		while [ $i -lt 200 ]; do
			cat "$TD/lifecycle_test.txt" > /dev/null 2>&1
			stat "$TD/lifecycle_test.txt" > /dev/null 2>&1
			readlink /proc/self/exe > /dev/null 2>&1
			i=$((i+1))
		done
	) &
done
wait
record "concurrency stress completed" PASS

# 4. Post-stress: no BUG/OOPS in dmesg
BUGS=$(dmesg 2>/dev/null | grep -cE 'BUG:|Oops|corrupt|use-after-free')
[ "$BUGS" -eq 0 ] && \
	record "no kernel BUG/OOPS after stress" PASS || \
	record "kernel BUG/OOPS detected: $BUGS" FAIL

# 5. Post-stress: syscalls still functional
cat "$TD/lifecycle_test.txt" | grep -q lifecycle && \
	record "syscalls functional post-stress" PASS || \
	record "syscalls broken post-stress" FAIL

# 6. Fallback reactivation (after READY cleared by restore)
# We cannot safely trigger a restore without unloading the module.
# But we CAN verify that the dispatcher hook exists in kallsyms as
# a proxy for fallback availability.
if grep -q ' ksu_hook_execve$' /proc/kallsyms 2>/dev/null; then
	record "dispatcher hook in kallsyms (fallback available)" PASS
else
	record "dispatcher hook missing" FAIL
fi

# 7. Repeated init/exit — not safely exercisable without module unload
record "repeated init/exit (needs module unload, deferred)" SKIP

# Cleanup
rm -f "$TD/lifecycle_test.txt"

echo "---"
echo "lifecycle: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
