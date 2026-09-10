#!/system/bin/sh
# test_branch_link_inventory.sh — collect branch-link runtime state from
# kallsyms + dmesg, correlate with the seven intended families, and emit
# an explicit READY/NOT-READY/UNKNOWN verdict per family.
#
# Usage: adb shell su -c 'sh /data/local/tmp/bl-tests/test_branch_link_inventory.sh'
# Requires: root (kptr_restrict=0 for kallsyms)

PASS=0; FAIL=0; UNKNOWN=0

echo "=== branch-link inventory ==="

# Lift kptr_restrict for kallsyms reads
OLD_KPTR=$(cat /proc/sys/kernel/kptr_restrict)
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null

# --- Wrapper symbol presence in kallsyms ---
check_sym() {
	if grep -qE " $1\$" /proc/kallsyms 2>/dev/null; then
		echo "  kallsyms: $1 = PRESENT"
	else
		echo "  kallsyms: $1 = MISSING"
	fi
}

echo "--- KSU wrapper symbols ---"
for sym in ksu_do_faccessat ksu_do_readlinkat ksu_vfs_statx \
	ksu_do_sys_open ksu_do_filp_open ksu_do_execve_file \
	ksu_vfs_create_mount ksu_clone_mnt ksu_cleanup_mnt \
	ksu_user_statfs ksu_fd_statfs; do
	check_sym "$sym"
done

# --- Required kernel symbols ---
echo "--- Required kernel helpers ---"
for sym in do_faccessat do_readlinkat vfs_statx user_statfs fd_statfs \
	do_filp_open do_sys_open vfs_getattr_nosec \
	vfs_create_mount clone_mnt cleanup_mnt __do_execve_file; do
	check_sym "$sym"
done

# --- Branch-link readiness from dmesg ---
echo "--- Branch-link readiness (dmesg) ---"
READY_LINE=$(dmesg 2>/dev/null | grep 'branch_link: readiness' | tail -n 1)
echo "$READY_LINE"

# Parse the readiness flags from the log line
READY_LINE_CLEAN=$(echo "$READY_LINE" | sed 's/.*readiness //')

# Extract each field and test
check_ready() {
	local name="$1" val
	val=$(echo "$READY_LINE_CLEAN" | grep -oE "$name=[01]" | head -n 1 | cut -d= -f2)
	if [ "$val" = "1" ]; then
		echo "  READY: $name"
		PASS=$((PASS+1))
	elif [ "$val" = "0" ]; then
		# stat-fd and readlink have explicit fallbacks, so 0 is not fatal
		case "$name" in
			stat-fd)
				echo "  NOT-READY (fallback active): $name"
				UNKNOWN=$((UNKNOWN+1));;
			*)
				echo "  NOT-READY: $name"
				FAIL=$((FAIL+1));;
		esac
	else
		echo "  UNKNOWN: $name (no log entry)"
		UNKNOWN=$((UNKNOWN+1))
	fi
}

check_ready faccess
check_ready readlink
check_ready stat-path
check_ready stat-fd
check_ready statfs
check_ready exec
check_ready mount

# --- Patch site / rollback / conflict check ---
echo "--- Rollback / conflict state ---"
CONFLICTS=$(dmesg 2>/dev/null | grep -ciE 'branch_link.*conflict|branch_link.*restore.*-[1-9]')
ROLLBACKS=$(dmesg 2>/dev/null | grep -ciE 'branch_link.*rollback|branch_link.*restore')
echo "  conflicts: $CONFLICTS"
echo "  restores/rollbacks: $ROLLBACKS"
if [ "$CONFLICTS" -gt 0 ]; then
	echo "  WARN: restore conflicts detected"
	FAIL=$((FAIL+1))
fi

# --- Global state ---
echo "--- Branch-link global state ---"
ACTIVE=$(dmesg 2>/dev/null | grep 'branch_link: readiness' | tail -n 1 | grep -oE '[a-z-]+=[01]' | grep -cE '=[1]')
echo "  families READY: $ACTIVE / 7"
RECORDS=$(echo "$READY_LINE" | grep -oE 'records=[0-9]+' | cut -d= -f2)
echo "  patch records: ${RECORDS:-unknown}"

echo "--- Summary ---"
echo "PASS=$PASS FAIL=$FAIL UNKNOWN=$UNKNOWN"

# Restore kptr_restrict
echo "$OLD_KPTR" > /proc/sys/kernel/kptr_restrict 2>/dev/null
exit 0
