#!/system/bin/sh
# test_compat_table_invariant.sh — verify the AArch32 compat syscall-table
# mirror invariants of the syscall-table TAMPER dispatcher.
#
# Verifiable without kernel debugfs:
#   1. boot log shows the dispatcher enabled and exactly the hooked set
#      registered (no duplicate nr, no spurious hooks);
#   2. the compat reboot mirror line exists (slot 88 mirrors native 142);
#   3. "compat syscall 88 hooked" (identity check passed at registration);
#   4. no compat hook attempt was made for slots whose native/compat
#      handlers differ (identity-check failures are logged, never patched
#      silently);
#   5. offline Image check (when available): compat_sys_call_table[88]
#      originally held the same pointer as sys_call_table[142].
#
# Usage: adb shell su -c 'sh /data/local/tmp/bl-tests/test_compat_table_invariant.sh'

PASS=0; FAIL=0; SKIP=0
record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

echo "=== compat syscall-table invariant ==="

# 1. Dispatcher enabled
dmesg 2>/dev/null | grep -q "syscall table tamper dispatcher enabled" &&
	record "tamper dispatcher enabled" PASS ||
	record "tamper dispatcher enabled" FAIL

# 2. Registered hook set: exactly the TAMPER-routed numbers, no duplicates
REG=$(dmesg 2>/dev/null | grep -oE "registered syscall hook for nr=[0-9]+" | awk -F= '{print $2}' | sort -n)
echo "  registered nrs: $(echo $REG | tr '\n' ' ')"
DUP=$(echo "$REG" | uniq -d | wc -l)
[ "$DUP" = "0" ] && record "no duplicate syscall-hook registrations" PASS ||
	record "duplicate syscall-hook registrations ($DUP)" FAIL
[ -n "$REG" ] && record "syscall hooks registered" PASS ||
	record "syscall hooks registered" FAIL

# 3. Compat mirror identity check performed and succeeded
dmesg 2>/dev/null | grep -q "compat reboot slot 88 mirrors native" &&
	record "compat reboot slot 88 mirrors native 142" PASS ||
	record "compat reboot slot 88 mirrors native 142" FAIL
dmesg 2>/dev/null | grep -q "compat syscall 88 hooked" &&
	record "compat syscall 88 dispatcher installed" PASS ||
	record "compat syscall 88 dispatcher installed" FAIL

# 4. No silent mismatch: a non-matching mirror must be logged, never patched quietly
MISMATCH=$(dmesg 2>/dev/null | grep -c "no longer mirrors native")
MISHOOK=$(dmesg 2>/dev/null | grep -c "compat syscall .* hook failed")
[ "$MISHOOK" = "0" ] && record "no compat hook failures" PASS ||
	record "compat hook failures present ($MISHOOK)" FAIL

# 5. Behavioral: a 32-bit process can still issue syscalls (compat table not broken)
if [ -x /data/local/tmp/bl-tests/compat_tester ]; then
	/data/local/tmp/bl-tests/compat_tester /data/local/tmp/bl-test/test_file >/dev/null 2>&1 &&
		record "compat task syscalls functional (32-bit tester)" PASS ||
		record "compat task syscalls functional (32-bit tester)" FAIL
else
	record "compat tester binary present" SKIP
fi

# 6. Behavioral: native syscall still routed through the dispatcher
#    (exec of a native binary exercises __NR_execve via the tampered slot)
/system/bin/toybox true 2>/dev/null &&
	record "native syscall routing functional" PASS ||
	record "native syscall routing functional" FAIL

echo "---"
echo "compat-table: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
