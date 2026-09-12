#!/system/bin/sh
# test_avc_spoof.sh — AVC audit-log spoofing (hookless BL) regression tests.
# Verifies feature lifecycle, branch-link family readiness, CONFIG_AUDIT
# audit-path presence, and absence of probe machinery — without relying on
# a single hardcoded log string for the pass/fail decision.

PASS=0; FAIL=0; SKIP=0
record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

KSUD=/data/adb/ksu/bin/ksud
echo "=== avc_spoof (hookless BL) ==="

# 1. family readiness from boot log
dmesg 2>/dev/null | grep -q "branch_link: avc profile" &&
	record "avc branch-link family installed" PASS ||
	record "avc branch-link family installed" FAIL
dmesg 2>/dev/null | grep -E "avc profile" | grep -q "family=7/7" &&
	record "avc family 7/7 sites committed" PASS ||
	record "avc family 7/7 sites committed (see dmesg)" FAIL

# 2. CONFIG_AUDIT=y audit path: kernel emits type=1400 audit records
dmesg 2>/dev/null | grep -q "type=1400" &&
	record "audit records present (CONFIG_AUDIT=y path live)" PASS ||
	record "audit records present (CONFIG_AUDIT=y path live)" FAIL

# 3. feature lifecycle via ksud (ID 10003)
if [ -x "$KSUD" ]; then
	STATE1=$("$KSUD" feature get 10003 2>/dev/null | grep Value | awk '{print $2}')
	"$KSUD" feature set 10003 0 >/dev/null 2>&1
	STATE2=$("$KSUD" feature get 10003 2>/dev/null | grep Value | awk '{print $2}')
	"$KSUD" feature set 10003 1 >/dev/null 2>&1
	STATE3=$("$KSUD" feature get 10003 2>/dev/null | grep Value | awk '{print $2}')
	[ "$STATE1" = "1" ] && record "avc_spoof enabled by default" PASS ||
		record "avc_spoof default state ($STATE1)" FAIL
	[ "$STATE2" = "0" ] && record "avc_spoof disable accepted" PASS ||
		record "avc_spoof disable ($STATE2)" FAIL
	[ "$STATE3" = "1" ] && record "avc_spoof re-enable accepted" PASS ||
		record "avc_spoof re-enable ($STATE3)" FAIL
	dmesg 2>/dev/null | grep -q "hookless slow_avc_audit spoofing armed" &&
		record "hookless arming message present" PASS ||
		record "hookless arming message present" FAIL
else
	record "ksud present" SKIP
fi

# 4. no probe registration attributable to AVC
dmesg 2>/dev/null | grep -q "register_slow_avc_audit kprobe: 0" &&
	record "no kprobe registration for AVC" FAIL ||
	record "no kprobe registration for AVC" PASS

# 5. repeated/concurrent invocation: trigger AVCs concurrently
(
	i=0; while [ $i -lt 20 ]; do
		cat /proc/net/unix >/dev/null 2>&1
		cat /proc/self/mountinfo >/dev/null 2>&1
		i=$((i+1))
	done
) &
(
	i=0; while [ $i -lt 20 ]; do
		cat /proc/net/tcp >/dev/null 2>&1
		i=$((i+1))
	done
) &
wait
record "concurrent AVC-generating syscalls completed" PASS
dmesg 2>/dev/null | tail -300 | grep -qE "BUG|Oops" &&
	record "no kernel BUG/OOPS" FAIL ||
	record "no kernel BUG/OOPS" PASS

# 6. enforcement unchanged: getenforce must still be Enforcing after toggle churn
[ "$(getenforce 2>/dev/null)" = "Enforcing" ] &&
	record "SELinux enforcing preserved" PASS ||
	record "SELinux enforcing preserved" FAIL

# 7. fail-closed readiness gating: no 'avc family failed' in log
dmesg 2>/dev/null | grep "branch_link: avc" | grep -q "family failed" &&
	record "avc family fail-closed log absent (committed cleanly)" FAIL ||
	record "avc family fail-closed log absent (committed cleanly)" PASS

echo "---"
echo "avc_spoof: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
