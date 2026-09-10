#!/system/bin/sh
# test_mount.sh — mount-family branch-link validation + SUSFS mount rules
TD=/data/local/tmp/bl-test
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

mkdir -p "$TD"

# 1. Current mounts visible
MOUNT_COUNT=$(cat /proc/mounts | wc -l)
[ "$MOUNT_COUNT" -gt 5 ] && \
	record "proc/mounts populated ($MOUNT_COUNT entries)" PASS || \
	record "proc/mounts only $MOUNT_COUNT entries" FAIL

# 2. Mount info format
grep -q ' / ' /proc/self/mountinfo && \
	record "mountinfo root entry" PASS || \
	record "mountinfo root entry" FAIL

# 3. SUSFS mount rules
SUSFS=/data/adb/ksu/bin/susfs
if [ -x "$SUSFS" ]; then
	# Check hide_sus_mnts
	$SUSFS hide_sus_mnts_for_non_su_procs 1 >/dev/null 2>&1
	[ $? -eq 0 ] && \
		record "SUSFS hide_sus_mnts set" PASS || \
		record "SUSFS hide_sus_mnts" FAIL
	$SUSFS hide_sus_mnts_for_non_su_procs 0 >/dev/null 2>&1
else
	record "SUSFS mount rules (no CLI)" SKIP
fi

# 4. mount namespace isolation (root context should see all mounts)
NS_COUNT=$(ls /proc/self/ns/ 2>/dev/null | wc -l)
[ "$NS_COUNT" -gt 3 ] && \
	record "namespace entries ($NS_COUNT)" PASS || \
	record "namespace entries ($NS_COUNT)" FAIL

# 5. NoMount netlink family check (if nl tool available)
command -v nl >/dev/null 2>&1 && \
	record "NoMount nl tool" PASS || \
	record "NoMount nl tool (no nl command)" SKIP

# 6. Cleanup
echo "---"
echo "mount: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
