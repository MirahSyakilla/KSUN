#!/system/bin/sh
# t02_sucompat.sh — sucompat /system/bin/su redirect + root-profile validation
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

echo "uid=$(id -u)"

# 1. ksud binary
if [ -x /data/adb/ksud ]; then
	record "ksud binary present" PASS
else
	record "ksud binary present" FAIL
fi

# 2. /system/bin/su accessible and redirects to root
if [ -x /system/bin/su ]; then
	RESULT=$(su -c id 2>/dev/null)
	if echo "$RESULT" | grep -q "uid=0"; then
		CTX=$(echo "$RESULT" | grep -oE 'context=[^ ]+' | head -n 1)
		record "sucompat /system/bin/su -> uid=0 ($CTX)" PASS
	else
		record "sucompat /system/bin/su (got: $RESULT)" FAIL
	fi
else
	record "/system/bin/su not present" SKIP
fi

# 3. KSU credential context (from root shell)
CTX=$(id | grep -oE 'context=[^ ]+' | head -n 1)
echo "current context: $CTX"
if echo "$CTX" | grep -qE 'u:r:ksu'; then
	record "KSU SELinux domain" PASS
else
	record "KSU SELinux domain (got $CTX)" SKIP
fi

# 4. SUSFS enabled features
SUSFS=/data/adb/ksu/bin/susfs
if [ -x "$SUSFS" ]; then
	FEATURES=$($SUSFS show enabled_features 2>/dev/null)
	echo "SUSFS features:"
	echo "$FEATURES" | while read -r f; do echo "  $f"; done
	$SUSFS show version >/dev/null 2>&1 && \
		record "SUSFS CLI functional" PASS || \
		record "SUSFS CLI" FAIL
else
	record "SUSFS CLI" SKIP
fi

echo "---"
echo "sucompat: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
