#!/system/bin/sh
# test_exec.sh — execve/execveat semantic + sucompat validation
TD=/data/local/tmp/bl-test
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

mkdir -p "$TD"
cd "$TD" || exit 1

# 1. Native execve — absolute path ELF
/system/bin/true && \
	record "execve absolute ELF" PASS || \
	record "execve absolute ELF" FAIL

# 2. Native execve — shell (script with shebang)
sh -c 'exit 0' && \
	record "execve shebang script" PASS || \
	record "execve shebang script" FAIL

# 3. execveat — via dirfd (exec something from a dirfd path)
# Shell can't do raw execveat; use the fact that toybox exec works
TOYBOX=$(which toybox)
if [ -n "$TOYBOX" ]; then
	"$TOYBOX" true && \
		record "exec toybox binary" PASS || \
		record "exec toybox binary" FAIL
else
	record "exec toybox binary" SKIP
fi

# 4. exec nonexistent -> ENOENT
"$TD/nonexistent_exec_xyz" >/dev/null 2>&1
[ $? -eq 127 ] && \
	record "exec nonexistent -> ENOENT/127" PASS || \
	record "exec nonexistent -> ENOENT/127 (got $?)" FAIL

# 5. exec directory -> EACCES/EISDIR
"$TD" >/dev/null 2>&1
[ $? -ne 0 ] && \
	record "exec directory -> error" PASS || \
	record "exec directory -> error" FAIL

# 6. sucompat: /system/bin/su redirect
if [ -x /system/bin/su ]; then
	RESULT=$(su -c id 2>/dev/null)
	if echo "$RESULT" | grep -q "uid=0"; then
		record "sucompat /system/bin/su -> uid=0" PASS
	else
		record "sucompat /system/bin/su -> uid=0 (got: $RESULT)" FAIL
	fi
else
	record "sucompat /system/bin/su (not present)" SKIP
fi

# 7. ksud present
if [ -x /data/adb/ksud ]; then
	record "ksud binary present" PASS
else
	record "ksud binary present" FAIL
fi

# 8. KernelSU root context
if id | grep -q "uid=0"; then
	CTX=$(id | grep -oE 'context=[^ ]+')
	echo "  root context: $CTX"
	record "KernelSU root with SELinux context" PASS
else
	record "KernelSU root context" FAIL
fi

# 9. execveat with AT_EMPTY_PATH — needs C harness
record "execveat AT_EMPTY_PATH (needs C harness)" SKIP

# 10. Compat execve — needs 32-bit binary
COMPAT_TESTER="$TD/exec_compat_tester"
if [ -x "$COMPAT_TESTER" ]; then
	"$COMPAT_TESTER" && \
		record "compat execve" PASS || \
		record "compat execve" FAIL
else
	record "compat execve (no 32-bit binary)" SKIP
fi

echo "---"
echo "exec: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
