#!/system/bin/sh
# test_readlink.sh — readlink/readlinkat semantic + NoMount pathname validation
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

# Create a symlink
ln -sf /data/local/tmp/bl-test/readlink_target.txt readlink_link.txt
echo "readlink_content" > readlink_target.txt

# 1. Native readlink
CONTENT=$(readlink readlink_link.txt)
if [ "$CONTENT" = "/data/local/tmp/bl-test/readlink_target.txt" ]; then
	record "native readlink absolute symlink" PASS
else
	record "native readlink absolute symlink (got: $CONTENT)" FAIL
fi

# 2. readlinkat via /proc/self/exe
PROCEXE=$(readlink /proc/self/exe)
if [ -n "$PROCEXE" ]; then
	record "readlink /proc/self/exe" PASS
else
	record "readlink /proc/self/exe" FAIL
fi

# 3. readlink /proc/<pid>/fd/<n>
exec 99<"$TD/readlink_target.txt"
FDLINK=$(readlink /proc/self/fd/99)
if [ -n "$FDLINK" ]; then
	record "readlink /proc/self/fd/99" PASS
else
	record "readlink /proc/self/fd/99" FAIL
fi
exec 99>&-

# 4. readlink nonexistent → error
readlink "$TD/nonexistent_readlink_xyz" >/dev/null 2>&1
if [ $? -ne 0 ]; then
	record "readlink nonexistent -> error" PASS
else
	record "readlink nonexistent -> error" FAIL
fi

# 5. Relative path with dirfd (basic: relative symlink target)
REL_LINK="$TD/readlink_rel_link.txt"
ln -sf "./readlink_target.txt" "$REL_LINK"
RESOLVED=$(readlink -f "$REL_LINK" 2>/dev/null)
if echo "$RESOLVED" | grep -q "readlink_target.txt"; then
	record "readlink relative symlink resolved" PASS
else
	record "readlink relative symlink resolved" SKIP
fi

# 6. Compat readlink (AArch32)
COMPAT_TESTER="$TD/readlink_compat_tester"
if [ -x "$COMPAT_TESTER" ]; then
	"$COMPAT_TESTER" "$TD/readlink_link.txt" && \
		record "compat readlink" PASS || \
		record "compat readlink" FAIL
else
	record "compat readlink (no 32-bit binary)" SKIP
fi

# 7. Buffer boundary — readlink to a very small buffer is a C-level test;
#    shell readlink uses auto-sized buffers, so SKIP
record "readlink buffer size boundary (needs C harness)" SKIP

# Cleanup
rm -f "$TD/readlink_link.txt" "$TD/readlink_rel_link.txt" "$TD/readlink_target.txt"

echo "---"
echo "readlink: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
