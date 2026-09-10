#!/system/bin/sh
# test_stat_statfs.sh — stat/newfstatat/statx/statfs semantic validation
TD=/data/local/tmp/bl-test
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

mkdir -p "$TD/stat_dir"
cd "$TD" || exit 1
echo "stat_content" > stat_test.txt

# 1. stat absolute
stat "$TD/stat_test.txt" >/dev/null 2>&1 && \
	record "stat absolute" PASS || \
	record "stat absolute" FAIL

# 2. stat relative AT_FDCWD
stat stat_test.txt >/dev/null 2>&1 && \
	record "stat relative AT_FDCWD" PASS || \
	record "stat relative AT_FDCWD" FAIL

# 3. newfstatat with dirfd (stat on relative from dir)
stat "$TD/stat_dir/../stat_test.txt" >/dev/null 2>&1 && \
	record "stat .. traversal" PASS || \
	record "stat .. traversal" FAIL

# 4. stat nonexistent -> ENOENT
stat "$TD/nonexistent_stat_xyz" >/dev/null 2>&1
[ $? -ne 0 ] && \
	record "stat nonexistent -> ENOENT" PASS || \
	record "stat nonexistent -> ENOENT" FAIL

# 5. statx (toybox stat may use statx internally on newer builds)
if stat -c '%s' stat_test.txt >/dev/null 2>&1; then
	SIZE=$(stat -c '%s' stat_test.txt)
	[ "$SIZE" = "13" ] && \
		record "stat size correct" PASS || \
		record "stat size (got $SIZE, expect 13)" FAIL
else
	record "stat -c format" SKIP
fi

# 6. statfs
df "$TD" >/dev/null 2>&1 && \
	record "statfs via df" PASS || \
	record "statfs via df" FAIL

# 7. fstat via proc fd
exec 98<stat_test.txt
stat /proc/self/fd/98 >/dev/null 2>&1 && \
	record "fstat via /proc fd" PASS || \
	record "fstat via /proc fd" FAIL
exec 98>&-

# 8. stat on symlink
ln -sf stat_test.txt stat_symlink.txt
stat stat_symlink.txt >/dev/null 2>&1 && \
	record "stat symlink follows" PASS || \
	record "stat symlink follows" FAIL

# 9. SUSFS kstat identity check (root context sees real stat)
INO1=$(stat -c '%i' stat_test.txt 2>/dev/null)
if [ -n "$INO1" ] && [ "$INO1" -gt 0 ]; then
	record "stat ino valid" PASS
else
	record "stat ino valid" SKIP
fi

# 10. Compat stat (AArch32) — needs 32-bit binary
COMPAT_TESTER="$TD/stat_compat_tester"
if [ -x "$COMPAT_TESTER" ]; then
	"$COMPAT_TESTER" "$TD/stat_test.txt" && \
		record "compat stat" PASS || \
		record "compat stat" FAIL
else
	record "compat stat (no 32-bit binary)" SKIP
fi

# Cleanup
rm -rf stat_test.txt stat_symlink.txt stat_dir

echo "---"
echo "stat/statfs: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
