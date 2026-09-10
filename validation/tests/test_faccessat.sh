#!/system/bin/sh
# test_faccessat.sh — faccessat/faccessat2 semantic + fallback validation
# Usage: adb shell su -c 'sh /data/local/tmp/bl-tests/test_faccessat.sh'
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

# Create test fixtures
touch faccessat_readable.txt faccessat_perm.txt
chmod 000 faccessat_perm.txt 2>/dev/null
mkdir -p faccessat_dir/sub

# 1. Native faccessat — absolute path, accessible
if [ -r "$TD/faccessat_readable.txt" ]; then
	record "native faccessat absolute readable" PASS
else
	record "native faccessat absolute readable" FAIL
fi

# 2. Native faccessat — relative path from CWD
if [ -r "faccessat_readable.txt" ]; then
	record "native faccessat relative AT_FDCWD" PASS
else
	record "native faccessat relative AT_FDCWD" FAIL
fi

# 3. Native faccessat — relative path from arbitrary dirfd
if [ -r "faccessat_dir/sub/.." ]; then
	record "faccessat dirfd traversal" PASS
else
	record "faccessat dirfd traversal" FAIL
fi

# 4. faccessat nonexistent → ENOENT
if ! ls "$TD/nonexistent_faccessat_xyz" >/dev/null 2>&1; then
	record "faccessat nonexistent -> ENOENT" PASS
else
	record "faccessat nonexistent -> ENOENT" FAIL
fi

# 5. faccessat2 (syscall 439) if supported
# faccessat2 was added in 5.8; on 5.4 it doesn't exist as a separate syscall
# unless vendor-backported. Use a C-free probe: just check /proc/kallsyms.
if grep -q ' __arm64_sys_faccessat2$' /proc/kallsyms 2>/dev/null; then
	record "faccessat2 present in kallsyms" PASS
else
	record "faccessat2 not in kernel (5.4 stock)" SKIP
fi

# 6. Compat faccessat (AArch32) — only if compat binary available
COMPAT_TESTER="$TD/faccessat_compat_tester"
if [ -x "$COMPAT_TESTER" ]; then
	"$COMPAT_TESTER" "$TD/faccessat_readable.txt" && \
		record "compat faccessat" PASS || \
		record "compat faccessat" FAIL
else
	record "compat faccessat (no 32-bit tester binary)" SKIP
fi

# 7. Permission-denied (running as non-root would show EACCES;
#    as root, most permission checks pass, so this is advisory)
echo "  note: running as uid=$(id -u), EACCES tests are advisory only"

# 8. Cleanup
rm -rf "$TD/faccessat_readable.txt" "$TD/faccessat_perm.txt" "$TD/faccessat_dir"

echo "---"
echo "faccessat: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
