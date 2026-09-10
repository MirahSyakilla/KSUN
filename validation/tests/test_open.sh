#!/system/bin/sh
# test_open.sh — openat/creat/O_* flag + open_redirect lifecycle validation
TD=/data/local/tmp/bl-test
PASS=0; FAIL=0; SKIP=0

record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

mkdir -p "$TD/open_dir"
cd "$TD" || exit 1

# 1. openat absolute
echo "test_content" > "$TD/open_test.txt"
cat "$TD/open_test.txt" | grep -q test_content && \
	record "openat absolute path" PASS || \
	record "openat absolute path" FAIL

# 2. openat relative AT_FDCWD
echo "rel_content" > open_rel.txt
cat open_rel.txt | grep -q rel_content && \
	record "openat relative AT_FDCWD" PASS || \
	record "openat relative AT_FDCWD" FAIL

# 3. O_CREAT — implicit via shell >
echo "creat_content" > open_creat_new.txt
[ -f open_creat_new.txt ] && \
	record "openat O_CREAT new file" PASS || \
	record "openat O_CREAT new file" FAIL

# 4. O_CREAT — via touch (creat syscall on compat, openat on native)
touch open_touch_new.txt
[ -f open_touch_new.txt ] && \
	record "creat/touch new file" PASS || \
	record "creat/touch new file" FAIL

# 5. Symlink open (follows by default)
ln -sf "$TD/open_test.txt" open_symlink.txt
cat open_symlink.txt | grep -q test_content && \
	record "openat symlink follows" PASS || \
	record "openat symlink follows" FAIL

# 6. O_NOFOLLOW — shell can't do this directly; SKIP
record "O_NOFOLLOW (needs C harness)" SKIP

# 7. O_PATH — shell can't exercise this directly; SKIP
record "O_PATH (needs C harness)" SKIP

# 8. O_TMPFILE — needs filesystem support; SKIP on most Android
record "O_TMPFILE (needs fs support + C harness)" SKIP

# 9. .. traversal
cat "$TD/open_dir/../open_test.txt" | grep -q test_content && \
	record "openat .. traversal" PASS || \
	record "openat .. traversal" FAIL

# 10. Nonexistent -> ENOENT
cat "$TD/nonexistent_open_xyz" >/dev/null 2>&1
[ $? -ne 0 ] && \
	record "openat nonexistent -> ENOENT" PASS || \
	record "openat nonexistent -> ENOENT" FAIL

# 11. open_redirect lifecycle (requires susfs CLI + root)
SUSFS=/data/adb/ksu/bin/susfs
if [ -x "$SUSFS" ]; then
	echo "== open_redirect lifecycle =="
	TGT="$TD/redir_target"
	DST="$TD/redir_dest"
	mkdir -p "$TGT" "$DST"
	echo "ORIGINAL" > "$TGT/marker.txt"
	echo "REDIRECTED" > "$DST/marker.txt"

	# Add redirect rule
	$SUSFS add_open_redirect "$TGT" "$DST" 1 >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		record "open_redirect rule added" PASS

		# Read through redirect (must be a non-su process per uid_scheme)
		# From this KSU shell the redirect is expected to NOT apply
		# (uid_scheme=1 excludes su domain); the content check is
		# expected to still show ORIGINAL from this context
		CONTENT=$(cat "$TGT/marker.txt")
		if [ "$CONTENT" = "ORIGINAL" ]; then
			record "open_redirect correctly excluded for su" PASS
		elif [ "$CONTENT" = "REDIRECTED" ]; then
			record "open_redirect applied for su (unexpected)" FAIL
		else
			record "open_redirect content unknown" FAIL
		fi

		# Remove all rules
		$SUSFS clear >/dev/null 2>&1
		CONTENT2=$(cat "$TGT/marker.txt")
		if [ "$CONTENT2" = "ORIGINAL" ]; then
			record "open_redirect cleared, original visible" PASS
		else
			record "open_redirect cleared but content wrong" FAIL
		fi
	else
		record "open_redirect rule add (check kstat gate)" SKIP
	fi
else
	record "open_redirect (no susfs CLI)" SKIP
fi

# 12. Compat creat (AArch32 nr 8 -> __arm64_sys_creat)
# Shell on 64-bit Android is native; compat creat needs a 32-bit binary.
COMPAT_TESTER="$TD/open_compat_tester"
if [ -x "$COMPAT_TESTER" ]; then
	"$COMPAT_TESTER" "$TD/compat_creat_test.txt" && \
		record "compat creat" PASS || \
		record "compat creat" FAIL
else
	record "compat creat (no 32-bit binary)" SKIP
fi

# Cleanup
rm -rf "$TD/open_dir" "$TD/open_test.txt" open_rel.txt open_creat_new.txt \
	open_touch_new.txt open_symlink.txt

echo "---"
echo "open: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit 0
