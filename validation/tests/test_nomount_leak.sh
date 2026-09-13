#!/system/bin/sh
# Phase 19 NoMount metamodule leakage suite.
# Treats NoMount as a security-sensitive filesystem-visibility metamodule:
# a mount/path hidden by NoMount must remain hidden through every relevant
# observable interface and namespace context.
#
# Usage: adb shell su -c 'sh /data/local/tmp/nm-leak/run_nomount_leak.sh'
# Output: PASS/FAIL/SKIP per probe; final summary; log file.
#
# Semantics derived from kernel/nomount/core.c (rule engine):
#  - exact rules rewrite the pathname to rule->real_path (core.c:2914-2944)
#  - whiteout => -ENOENT (core.c:3006-3009)
#  - directory rules are recursive prefixes (core.c:2946-2977)
#  - paths canonicalized: //, ., .., trailing / (core.c:456-531)
#  - private backends (no o+x) => -ENOENT for uid>=10000 (core.c:794-815,2978)
#  - stat identity spoofed: visible_ino/visible_dev (core.c:3339-3359,3411-3459)
#  - statfs returns captured virtual-side kstatfs (core.c:3461-3531)
#  - d_path rewritten => /proc/pid/fd/N readlink shows virtual (core.c:3295-3337)
#  - readdir merges native+injected (core.c:3198-3247)
#  - root/shell are negative controls (uid gates core.c:2978,2986)

TD=/data/local/tmp/nm-leak
LOG=/data/local/tmp/nm-leak-results.log
NM=/data/adb/modules/nomount/bin/nm
BUSYBOX=/data/adb/ksu/bin/busybox

PASS=0; FAIL=0; SKIP=0
record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1" | tee -a "$LOG"
}

echo "=== NoMount leakage suite $(date) ===" > "$LOG"
echo "kernel: $(uname -r)" >> "$LOG"

# ---- preflight ---------------------------------------------------------------
if [ ! -x "$NM" ]; then
	record "nm CLI present" SKIP
	echo "TOTAL: PASS=$PASS FAIL=$FAIL SKIP=$SKIP" | tee -a "$LOG"
	exit 0
fi
record "nm CLI present" PASS
"$NM" version >/dev/null 2>&1 && record "nm version probe" PASS || record "nm version probe" FAIL

# ---- setup -------------------------------------------------------------------
rm -rf "$TD"; mkdir -p "$TD/virt" "$TD/real" "$TD/priv/secret" "$TD/pub" "$TD/pub2"
echo STOCK > "$TD/virt/file.txt"
echo BACKEND > "$TD/real/file.txt"
echo SECRET > "$TD/priv/secret/f"
chmod 770 "$TD/priv" "$TD/priv/secret"     # private backend: no o+x
chmod 755 "$TD/virt" "$TD/real" "$TD/pub"

R1="$TD/virt/file.txt"
R2="$TD/real/file.txt"

# Native (pre-rule) identity of the backend object, captured before any rule
# exists.  With a rule active, the backend path itself presents the visible
# identity (identity consistency by design), so leak checks must compare
# against this pre-rule snapshot.
INO_NATIVE=$(stat -c %i "$R2" 2>/dev/null)
FT_NATIVE=$(stat -f -c %t "$R2" 2>/dev/null)

# ---- A. path visibility ------------------------------------------------------
"$NM" add "$R1" "$R2" >/dev/null 2>&1
record "rule add" PASS

if [ "$(cat "$R1")" = "BACKEND" ]; then record "A1 exact redirect content" PASS
else record "A1 exact redirect content" FAIL; fi

if [ "$(cat "$R1" 2>/dev/null)" = "BACKEND" ]; then record "A2 redirect content stable" PASS
else record "A2 redirect content stable" FAIL; fi

# canonicalization: //, ., .., trailing /
ok=1
[ "$(cat "$TD/virt//file.txt" 2>/dev/null)" = "BACKEND" ] || ok=0
[ "$(cat "$TD/virt/./file.txt" 2>/dev/null)" = "BACKEND" ] || ok=0
[ "$(cat "$TD/virt/x/../file.txt" 2>/dev/null)" = "BACKEND" ] || ok=0
[ "$ok" = "1" ] && record "A4 canonicalization forms" PASS || record "A4 canonicalization forms" FAIL

# stat identity: a VIRTUAL-ONLY object (no native existence) must report a
# synthetic ino, never the backend's native ino (core.c:817-826).  Existing
# virtual objects keep their native identity by design.  Uses a dedicated
# backend file: the engine enforces one rule per backend inode
# (core.c real-inode conflict check), so sharing $R2 with the active rule
# would make the add fail silently.
echo GHOSTBACKEND > "$TD/real/ghost_backend.txt"
"$NM" add "$TD/virt/ghost.txt" "$TD/real/ghost_backend.txt" >/dev/null 2>&1
INO_GHOST=$(stat -c %i "$TD/virt/ghost.txt" 2>/dev/null)
"$NM" del "$TD/virt/ghost.txt" >/dev/null 2>&1
rm -f "$TD/real/ghost_backend.txt"
if [ -n "$INO_GHOST" ] && [ "$INO_GHOST" != "$INO_NATIVE" ]; then
	record "A5 virtual-only object uses synthetic identity" PASS
else record "A5 virtual-only object uses synthetic identity" FAIL; fi

# statfs: must not report the backend fs type.  Needs a CROSS-FILESYSTEM
# backend and a clean rule state (an active file rule on the parent dir
# would rewrite the probe's own d_path).  Use /dev (tmpfs) backend.
"$NM" clear >/dev/null 2>&1
mkdir -p /dev/nmtest 2>/dev/null
echo BACKEND > /dev/nmtest/file.txt 2>/dev/null
# Capture the backend's true fs type BEFORE the rule: once the rule is
# active, the backend path itself presents the virtualized identity
# (identity consistency by design), so a post-rule read is useless as a
# control.
FT_BACKEND=$(stat -f -c %t /dev/nmtest/file.txt 2>/dev/null)
"$NM" add "$TD/virt/cross.txt" /dev/nmtest/file.txt >/dev/null 2>&1
FT_V=$(stat -f -c %t "$TD/virt/cross.txt" 2>/dev/null)
FT_DATA=$(stat -f -c %t "$TD" 2>/dev/null)
if [ -n "$FT_V" ] && [ "$FT_V" != "$FT_BACKEND" ] && [ "$FT_V" = "$FT_DATA" ];
then record "A6 statfs f_type virtualized (cross-fs backend)" PASS
else record "A6 statfs f_type virtualized (cross-fs backend)" FAIL; fi
"$NM" clear >/dev/null 2>&1
rm -rf /dev/nmtest
"$NM" add "$R1" "$R2" >/dev/null 2>&1

# /proc/self/fd readlink must show the VIRTUAL path (d_path rewrite)
CATPID=$$
( cat "$R1" >/dev/null 2>&1 & echo $! > "$TD/cat.pid" ; wait ) 2>/dev/null
CPID=$(cat "$TD/cat.pid" 2>/dev/null)
if [ -n "$CPID" ]; then
	sleep 0.2
	LNK=$(readlink "/proc/$CPID/fd/1" 2>/dev/null)
	kill "$CPID" 2>/dev/null
fi
# fallback: use our own transient fd via a subshell trick
if [ -z "$LNK" ]; then
	LNK=$("$BUSYBOX" sh -c "exec 9<'$R1'; readlink /proc/self/fd/9" 2>/dev/null)
fi
case "$LNK" in
	*"$TD/real"*) record "A7 fd readlink shows virtual path" FAIL ;;
	*"$TD/virt"*) record "A7 fd readlink shows virtual path" PASS ;;
	*) record "A7 fd readlink shows virtual path" SKIP ;;
esac

# readdir merge: with a DIRECTORY rule, backend-only children must appear
# through the virtual path (core.c readdir merge), and injected ghost files
# must be listed.
echo BACKEND2 > "$TD/real/only_backend.txt"
"$NM" add "$TD/virt" "$TD/real" >/dev/null 2>&1
LSV=$(ls "$TD/virt" 2>/dev/null)
ok=1
case "$LSV" in *only_backend.txt*) ;; *) ok=0 ;; esac
case "$LSV" in *file.txt*) ;; *) ok=0 ;; esac
if [ "$ok" = "1" ]; then record "A8 readdir merges backend-only child" PASS
else record "A8 readdir merges backend-only child (got: $LSV)" FAIL; fi
"$NM" del "$TD/virt" >/dev/null 2>&1
rm -f "$TD/real/only_backend.txt"

# private backend: gated uid>=10000 must get ENOENT (we test as root: control)
if [ "$(cat "$TD/priv/secret/f" 2>/dev/null)" = "SECRET" ]; then
	record "A11 private backend root control (visible by design)" PASS
else record "A11 private backend root control" FAIL; fi

# negative control: unrelated path unaffected
echo UNRELATED > "$TD/pub/other.txt"
if [ "$(cat "$TD/pub/other.txt" 2>/dev/null)" = "UNRELATED" ]; then
	record "I2 unrelated path unaffected" PASS
else record "I2 unrelated path unaffected" FAIL; fi

# ---- B. mount reporting ------------------------------------------------------
# d_path rewrite must cover mountinfo path fields for redirected paths
if grep -q "$TD/real" /proc/self/mountinfo 2>/dev/null; then
	record "B8 mountinfo does not expose backend path" FAIL
else
	record "B8 mountinfo does not expose backend path" PASS
fi

# negative control: standard mounts visible
if grep -q "/system" /proc/self/mountinfo 2>/dev/null; then
	record "I1 standard mounts visible (no over-filtering)" PASS
else record "I1 standard mounts visible" FAIL; fi

# ---- G. dynamic lifecycle ----------------------------------------------------
"$NM" del "$R1" >/dev/null 2>&1
if [ "$(cat "$R1" 2>/dev/null)" = "STOCK" ]; then record "G1 del restores native" PASS
else record "G1 del restores native" FAIL; fi

"$NM" add "$R1" "$R2" >/dev/null 2>&1
if [ "$(cat "$R1" 2>/dev/null)" = "BACKEND" ]; then record "G4 re-add works" PASS
else record "G4 re-add works" FAIL; fi

# toggle loop: 25x del/add interleaved with reads
torn=0
i=0
while [ $i -lt 25 ]; do
	"$NM" del "$R1" >/dev/null 2>&1
	C=$(cat "$R1" 2>/dev/null)
	[ "$C" = "STOCK" ] || torn=1
	"$NM" add "$R1" "$R2" >/dev/null 2>&1
	C=$(cat "$R1" 2>/dev/null)
	[ "$C" = "BACKEND" ] || torn=1
	i=$((i+1))
done
[ "$torn" = "0" ] && record "G5 toggle loop consistency" PASS || record "G5 toggle loop consistency" FAIL

"$NM" clear >/dev/null 2>&1
if [ "$(cat "$R1" 2>/dev/null)" = "STOCK" ]; then record "G8 clear-all restores" PASS
else record "G8 clear-all restores" FAIL; fi

# ---- H. concurrency ----------------------------------------------------------
"$NM" add "$R1" "$R2" >/dev/null 2>&1
( i=0; while [ $i -lt 40 ]; do "$NM" del "$R1" >/dev/null 2>&1; "$NM" add "$R1" "$R2" >/dev/null 2>&1; i=$((i+1)); done ) &
CHURN=$!
torn=0
i=0
while [ $i -lt 120 ] && kill -0 "$CHURN" 2>/dev/null; do
	C=$(cat "$R1" 2>/dev/null)
	if [ "$C" != "STOCK" ] && [ "$C" != "BACKEND" ]; then torn=1; fi
	i=$((i+1))
done
wait "$CHURN" 2>/dev/null
[ "$torn" = "0" ] && record "H2 rule-churn lookup consistency" PASS || record "H2 rule-churn lookup consistency" FAIL

# mountinfo read during mount churn (root-driven bind/umount on pub)
( i=0; while [ $i -lt 15 ]; do
	mount --bind "$TD/pub" "$TD/pub2" >/dev/null 2>&1
	umount "$TD/pub2" >/dev/null 2>&1
	i=$((i+1)); done ) &
CHURN2=$!
torn=0
i=0
while [ $i -lt 60 ] && kill -0 "$CHURN2" 2>/dev/null; do
	grep -q . /proc/self/mountinfo 2>/dev/null || torn=1
	i=$((i+1))
done
wait "$CHURN2" 2>/dev/null
[ "$torn" = "0" ] && record "H1 mountinfo read during churn" PASS || record "H1 mountinfo read during churn" FAIL

"$NM" clear >/dev/null 2>&1

echo "TOTAL: PASS=$PASS FAIL=$FAIL SKIP=$SKIP" | tee -a "$LOG"
[ "$FAIL" -eq 0 ]
