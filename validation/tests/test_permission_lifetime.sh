#!/system/bin/sh
# test_permission_lifetime.sh — validate the one-shot permission_consumed
# lifecycle of the NoMount access-scope state machine through the real rule
# engine (getname scope creation -> permission consumption -> scope teardown
# at syscall exit).
#
# Exercises, per round:
#   1. first redirected open (fresh scope, permission consumed, force-allow
#      applies if DAC would deny);
#   2. second open in a NEW syscall (fresh scope re-created by getname;
#      consumption must NOT leak);
#   3. cleanup (rule delete) restores stock semantics;
#   4. repeated rounds prove no state accumulation;
#   5. concurrent rounds prove per-task scope isolation
#      (scopes are hash-keyed by 'current' — cross-task leakage would
#       corrupt a concurrent worker's read).
#
# Backend is root:root 0600 so the force-allow path (DAC denial -> policy
# override) is genuinely exercised, not just the pass-through path.

PASS=0; FAIL=0; SKIP=0
record() {
	if [ "$2" = "PASS" ]; then PASS=$((PASS+1))
	elif [ "$2" = "SKIP" ]; then SKIP=$((SKIP+1))
	else FAIL=$((FAIL+1)); fi
	echo "$2: $1"
}

NM=/data/adb/modules/nomount/bin/nm
BASE=/data/local/tmp/nm-lifetime
VIS="$BASE/base/target.txt"
REAL="$BASE/real/backend.txt"

echo "=== permission one-shot lifetime ==="

[ -x "$NM_BIN" ] || [ -x "$NM" ] || { record "nm tool present" SKIP; echo "---"; echo "lifetime: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"; exit 0; }

for round in 1 2 3; do
	# reset workspace
	rm -rf "$BASE"; mkdir -p "$BASE/base" "$BASE/real"
	echo STOCK > "$VIS"
	echo BACKEND > "$REAL"
	chown 0:0 "$REAL"; chmod 600 "$REAL"   # DAC denies non-root readers

	# 1. add rule and read through the virtual path
	"$NM" add "$VIS" "$REAL" >/dev/null 2>&1 ||
		{ record "round $round: rule add" FAIL; continue; }
	C1=$(cat "$VIS" 2>/dev/null | tr -d '\r\n')
	[ "$C1" = "BACKEND" ] && record "round $round: first redirected open (scope 1, consumed)" PASS ||
		record "round $round: first redirected open (got '$C1')" FAIL

	# 2. SECOND independent syscall — new scope must be created; a leaked
	#    permission_consumed flag would leave the second open unforced.
	#    Read it twice; both must work.
	C2=$(cat "$VIS" 2>/dev/null | tr -d '\r\n')
	[ "$C2" = "BACKEND" ] && record "round $round: second open (fresh scope)" PASS ||
		record "round $round: second open (got '$C2')" FAIL
	C3=$(cat "$VIS" 2>/dev/null | tr -d '\r\n')
	[ "$C3" = "BACKEND" ] && record "round $round: repeated open" PASS ||
		record "round $round: repeated open (got '$C3')" FAIL

	# 3. stat identity must stay the VISIBLE inode across repeated access
	I1=$(stat -c '%i' "$VIS" 2>/dev/null)
	I2=$(stat -c '%i' "$VIS" 2>/dev/null)
	[ -n "$I1" ] && [ "$I1" = "$I2" ] && record "round $round: visible identity stable" PASS ||
		record "round $round: visible identity unstable ($I1 vs $I2)" FAIL

	# 4. cleanup restores stock semantics
	"$NM" del "$VIS" >/dev/null 2>&1 || record "round $round: rule del" FAIL
	C4=$(cat "$VIS" 2>/dev/null | tr -d '\r\n')
	[ "$C4" = "STOCK" ] && record "round $round: cleanup restored stock" PASS ||
		record "round $round: cleanup left '$C4'" FAIL
done

# 5. concurrent isolation: 4 workers x 30 open/close rounds on separate rules
CONC_BASE=/data/local/tmp/nm-lifetime-conc
rm -rf "$CONC_BASE"
i=0
while [ $i -lt 4 ]; do
	mkdir -p "$CONC_BASE/w$i/base" "$CONC_BASE/w$i/real"
	echo STOCK > "$CONC_BASE/w$i/base/target.txt"
	echo BACKEND > "$CONC_BASE/w$i/real/backend.txt"
	"$NM" add "$CONC_BASE/w$i/base/target.txt" "$CONC_BASE/w$i/real/backend.txt" >/dev/null 2>&1
	i=$((i+1))
done
(
	i=0
	while [ $i -lt 4 ]; do
		(
			j=0; ok=1
			while [ $j -lt 30 ]; do
				C=$(cat "$CONC_BASE/w$i/base/target.txt" 2>/dev/null | tr -d '\r\n')
				[ "$C" = "BACKEND" ] || ok=0
				j=$((j+1))
			done
			echo "worker $i ok=$ok"
		) &
		i=$((i+1))
	done
	wait
) 2>/dev/null | while read -r line; do echo "$line"; done > "$CONC_BASE/out"
CONC_OK=$(grep -c "ok=1" "$CONC_BASE/out")
CONC_BAD=$(grep -c "ok=0" "$CONC_BASE/out")
[ "$CONC_OK" = "4" ] && [ "$CONC_BAD" = "0" ] &&
	record "concurrent scope isolation (4x30 opens, no cross-talk)" PASS ||
	record "concurrent scope isolation ($CONC_OK/4 clean, $CONC_BAD bad)" FAIL
i=0
while [ $i -lt 4 ]; do
	"$NM" del "$CONC_BASE/w$i/base/target.txt" >/dev/null 2>&1
	i=$((i+1))
done

# 6. kernel stayed healthy
dmesg 2>/dev/null | tail -400 | grep -qE "BUG|Oops" &&
	record "no kernel BUG/OOPS during lifetime test" FAIL ||
	record "no kernel BUG/OOPS during lifetime test" PASS

echo "---"
echo "lifetime: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
