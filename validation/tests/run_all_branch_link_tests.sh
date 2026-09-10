#!/system/bin/sh
# run_all_branch_link_tests.sh — run all validation tests, collect results
# Usage: adb shell su -c 'sh /data/local/tmp/bl-tests/run_all_branch_link_tests.sh'
# Output: /data/local/tmp/bl-test-results-<timestamp>.log

TS=$(date +%Y%m%d-%H%M%S)
OUTFILE="/data/local/tmp/bl-test-results-$TS.log"
TESTDIR="/data/local/tmp/bl-tests"

echo "=== KernelSU-Next branch-link validation suite ===" | tee "$OUTFILE"
echo "Timestamp: $TS" | tee -a "$OUTFILE"
echo "Kernel: $(uname -r)" | tee -a "$OUTFILE"
echo "" | tee -a "$OUTFILE"

TOTAL_PASS=0; TOTAL_FAIL=0; TOTAL_SKIP=0

for test in \
	test_branch_link_inventory.sh \
	test_faccessat.sh \
	test_readlink.sh \
	test_stat_statfs.sh \
	test_open.sh \
	test_exec.sh \
	test_mount.sh \
	test_lifecycle.sh \
	t02_sucompat.sh; do
	TESTPATH="$TESTDIR/$test"
	if [ ! -f "$TESTPATH" ]; then
		echo "SKIP: $test (not found)" | tee -a "$OUTFILE"
		continue
	fi
	echo "" | tee -a "$OUTFILE"
	echo "====== $test ======" | tee -a "$OUTFILE"
	sh "$TESTPATH" 2>&1 | tee -a "$OUTFILE"
	# Extract the last summary line
	SUMMARY=$(grep -E 'PASS=[0-9]+ FAIL=[0-9]+' | tail -n 1)
	if [ -n "$SUMMARY" ]; then
		P=$(echo "$SUMMARY" | grep -oE 'PASS=[0-9]+' | cut -d= -f2)
		F=$(echo "$SUMMARY" | grep -oE 'FAIL=[0-9]+' | cut -d= -f2)
		S=$(echo "$SUMMARY" | grep -oE 'SKIP=[0-9]+' | cut -d= -f2)
		TOTAL_PASS=$((TOTAL_PASS + ${P:-0}))
		TOTAL_FAIL=$((TOTAL_FAIL + ${F:-0}))
		TOTAL_SKIP=$((TOTAL_SKIP + ${S:-0}))
	fi
done

echo "" | tee -a "$OUTFILE"
echo "========================================" | tee -a "$OUTFILE"
echo "TOTAL: PASS=$TOTAL_PASS FAIL=$TOTAL_FAIL SKIP=$TOTAL_SKIP" | tee -a "$OUTFILE"

if [ "$TOTAL_FAIL" -gt 0 ]; then
	echo "RESULT: FAILURES DETECTED" | tee -a "$OUTFILE"
	echo "" | tee -a "$OUTFILE"
	echo "--- Recent kernel errors ---" | tee -a "$OUTFILE"
	dmesg | grep -iE 'BUG:|Oops|branch_link.*error|branch_link.*conflict' | \
		tail -n 10 | tee -a "$OUTFILE"
else
	echo "RESULT: ALL PASS" | tee -a "$OUTFILE"
fi

echo "Log saved: $OUTFILE"
