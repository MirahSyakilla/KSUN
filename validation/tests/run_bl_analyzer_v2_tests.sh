#!/bin/sh
# Phase 17 analyzer test suite: fail-closed positive/negative cases.
# Artifacts stay under validation/audit/phase17/. No /tmp.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ANALYZER="$HERE/../../tools/bl-analyzer/bl_analyzer_v2.py"
OUT="$HERE/../audit/phase17"
LISA_VMLINUX=/home/meow/lisa_kernel/out/vmlinux
LISA_SYSMAP=/home/meow/lisa_kernel/out/System.map
LISA_CONFIG=/home/meow/lisa_kernel/out/.config
LISA_SRCTREE=/home/meow/lisa_kernel

PASS=0
FAIL=0
FAILED=""

expect_exit() {  # name expected_exit cmd...
    name="$1"; want="$2"; shift 2
    "$@" >"$OUT/t.out" 2>"$OUT/t.err"
    got=$?
    if [ "$got" != "$want" ]; then
        FAIL=$((FAIL+1)); FAILED="$FAILED $name(got$got,want$want)"
        printf 'FAIL %-42s exit=%s want=%s\n' "$name" "$got" "$want"
    else
        PASS=$((PASS+1))
        printf 'PASS %-42s exit=%s\n' "$name" "$got"
    fi
}

# shorthand runner
run() {
    python3 "$ANALYZER" "$@" 2>/dev/null
}

echo "== positive =="
expect_exit fixture_assertions 0 python3 "$HERE/bl_analyzer_v2_fixtures.py"

expect_exit pos_lisa_full 0 run \
    --vmlinux "$LISA_VMLINUX" --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" \
    --srctree "$LISA_SRCTREE" --image /home/meow/lisa_kernel/out/arch/arm64/boot/Image \
    --compat-execveat \
    --output-json "$OUT/pos_manifest.json" --output-c "$OUT/pos_rows.h"

# determinism: two runs byte-identical
run --vmlinux "$LISA_VMLINUX" --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" \
    --srctree "$LISA_SRCTREE" --compat-execveat \
    --output-json "$OUT/det1.json" >/dev/null 2>&1
run --vmlinux "$LISA_VMLINUX" --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" \
    --srctree "$LISA_SRCTREE" --compat-execveat \
    --output-json "$OUT/det2.json" >/dev/null 2>&1
if cmp -s "$OUT/det1.json" "$OUT/det2.json"; then
    PASS=$((PASS+1)); echo "PASS determinism"
else
    FAIL=$((FAIL+1)); FAILED="$FAILED determinism"; echo "FAIL determinism"
fi

# stale generated output must not survive a failing run: write a sentinel,
# force failure, check sentinel untouched and no NEW manifest written
run --vmlinux "$LISA_VMLINUX" --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" \
    --srctree "$LISA_SRCTREE" --compat-execveat \
    --output-json "$OUT/stale.json" >/dev/null 2>&1
if [ ! -f "$OUT/stale.json" ]; then
    echo "FAIL stale_setup (no baseline manifest)"; exit 1
fi
sha_before=$(sha256sum "$OUT/stale.json" | cut -d' ' -f1)
expect_exit stale_reject 32 run \
    --vmlinux "$LISA_VMLINUX" --sysmap /dev/null --config "$LISA_CONFIG" \
    --srctree "$LISA_SRCTREE" --compat-execveat \
    --output-json "$OUT/stale.json"
sha_after=$(sha256sum "$OUT/stale.json" | cut -d' ' -f1)
if [ "$sha_before" = "$sha_after" ]; then
    PASS=$((PASS+1)); echo "PASS stale_not_clobbered"
else
    FAIL=$((FAIL+1)); FAILED="$FAILED stale_not_clobbered"; echo "FAIL stale_not_clobbered"
fi

echo "== negative: inputs =="
expect_exit neg_vmlinux_missing 32 run --vmlinux "$OUT/nope.vmlinux" \
    --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"
expect_exit neg_sysmap_missing 32 run --vmlinux "$LISA_VMLINUX" \
    --sysmap "$OUT/nope.map" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"
expect_exit neg_sysmap_empty 32 run --vmlinux "$LISA_VMLINUX" \
    --sysmap /dev/null --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"
expect_exit neg_config_missing 32 run --vmlinux "$LISA_VMLINUX" \
    --sysmap "$LISA_SYSMAP" --config "$OUT/nope.config" --srctree "$LISA_SRCTREE"
expect_exit neg_x86_image 32 run --vmlinux /bin/true \
    --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"
expect_exit neg_et_rel 32 run --vmlinux /home/meow/lisa_kernel/out/vmlinux.o \
    --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"
expect_exit neg_output_alias 32 run --vmlinux "$LISA_VMLINUX" \
    --sysmap "$LISA_SYSMAP" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE" \
    --output-json "$LISA_VMLINUX"

echo "== negative: system.map mismatch =="
# truncated map = pair mismatch (symbol check fails)
head -200 "$LISA_SYSMAP" > "$OUT/trunc.map"
expect_exit neg_sysmap_unrelated 32 run --vmlinux "$LISA_VMLINUX" \
    --sysmap "$OUT/trunc.map" --config "$LISA_CONFIG" --srctree "$LISA_SRCTREE"

echo "== negative: usage =="
expect_exit neg_no_args 2 run
expect_exit neg_bad_flag 2 run --bogus-flag x

echo
echo "PASS=$PASS FAIL=$FAIL"
[ -n "$FAILED" ] && echo "failed:$FAILED"
[ "$FAIL" -eq 0 ]
