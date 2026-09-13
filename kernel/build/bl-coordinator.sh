#!/bin/sh
# KernelSU-Next branch-link two-stage build coordinator (Phase 19).
#
# Invoked from arch/arm64/Makefile.postlink after the vmlinux link.  Runs a
# bounded analyze->relink fixed point:
#
#   stage 0: this link used the bootstrap manifest data object
#   stage 1: analyze vmlinux/System.map -> generated manifest .c/.h/.o
#   stage 2: relink vmlinux with the generated object, regenerate System.map
#   stage 3: re-analyze final vmlinux; require semantic fixed point
#   READY:   nonce + digests published; packaging may proceed
#
# Fail-closed: any failure removes vmlinux/System.map/Image and the READY
# stamp and exits nonzero, which fails the parent vmlinux recipe.
#
# Environment (from Makefile.postlink):
#   KSU_SRCTREE   absolute kernel source tree
#   KSU_OBJTREE   absolute object tree (O=)
#   KSU_KSU_DIR   absolute KernelSU-Next/kernel directory
#   KSU_NONCE     per-generation nonce
#   KSU_GEN_SRC   generated manifest .c path (object tree)
#   KSU_GEN_IDS   generated manifest ids .h path (object tree)
#   KSU_GEN_OBJ   generated manifest .o path (object tree)
#   KSU_ANALYZER  analyzer invocation prefix (python3 + script path)
#   KSU_MAKE      $(MAKE) for the relink recursion

set -u

SRCTREE="${KSU_SRCTREE:?}"
OBJTREE="${KSU_OBJTREE:?}"
KSU_DIR="${KSU_KSU_DIR:?}"
NONCE="${KSU_NONCE:?}"
GEN_SRC="${KSU_GEN_SRC:?}"
GEN_IDS="${KSU_GEN_IDS:?}"
GEN_OBJ="${KSU_GEN_SRC%.c}.o"
ANALYZER="${KSU_ANALYZER:?}"
MAKE="${KSU_MAKE:-make}"

VMLINUX="$OBJTREE/vmlinux"
SYSMAP="$OBJTREE/System.map"
IMAGE="$OBJTREE/arch/arm64/boot/Image"
STAGE_DIR="$OBJTREE/.ksu-bl"
TX="$STAGE_DIR/tx-$NONCE"

log() { echo "bl-coordinator: $*"; }
fail() {
	log "FAIL: $*"
	rm -f "$VMLINUX" "$SYSMAP" "$IMAGE"
	rm -f "$TX/READY" "$TX"/*.json "$TX"/*.c "$TX"/*.h 2>/dev/null
	rm -f "$GEN_SRC" "$GEN_IDS" "$GEN_OBJ" 2>/dev/null
	exit 1
}

mkdir -p "$TX" || fail "cannot create $TX"

# ---- stage 0 marker ----------------------------------------------------------
echo "$NONCE" > "$TX/stage0"

# ---- stage 1: analyze the bootstrap link --------------------------------------
log "stage 1: analyzing bootstrap vmlinux"
$ANALYZER \
	--vmlinux "$VMLINUX" \
	--sysmap "$SYSMAP" \
	--config "$OBJTREE/.config" \
	--srctree "$SRCTREE" \
	--nonce "$NONCE" \
	--output-json "$TX/manifest_stage1.json" \
	--output-ids "$GEN_IDS" \
	--output-object "$GEN_SRC" \
	|| fail "stage-1 analysis failed"
echo "$NONCE" > "$TX/stage1"

# ---- stage 2: relink with the generated object --------------------------------
log "stage 2: relinking vmlinux with generated manifest object"
rm -f "$VMLINUX" "$SYSMAP"
# The relink re-enters the top-level Makefile with the coordinator disabled
# for this invocation (stage=final guard), preserving O= and tool variables.
KSU_BL_STAGE=final KSU_BL_NONCE="$NONCE" \
	"$MAKE" -C "$OBJTREE" -f "$SRCTREE/Makefile" O="$OBJTREE" vmlinux \
	|| fail "stage-2 relink failed"
[ -f "$VMLINUX" ] || fail "stage-2 produced no vmlinux"
[ -f "$SYSMAP" ] || fail "stage-2 produced no System.map"
echo "$NONCE" > "$TX/stage2"

# ---- stage 3: independent final-image analysis --------------------------------
log "stage 3: analyzing final vmlinux"
$ANALYZER \
	--vmlinux "$VMLINUX" \
	--sysmap "$SYSMAP" \
	--config "$OBJTREE/.config" \
	--srctree "$SRCTREE" \
	--nonce "$NONCE" \
	--output-json "$TX/manifest_stage3.json" \
	|| fail "stage-3 analysis failed"

# fixed point: the stage-3 payload must equal the stage-1 payload (semantic
# census invariance across the relink).  Compare the analyzer's payload
# digest fields.
P1=$(grep -o '"payload_sha256": "[0-9a-f]*"' "$TX/manifest_stage1.json" | head -1)
P3=$(grep -o '"payload_sha256": "[0-9a-f]*"' "$TX/manifest_stage3.json" | head -1)
if [ "$P1" != "$P3" ]; then
	log "fixed-point check: stage1=$P1 stage3=$P3"
	fail "manifest did not converge (bounded fixed point exceeded)"
fi
log "fixed point reached: $P1"

# ---- READY --------------------------------------------------------------------
VM_SHA=$(sha256sum "$VMLINUX" | cut -d' ' -f1)
cat > "$TX/READY" <<EOF
nonce=$NONCE
vmlinux_sha256=$VM_SHA
payload=$P1
EOF
log "READY published (vmlinux $VM_SHA)"
exit 0
