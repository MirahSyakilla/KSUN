#!/bin/sh
# KernelSU-Next branch-link two-stage build coordinator (Phase 20).
#
# Invoked from arch/arm64/Makefile.postlink after the vmlinux link.  Runs a
# bounded analyze->relink fixed point:
#
#   stage 0: this link used the bootstrap manifest data object
#   stage 1: analyze vmlinux/System.map -> generated manifest .c/.h
#            (staged in the tx dir, atomically moved into the object tree)
#   stage 2: relink vmlinux with the generated object, regenerate System.map
#            (KSU_BL_STAGE=final; postlink makefile no-ops this re-entry)
#   stage 3: re-analyze final vmlinux; require semantic fixed point
#            (payload digest equality, strict validation -- empty/short
#            digests FAIL, per the Phase 20 adversarial review)
#   READY:   nonce + digests published; a second bounded iteration runs if
#            the payload moved; never more than 2.
#
# Fail-closed: any failure removes vmlinux/System.map/Image and the READY
# stamp and exits nonzero, which fails the parent vmlinux recipe.
# Interrupted builds: trap-based cleanup + .DELETE_ON_ERROR + the READY
# consumer gate in the packaging step close the truncated-vmlinux window.

set -eu

SRCTREE="${KSU_SRCTREE:?}"
OBJTREE="${KSU_OBJTREE:?}"
KSU_DIR="${KSU_KSU_DIR:?}"
NONCE="${KSU_NONCE:?}"
GEN_SRC="${KSU_GEN_SRC:?}"
GEN_IDS="${KSU_GEN_IDS:?}"
ANALYZER="${KSU_ANALYZER:?}"
MAKE="${KSU_MAKE:?}"
READELF="${KSU_READELF:-llvm-readelf}"
NM="${KSU_NM:-llvm-nm}"

VMLINUX="$OBJTREE/vmlinux"
SYSMAP="$OBJTREE/System.map"
IMAGE="$OBJTREE/arch/arm64/boot/Image"
STAGE_DIR="$OBJTREE/.ksu-bl"
TX="$STAGE_DIR/tx-current"
MAX_ITER=2

log() { echo "bl-coordinator: $*"; }

cleanup() {
	rm -f "$VMLINUX" "$SYSMAP" "$IMAGE"
	rm -rf "$TX"
	rm -f "$STAGE_DIR/stage-guard" "$GEN_SRC" "$GEN_IDS"
}
fail() {
	log "FAIL: $*"
	cleanup
	exit 1
}
trap 'fail "interrupted (signal)"' INT TERM HUP

payload_of() {
	# strictly one well-formed 64-hex payload_sha256 or fail (Phase 20
	# adversarial review: empty/multiple/short digests must fail closed)
	_f="$1"
	_v=$(grep -o '"payload_sha256": "[0-9a-f]\{64\}"' "$_f" | wc -l)
	if [ "$_v" != "1" ]; then
		fail "payload digest missing/ambiguous in $_f ($_v matches)"
	fi
	grep -o '"payload_sha256": "[0-9a-f]\{64\}"' "$_f" \
		| sed 's/.*"\([0-9a-f]\{64\}\)".*/\1/'
}

# content-derived transaction dir: fresh per generation
rm -rf "$TX"
mkdir -p "$TX" || fail "cannot create $TX"

# ---- stage 0 marker ----------------------------------------------------------
# A stale stage-guard from a previous run would permanently no-op all
# subsequent postlinks (Phase 20 adversarial review finding 9).  The guard
# is set fresh here and cleared at READY/fail.
echo "$NONCE" > "$TX/stage0"
echo "final" > "$STAGE_DIR/stage-guard"

ANALYZER_COMMON="--config $OBJTREE/.config --srctree $SRCTREE --nonce $NONCE --readelf $READELF --nm $NM"

# Source-shape probes. These MUST mirror the Kbuild probes in
# drivers/kernelsu/Kbuild exactly, otherwise the analyzer validates routes for a
# different exec-helper ABI than the compiler actually built and stage 1 fails
# with POLICY_DRIFT on the exec routes.
#
# Kbuild: grep -Fq "__do_execve_file" fs/exec.c        -> KSU_EXECVE_LEGACY_HELPER
#         else grep -Fq "do_execveat_common" fs/exec.c -> KSU_EXECVE_COMMON_HELPER
#         grep -Fq "__NR_execveat" unistd32.h          -> KSU_HAS_COMPAT_EXECVEAT
#
# Note this is deliberately NOT derived from LINUX_VERSION_CODE: exec helper
# layout is backported independently of the nominal kernel version (5.4 trees
# can carry the common helper, and vice versa).
if grep -Fq "__do_execve_file" "$SRCTREE/fs/exec.c" 2>/dev/null; then
	log "probe: exec helper layout = legacy"
elif grep -Fq "do_execveat_common" "$SRCTREE/fs/exec.c" 2>/dev/null; then
	log "probe: exec helper layout = common (--exec-common)"
	ANALYZER_COMMON="$ANALYZER_COMMON --exec-common"
else
	log "probe: exec helper layout undetermined; assuming legacy"
fi
if grep -Fq "__NR_execveat" "$SRCTREE/arch/arm64/include/asm/unistd32.h" 2>/dev/null; then
	log "probe: compat execveat present (--compat-execveat)"
	ANALYZER_COMMON="$ANALYZER_COMMON --compat-execveat"
else
	log "probe: compat execveat absent"
fi

# ---- stage 1: analyze the bootstrap link --------------------------------------
log "stage 1: analyzing bootstrap vmlinux"
$ANALYZER \
	--vmlinux "$VMLINUX" \
	--sysmap "$SYSMAP" \
	$ANALYZER_COMMON \
	--output-json "$TX/manifest_stage1.json" \
	--output-ids "$TX/bl_manifest_ids.h" \
	--output-object "$TX/bl_manifest_gen.c" \
	|| fail "stage-1 analysis failed"
P1=$(payload_of "$TX/manifest_stage1.json") || exit 1
echo "$NONCE" > "$TX/stage1"

# atomic publication of the generated artifacts into the compile path
mv "$TX/bl_manifest_ids.h" "$GEN_IDS"
mv "$TX/bl_manifest_gen.c" "$GEN_SRC"


# stage-1 payload digest (fixed-point reference).  P1 was assigned from
# the stage-1 manifest above; it MUST stay set, because stage 3 passes it
# to the analyzer as --expect-payload.  Clearing it here turned the
# fixed-point gate into a no-op (the analyzer skips the comparison when
# the expected digest is empty) while still reporting "fixed point
# verified" in the log.
[ -n "$P1" ] || fail "stage-1 payload digest missing"

# ---- stage 2: relink with the generated object --------------------------------
log "stage 2: relinking vmlinux with generated manifest object"
rm -f "$VMLINUX" "$SYSMAP"
KSU_BL_STAGE=final \
	"$MAKE" -C "$OBJTREE" -f "$SRCTREE/Makefile" O="$OBJTREE" vmlinux \
	|| fail "stage-2 relink failed"
[ -f "$VMLINUX" ] || fail "stage-2 produced no vmlinux"
[ -f "$SYSMAP" ] || fail "stage-2 produced no System.map"
echo "$NONCE" > "$TX/stage2"

# Image is produced by the Image target AFTER vmlinux postlink. Stage 3
# identity needs it now; synthesize the same way arch/arm64/boot/Makefile
# does so a clean tree (no leftover Image) can still finish.
if [ ! -f "$IMAGE" ]; then
	mkdir -p "$(dirname "$IMAGE")"
	if command -v llvm-objcopy >/dev/null 2>&1; then
		OBJCOPY_BIN=llvm-objcopy
	else
		OBJCOPY_BIN=aarch64-linux-gnu-objcopy
	fi
	log "producing Image for stage-3 identity via $OBJCOPY_BIN"
	"$OBJCOPY_BIN" -O binary -R .note -R .note.gnu.build-id -R .comment -S \
		"$VMLINUX" "$IMAGE" || fail "cannot produce Image for stage-3"
fi

# ---- stage 3: independent final-image analysis, bounded fixed point -----------
# The analyzer's --stage2 --expect-payload gate returns EXIT_IDENTITY (16)
# on payload drift.  One bounded regeneration iteration is allowed: rebuild
# the manifest from the FINAL image and relink once more.  A second drift
# fails closed.
iter=1
while :; do
	log "stage 3: independent analysis of final vmlinux (iter $iter)"
	set +e
	$ANALYZER \
		--vmlinux "$VMLINUX" \
		--sysmap "$SYSMAP" \
		$ANALYZER_COMMON \
		--image "$OBJTREE/arch/arm64/boot/Image" \
		--stage2 --expect-payload "$P1" \
		--output-json "$TX/manifest_final.json"
	A_RC=$?
	set -e
	if [ "$A_RC" = "0" ]; then
		PF=$(payload_of "$TX/manifest_final.json") || exit 1
		log "fixed point verified: $PF (iter $iter)"
		break
	fi
	if [ "$A_RC" != "16" ]; then
		fail "stage-3 analysis failed (rc=$A_RC)"
	fi
	log "payload drifted on iter $iter"
	if [ "$iter" -ge "$MAX_ITER" ]; then
		fail "manifest did not converge within $MAX_ITER iterations"
	fi
	log "regenerating manifest from the final image"
	$ANALYZER \
		--vmlinux "$VMLINUX" \
		--sysmap "$SYSMAP" \
		$ANALYZER_COMMON \
		--output-json "$TX/manifest_stage1.json" \
		--output-ids "$TX/bl_manifest_ids.h" \
		--output-object "$TX/bl_manifest_gen.c" \
		|| fail "regeneration analysis failed"
	mv "$TX/bl_manifest_ids.h" "$GEN_IDS"
	mv "$TX/bl_manifest_gen.c" "$GEN_SRC"
	P1=$(payload_of "$TX/manifest_stage1.json") || exit 1
	rm -f "$VMLINUX" "$SYSMAP"
	KSU_BL_STAGE=final \
		"$MAKE" -C "$OBJTREE" -f "$SRCTREE/Makefile" O="$OBJTREE" vmlinux \
		|| fail "iteration-$iter relink failed"
	[ -f "$VMLINUX" ] || fail "iteration-$iter produced no vmlinux"
	iter=$((iter + 1))
done

# ---- READY --------------------------------------------------------------------
VM_SHA=$(sha256sum "$VMLINUX" | cut -d' ' -f1)
[ -n "$VM_SHA" ] || fail "vmlinux digest unavailable"
cat > "$TX/READY" <<EOF
nonce=$NONCE
vmlinux_sha256=$VM_SHA
payload=$PF
EOF
rm -f "$STAGE_DIR/stage-guard"
log "READY published (vmlinux $VM_SHA)"
exit 0
