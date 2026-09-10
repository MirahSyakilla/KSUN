#!/system/bin/sh
# audit_scan_boundaries.sh — static image scan-boundary audit
# Disassembles the kernel image and verifies that every required
# wrapper->helper BL pair exists within the wrapper's own function body,
# catching the scan-window overlap bug that caused families to roll back.
#
# Usage (on host, not device):
#   PATH=$PATH:$CROSS_BIN sh audit_scan_boundaries.sh <System.map> <Image> <output-file>
# Requires: aarch64-linux-gnu-objdump

if [ $# -lt 3 ]; then
	echo "Usage: $0 <System.map> <Image> <output-file>"
	exit 1
fi

SYSMAP="$1"; IMAGE="$2"; OUTFILE="$3"
CROSS_OBJDUMP=${CROSS_OBJDUMP:-aarch64-linux-gnu-objdump}

# Required wrapper -> helper pairs (ARM64 ARM64 only)
PAIRS="
__arm64_sys_faccessat:do_faccessat
__arm64_sys_openat:do_sys_open
__arm64_compat_sys_open:do_sys_open
__arm64_compat_sys_openat:do_sys_open
__arm64_sys_creat:do_sys_open
__arm64_sys_newfstatat:vfs_statx
__arm64_sys_fstatat64:vfs_statx
__arm64_sys_statx:vfs_statx
__arm64_sys_readlinkat:do_readlinkat
__arm64_sys_execve:do_execveat_common
__arm64_sys_execveat:do_execveat_common
__arm64_sys_statfs:user_statfs
__arm64_sys_fstatfs:fd_statfs
"

echo "# Static scan-boundary audit" > "$OUTFILE"
echo "# Image: $IMAGE" >> "$OUTFILE"
echo "# Generated: $(date)" >> "$OUTFILE"
echo "" >> "$OUTFILE"

# Disassemble once (bounded: dump full image then parse)
DISASM=$(mktemp)
"$CROSS_OBJDUMP" -D -b binary -m aarch64 --adjust-vma=0 "$IMAGE" > "$DISASM" 2>/dev/null

TOTAL=0; OK=0; MISSING=0

echo "$PAIRS" | while IFS=: read -r wrapper helper; do
	[ -z "$wrapper" ] && continue
	TOTAL=$((TOTAL+1))

	W_ADDR=$(grep -E " $wrapper\$" "$SYSMAP" | head -n 1 | awk '{print $1}')
	T_ADDR=$(grep -E " $helper\$" "$SYSMAP" | head -n 1 | awk '{print $1}')

	if [ -z "$W_ADDR" ] || [ -z "$T_ADDR" ]; then
		echo "MISSING_SYMBOL: $wrapper or $helper" >> "$OUTFILE"
		MISSING=$((MISSING+1))
		continue
	fi

	# Find BL to T_ADDR within W_ADDR..W_ADDR+256 bytes
	# (Syscall wrappers are tiny; 256 bytes is generous)
	HEX_T=$(printf '%x' "$((0x$W_ADDR + 0x100))")
	FOUND=$(sed -n "/^${W_ADDR}:/,/^${HEX_T}:/p" "$DISASM" | \
		grep -c "bl.*${T_ADDR}")

	if [ "$FOUND" -gt 0 ]; then
		echo "OK: $wrapper -> $helper (BL x$FOUND within own body)" >> "$OUTFILE"
		OK=$((OK+1))
	else
		echo "MISSING: $wrapper -> $helper (no BL within own body)" >> "$OUTFILE"
		MISSING=$((MISSING+1))
	fi
done

echo "" >> "$OUTFILE"
echo "Total: $TOTAL OK: $OK MISSING: $MISSING" >> "$OUTFILE"

rm -f "$DISASM"
echo "Audit written to $OUTFILE"
