#!/usr/bin/env bash
# Tag a kernel build with a test identifier.
#
# The identifier is written to two places that must never drift apart:
#   * $HOME/AnyKernel3/version.txt     -> names the published release archive
#   * $KERNEL_SRC/arch/arm64/configs/vendor/localversion.config
#                                       -> becomes the running kernel's
#                                          uname string, so the build that is
#                                          actually running can be identified
#
# Run it where the kernel tree and AnyKernel3 live (the build server), or
# locally with KERNEL_SRC pointing at a local tree.
#
# Usage: set_test_version.sh <base> <testid>
#   base   e.g. v2.1
#   testid e.g. test01
set -euo pipefail

BASE="${1:?usage: set_test_version.sh <base> <testid>}"
TESTID="${2:?usage: set_test_version.sh <base> <testid>}"
KERNEL_SRC="${KERNEL_SRC:-$HOME/kernels/meowkernel}"
AK3_DIR="${AK3_DIR:-$HOME/AnyKernel3}"

VERSION="${BASE}-${TESTID}"
LOCALVERSION="CONFIG_LOCALVERSION=\"-MeowKernel-${VERSION}\""

[ -d "$KERNEL_SRC" ] || { echo "no kernel tree at $KERNEL_SRC" >&2; exit 1; }
[ -d "$AK3_DIR" ] || { echo "no AnyKernel3 dir at $AK3_DIR" >&2; exit 1; }

printf '%s\n' "$VERSION" > "$AK3_DIR/version.txt"
cat > "$KERNEL_SRC/arch/arm64/configs/vendor/localversion.config" <<CFG
${LOCALVERSION}
CONFIG_LOCALVERSION_AUTO=n
CFG

echo "version.txt:"
sed 's/^/  /' "$AK3_DIR/version.txt"
echo "localversion.config:"
sed 's/^/  /' "$KERNEL_SRC/arch/arm64/configs/vendor/localversion.config"
