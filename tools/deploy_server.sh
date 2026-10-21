#!/usr/bin/env bash
# Provision a build server from this repository alone.
#
# The repository is the source of truth.  A rented server can disappear at
# any time, so everything the server needs is pushed to it from here
# rather than being edited in place on the server.
#
# Usage:
#   deploy_server.sh <host> [kernel-source]
#
#   host           ssh target, e.g. meowing@203.0.113.10
#   kernel-source  local kernel tree to publish (default: the parent of
#                  this repository, which holds KernelSU-Next/)
#
# After this runs the server has:
#   ~/kernels/meowkernel   the kernel tree, built from the same source
#   ~/bin/gendc|genkz|genkp|kbuild.env|set_test_version.sh
#   ~/AnyKernel3            the release staging directory, including the
#                           kernel+dtbo-only anykernel.sh from this repo
set -euo pipefail

HOST="${1:?usage: deploy_server.sh <host> [kernel-source]}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_SRC="${2:-$(dirname "$REPO_DIR")}"

[ -d "$KERNEL_SRC" ] || { echo "no kernel source at $KERNEL_SRC" >&2; exit 1; }

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)
RSYNC_OPTS=(-aH --partial -e "ssh -o BatchMode=yes -o ConnectTimeout=15")

echo "==> host      : $HOST"
echo "==> repo      : $REPO_DIR"
echo "==> kernelsrc : $KERNEL_SRC"

echo "==> preparing remote directories"
ssh "${SSH_OPTS[@]}" "$HOST" 'mkdir -p ~/kernels ~/bin ~/AnyKernel3 ~/KernelReleases'

echo "==> publishing the kernel tree"
rsync "${RSYNC_OPTS[@]}" \
  --exclude='.git/' --exclude='out/' --exclude='__pycache__/' \
  --exclude='KernelSU-Next/validation/' \
  --exclude='KernelSU-Next/userspace/*/target/' \
  "$KERNEL_SRC"/ "$HOST:~/kernels/meowkernel/"

echo "==> publishing the build wrappers"
rsync "${RSYNC_OPTS[@]}" "$REPO_DIR/tools/build/" "$HOST:~/bin/"

echo "==> publishing the release staging directory"
# The AnyKernel3 directory carries the magiskboot tooling and the META-INF
# update-binary that the installer needs, so the whole directory is
# published.  The anykernel.sh in this repository is authoritative and is
# written last so it always wins over the copy inside that directory.
AK3_SRC="${AK3_SRC:-$HOME/AnyKernel3}"
if [ -d "$AK3_SRC" ]; then
  rsync "${RSYNC_OPTS[@]}" \
    --exclude='Image' --exclude='dtb' --exclude='dtbo.img' --exclude='version.txt' \
    "$AK3_SRC"/ "$HOST:~/AnyKernel3/"
else
  echo "    (no local AnyKernel3 at $AK3_SRC; remote copy left untouched)"
fi
rsync "${RSYNC_OPTS[@]}" "$REPO_DIR/tools/anykernel/anykernel.sh" "$HOST:~/AnyKernel3/anykernel.sh"
ssh "${SSH_OPTS[@]}" "$HOST" 'chmod +x ~/bin/gendc ~/bin/genkz ~/bin/genkp ~/bin/set_test_version.sh 2>/dev/null || true'

echo "==> tagging the release"
ssh "${SSH_OPTS[@]}" "$HOST" \
  'KERNEL_SRC=$HOME/kernels/meowkernel ~/bin/set_test_version.sh "${1:-v2.1}" "${2:-test01}"' \
  _ "${VERSION_BASE:-v2.1}" "${VERSION_TEST:-test01}" || true

echo "==> remote state"
ssh "${SSH_OPTS[@]}" "$HOST" 'ls -1 ~/bin; echo; cat ~/AnyKernel3/version.txt'

echo
echo "Done.  Build with:  ssh $HOST 'cd ~/kernels/meowkernel && ~/bin/gendc && ~/bin/genkz'"
