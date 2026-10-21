#!/usr/bin/env bash
# Build ksud for aarch64-linux-android without `cross`.
#
# `cross` is not installed here, so the NDK's clang is used directly as the
# linker.  The API level matters: __system_property_read_callback, which
# userspace/ksud/src/utils.rs declares for its property reader, only exists
# in bionic from API 26 onwards.  Linking against API 21 fails with
# "undefined symbol: __system_property_read_callback".
#
# Usage: build_ksud.sh [api-level]      (default 26)
set -euo pipefail

API="${1:-26}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KSUD_DIR="${REPO_DIR}/userspace/ksud"
NDK="${ANDROID_NDK_HOME:-$HOME/bin/android-ndk-r27c}"
TC="${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin"
SYS="${NDK}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"

export PATH="$HOME/.cargo/bin:$PATH"
export CC_aarch64_linux_android="${TC}/aarch64-linux-android${API}-clang"
export AR_aarch64_linux_android="${TC}/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${TC}/aarch64-linux-android${API}-clang"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=${SYS} -I${SYS}/usr/include/aarch64-linux-android -I${SYS}/usr/include"
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-21/lib}"
export RUSTFLAGS="-C link-arg=--sysroot=${SYS} -C link-arg=-L${SYS}/usr/lib/aarch64-linux-android/${API} -C link-arg=-L${SYS}/usr/lib/aarch64-linux-android"

# The version the kernel reports, so the userspace and the kernel agree.
KSU_VERSION_OVERRIDE="${KSU_VERSION_OVERRIDE:-$(cd "${REPO_DIR}/.." && git rev-list --count HEAD)}"
KSU_VERSION_TAG_OVERRIDE="${KSU_VERSION_TAG_OVERRIDE:-$(cd "${REPO_DIR}/.." && git describe --tags --long 2>/dev/null)}"
export KSU_VERSION_OVERRIDE KSU_VERSION_TAG_OVERRIDE

cd "${KSUD_DIR}"
cargo build --target aarch64-linux-android --release

OUT="${KSUD_DIR}/target/aarch64-linux-android/release/ksud"
echo "built ${OUT} ($(stat -c%s "${OUT}") bytes) api=${API} version=${KSU_VERSION_OVERRIDE}"
