#!/bin/sh
set -eu

GKI_ROOT=$(pwd)
KSU_DIR="KernelSU-Next"
KSU_REMOTE="https://github.com/MirahSyakilla/KSUN"
KSU_BRANCH="susfs+nomount-hookless"

display_usage() {
    echo "Usage: $0 [--cleanup | <commit-or-tag>]"
    echo "  --cleanup:              Cleans up previous modifications made by the script."
    echo "  <commit-or-tag>:        Sets up or updates the KernelSU-Next to specified tag or commit."
    echo "  -h, --help:             Displays this usage information."
    echo "  (no args):              Sets up or updates KernelSU-Next from the susfs+nomount-hookless branch."
    echo "                          The KernelSU version stamp is refreshed automatically."
}

initialize_variables() {
    if test -d "$GKI_ROOT/common/drivers"; then
         DRIVER_DIR="$GKI_ROOT/common/drivers"
    elif test -d "$GKI_ROOT/drivers"; then
         DRIVER_DIR="$GKI_ROOT/drivers"
    else
         echo '[ERROR] "drivers/" directory not found.'
         exit 127
    fi

    DRIVER_MAKEFILE=$DRIVER_DIR/Makefile
    DRIVER_KCONFIG=$DRIVER_DIR/Kconfig
}

refresh_version_stamp() {
    VERSION_STAMP="$GKI_ROOT/$KSU_DIR/kernel/.ksu_git_version"

    if ! git -C "$GKI_ROOT/$KSU_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        echo "[-] $KSU_DIR is not a git checkout; version stamp left untouched."
        return 0
    fi

    KSU_VERSION=$(git -C "$GKI_ROOT/$KSU_DIR" rev-list --count HEAD 2>/dev/null || true)
    if [ -z "$KSU_VERSION" ]; then
        echo "[!] Unable to derive KernelSU-Next version from git."
        return 0
    fi

    KSU_TAG=$(git -C "$GKI_ROOT/$KSU_DIR" describe --tags --abbrev=0 2>/dev/null || true)
    {
        printf '%s\n' "$KSU_VERSION"
        printf '%s\n' "$KSU_TAG"
    } > "$VERSION_STAMP.tmp" && mv "$VERSION_STAMP.tmp" "$VERSION_STAMP"

    if [ -n "$KSU_TAG" ]; then
        echo "[+] KernelSU-Next version stamp refreshed: $KSU_VERSION / $KSU_TAG."
    else
        echo "[+] KernelSU-Next version stamp refreshed: $KSU_VERSION."
    fi
}

# Reverts modifications made by this script
perform_cleanup() {
    echo "[+] Cleaning up..."
    [ -L "$DRIVER_DIR/kernelsu" ] && rm "$DRIVER_DIR/kernelsu" && echo "[-] Symlink removed."
    grep -q "kernelsu" "$DRIVER_MAKEFILE" && sed -i '/kernelsu/d' "$DRIVER_MAKEFILE" && echo "[-] Makefile reverted."
    grep -q "drivers/kernelsu/Kconfig" "$DRIVER_KCONFIG" && sed -i '/drivers\/kernelsu\/Kconfig/d' "$DRIVER_KCONFIG" && echo "[-] Kconfig reverted."
    if [ -d "$GKI_ROOT/$KSU_DIR" ]; then
        rm -rf "$GKI_ROOT/$KSU_DIR" && echo "[-] $KSU_DIR directory deleted."
    fi
}

# Sets up or update KernelSU-Next environment
setup_kernelsu() {
    echo "[+] Setting up $KSU_DIR..."
    if ! test -d "$GKI_ROOT/$KSU_DIR"; then
        git clone -b "$KSU_BRANCH" "$KSU_REMOTE" "$GKI_ROOT/$KSU_DIR" && echo "[+] Repository cloned."
    fi
    cd "$GKI_ROOT/$KSU_DIR"
    git remote set-url origin "$KSU_REMOTE"
    git stash && echo "[-] Stashed current changes."

    git fetch --tags origin "$KSU_BRANCH" && echo "[+] Repository updated."
    if [ -z "${1-}" ]; then
        git checkout -B "$KSU_BRANCH" "origin/$KSU_BRANCH" && echo "[-] Switched to $KSU_BRANCH branch."
    else
        git checkout "$1" && echo "[-] Checked out $1." || echo "[-] Checkout default branch"
    fi
    refresh_version_stamp
    cd "$DRIVER_DIR"
    ln -sf "$(realpath --relative-to="$DRIVER_DIR" "$GKI_ROOT/$KSU_DIR/kernel")" "kernelsu" && echo "[+] Symlink created."

    # Add entries in Makefile and Kconfig if not already existing
    grep -q "kernelsu" "$DRIVER_MAKEFILE" || printf "\nobj-\$(CONFIG_KSU) += kernelsu/\n" >> "$DRIVER_MAKEFILE" && echo "[+] Modified Makefile."
    grep -q "source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" || sed -i "/endmenu/i\source \"drivers/kernelsu/Kconfig\"" "$DRIVER_KCONFIG" && echo "[+] Modified Kconfig."
    echo '[+] Done.'
}

# Process command-line arguments
if [ "$#" -eq 0 ]; then
    initialize_variables
    setup_kernelsu
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    display_usage
elif [ "$1" = "--cleanup" ]; then
    initialize_variables
    perform_cleanup
else
    initialize_variables
    setup_kernelsu "$@"
fi
