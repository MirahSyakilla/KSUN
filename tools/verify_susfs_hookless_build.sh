#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-/home/meow/hiding-stuff/lisa_kernel/out}"
CONFIG_FILE="$OUT_DIR/.config"
SYSTEM_MAP="$OUT_DIR/System.map"
VMLINUX="$OUT_DIR/vmlinux"

die() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

check_file() {
	local path="$1"

	[ -e "$path" ] || die "missing required file: $path"
}

check_config_enabled() {
	local key="$1"

	if ! rg -q "^${key}=y$" "$CONFIG_FILE"; then
		die "required config is not enabled: $key"
	fi
	printf 'PASS: %s=y\n' "$key"
}

check_symbol() {
	local symbol="$1"

	if ! rg -q "[[:space:]]${symbol}($|\\.)" "$SYSTEM_MAP"; then
		die "required symbol missing from System.map: $symbol"
	fi
	printf 'PASS: symbol %s\n' "$symbol"
}

printf 'Checking hookless SUSFS build in %s\n' "$OUT_DIR"
check_file "$CONFIG_FILE"
check_file "$SYSTEM_MAP"
check_file "$VMLINUX"

printf '\nConfig checks\n'
check_config_enabled CONFIG_KSU
check_config_enabled CONFIG_KSU_HOOK_CORE
check_config_enabled CONFIG_KSU_HOOKLESS_SUSFS
check_config_enabled CONFIG_KPROBES
check_config_enabled CONFIG_KRETPROBES
check_config_enabled CONFIG_HAVE_SYSCALL_TRACEPOINTS
check_config_enabled CONFIG_KALLSYMS
check_config_enabled CONFIG_KALLSYMS_ALL

printf '\nCore hookless SUSFS symbols\n'
check_symbol ksu_susfs_handle_compat
check_symbol ksu_susfs_init
check_symbol ksu_susfs_exit
check_symbol ksu_susfs_kstat_init
check_symbol ksu_susfs_procfs_init

printf '\nVFS / proc / mm hook targets\n'
check_symbol vfs_getattr_nosec
check_symbol vfs_create_mount
check_symbol clone_mnt
check_symbol cleanup_mnt
check_symbol proc_pid_maps_operations
check_symbol proc_pid_smaps_operations
check_symbol proc_pid_smaps_rollup_operations
check_symbol proc_pagemap_operations
check_symbol proc_mem_operations
check_symbol proc_map_files_operations
check_symbol proc_map_files_inode_operations
check_symbol tid_map_files_dentry_operations
check_symbol proc_map_files_instantiate
check_symbol proc_fdinfo_file_operations
check_symbol proc_mounts_operations
check_symbol proc_mountinfo_operations
check_symbol proc_mountstats_operations

printf '\nMount consistency guardrails\n'
if rg -q '^CONFIG_KSU_HACK_ARM64_BRANCH_LINK=y$' "$CONFIG_FILE"; then
	check_symbol ksu_branch_link_patch_init
	check_symbol ksu_do_filp_open
	check_symbol ksu_susfs_open_redirect_getname
	check_symbol ksu_susfs_set_open_redirect_ready
	check_symbol do_filp_open
	check_symbol ksu_susfs_set_mount_runtime_ready
	check_symbol ksu_susfs_should_hide_new_vfsmount
	check_symbol ksu_susfs_should_hide_cloned_mount
	check_symbol ksu_susfs_handle_cleanup_mnt
else
	check_symbol ksu_susfs_vfs_create_mount_handler
	check_symbol ksu_susfs_clone_mnt_handler
	check_symbol ksu_susfs_cleanup_mnt_pre
fi
check_symbol ksu_susfs_fdinfo_show
check_symbol ksu_susfs_visible_mnt_id

printf '\nSummary\n'
printf 'PASS: build artifacts contain the required hookless SUSFS code and symbol dependencies.\n'
printf 'NOTE: this is a static verification pass; runtime boot testing is still required for behavioral proof.\n'
