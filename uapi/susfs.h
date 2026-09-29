#ifndef __KSU_UAPI_SUSFS_H
#define __KSU_UAPI_SUSFS_H

#include <linux/types.h>
#include <uapi/linux/utsname.h>

#define KSU_SUSFS_MAGIC 0xFAFAFAFA

#define KSU_SUSFS_CMD_ADD_SUS_PATH 0x55550
#define KSU_SUSFS_CMD_ADD_SUS_PATH_LOOP 0x55553
#define KSU_SUSFS_CMD_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define KSU_SUSFS_CMD_ADD_SUS_KSTAT 0x55570
#define KSU_SUSFS_CMD_UPDATE_SUS_KSTAT 0x55571
#define KSU_SUSFS_CMD_ADD_SUS_KSTAT_STATICALLY 0x55572
#define KSU_SUSFS_CMD_SET_UNAME 0x55590
#define KSU_SUSFS_CMD_ENABLE_LOG 0x555a0
#define KSU_SUSFS_CMD_SET_CMDLINE_OR_BOOTCONFIG 0x555b0
#define KSU_SUSFS_CMD_ADD_OPEN_REDIRECT 0x555c0
#define KSU_SUSFS_CMD_SHOW_VERSION 0x555e1
#define KSU_SUSFS_CMD_SHOW_ENABLED_FEATURES 0x555e2
#define KSU_SUSFS_CMD_SHOW_VARIANT 0x555e3
#define KSU_SUSFS_CMD_ENABLE_AVC_LOG_SPOOFING 0x60010
#define KSU_SUSFS_CMD_ADD_SUS_MAP 0x60020

/*
 * Suspect-uid oracle policy. GETSIZE reports how many bytes SETLIST will
 * accept so the caller learns the bound without the kernel ever trusting a
 * length it did not choose; SETLIST replaces the whole table.
 */
#define KSU_SUSFS_CMD_SUSPECT_UID_GETSIZE 0x555d0
#define KSU_SUSFS_CMD_SUSPECT_UID_SETLIST 0x555d1
#define KSU_SUSFS_MAX_SUSPECT_UIDS 64

#define KSU_SUSFS_MAX_PATHNAME 256
#define KSU_SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE 8192
#define KSU_SUSFS_ENABLED_FEATURES_SIZE 8192
#define KSU_SUSFS_MAX_VERSION_BUFSIZE 16
#define KSU_SUSFS_MAX_VARIANT_BUFSIZE 16

#define KSU_SUSFS_ERR_CMD_NOT_SUPPORTED 126

#define KSU_SUSFS_KSTAT_SPOOF_INO (1U << 0)
#define KSU_SUSFS_KSTAT_SPOOF_DEV (1U << 1)
#define KSU_SUSFS_KSTAT_SPOOF_NLINK (1U << 2)
#define KSU_SUSFS_KSTAT_SPOOF_SIZE (1U << 3)
#define KSU_SUSFS_KSTAT_SPOOF_ATIME_TV_SEC (1U << 4)
#define KSU_SUSFS_KSTAT_SPOOF_ATIME_TV_NSEC (1U << 5)
#define KSU_SUSFS_KSTAT_SPOOF_MTIME_TV_SEC (1U << 6)
#define KSU_SUSFS_KSTAT_SPOOF_MTIME_TV_NSEC (1U << 7)
#define KSU_SUSFS_KSTAT_SPOOF_CTIME_TV_SEC (1U << 8)
#define KSU_SUSFS_KSTAT_SPOOF_CTIME_TV_NSEC (1U << 9)
#define KSU_SUSFS_KSTAT_SPOOF_BLOCKS (1U << 10)
#define KSU_SUSFS_KSTAT_SPOOF_BLKSIZE (1U << 11)

enum ksu_susfs_uid_scheme {
	KSU_SUSFS_UID_NON_APP_PROC = 0,
	KSU_SUSFS_UID_ROOT_PROC_EXCEPT_SU_PROC = 1,
	KSU_SUSFS_UID_NON_SU_PROC = 2,
	KSU_SUSFS_UID_UMOUNTED_APP_PROC = 3,
	KSU_SUSFS_UID_UMOUNTED_PROC = 4,
};

struct ksu_susfs_path_cmd {
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
	int err;
};

struct ksu_susfs_open_redirect_cmd {
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
	char redirected_pathname[KSU_SUSFS_MAX_PATHNAME];
	int uid_scheme;
	int err;
};

struct ksu_susfs_hide_mounts_cmd {
	bool enabled;
	int err;
};

struct ksu_susfs_kstat_cmd {
	int is_statically;
	unsigned long target_ino;
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
	unsigned long spoofed_ino;
	unsigned long spoofed_dev;
	unsigned int spoofed_nlink;
	long long spoofed_size;
	long spoofed_atime_tv_sec;
	unsigned long spoofed_atime_tv_nsec;
	long spoofed_mtime_tv_sec;
	unsigned long spoofed_mtime_tv_nsec;
	long spoofed_ctime_tv_sec;
	unsigned long spoofed_ctime_tv_nsec;
	long long spoofed_blocks;
	long spoofed_blksize;
	int flags;
	int err;
};

struct ksu_susfs_uname_cmd {
	char release[__NEW_UTS_LEN + 1];
	char version[__NEW_UTS_LEN + 1];
	int err;
};

struct ksu_susfs_log_cmd {
	bool enabled;
	int err;
};

struct ksu_susfs_cmdline_cmd {
	char fake_cmdline_or_bootconfig
		[KSU_SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE];
	int err;
};

struct ksu_susfs_avc_cmd {
	bool enabled;
	int err;
};

/*
 * Packed __u32 uid list, capped at KSU_SUSFS_MAX_SUSPECT_UIDS. count is
 * informational on the way out: the kernel clamps to its own table bound
 * rather than trusting whatever the caller claimed.
 */
struct ksu_susfs_suspect_uid_cmd {
	__u32 count;
	__u32 uids[KSU_SUSFS_MAX_SUSPECT_UIDS];
	int err;
};

struct ksu_susfs_suspect_uid_size_cmd {
	__u32 max_uids;
	int err;
};

struct ksu_susfs_map_cmd {
	char target_pathname[KSU_SUSFS_MAX_PATHNAME];
	int err;
};

struct ksu_susfs_enabled_features_cmd {
	char enabled_features[KSU_SUSFS_ENABLED_FEATURES_SIZE];
	int err;
};

struct ksu_susfs_variant_cmd {
	char susfs_variant[KSU_SUSFS_MAX_VARIANT_BUFSIZE];
	int err;
};

struct ksu_susfs_version_cmd {
	char susfs_version[KSU_SUSFS_MAX_VERSION_BUFSIZE];
	int err;
};

#endif // __KSU_UAPI_SUSFS_H
