#ifndef __KSU_NOMOUNT_H
#define __KSU_NOMOUNT_H

#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/types.h>

/* Module visible ABI version.  Bumped whenever the transport or the wire
 * format changes so that a mismatched client is detected instead of being
 * silently mis-parsed. */
#define KSU_NOMOUNT_VERSION 15
/* Transport revision: 1 was the Generic Netlink family, 2 is the keyring
 * transport. */
#define KSU_NOMOUNT_TRANSPORT_VERSION 2
#define KSU_NOMOUNT_KEY_TYPE_NAME "nomount"
#define KSU_NOMOUNT_MAGIC_SIG 0x4E4F4D4F554E54ULL
/* The kernel replaces the signature with this marker once it has applied the
 * command, so that the client can tell a processed command apart from a
 * command the kernel refused before it ran. */
#define KSU_NOMOUNT_MAGIC_DONE 0x444F4E45ULL

#define KSU_NOMOUNT_HASH_BITS 12
#define KSU_NOMOUNT_UID_HASH_BITS 4
#define KSU_NOMOUNT_MAX_PATH PATH_MAX

#define KSU_NOMOUNT_FLAG_IS_DIR (1U << 1)
#define KSU_NOMOUNT_FLAG_WHITEOUT (1U << 2)
#define KSU_NOMOUNT_FLAG_INTERNAL (1U << 31)

enum ksu_nomount_cmd {
	KSU_NOMOUNT_CMD_UNSPEC = 0,
	KSU_NOMOUNT_CMD_GET_VERSION,
	KSU_NOMOUNT_CMD_ADD_RULE,
	KSU_NOMOUNT_CMD_DEL_RULE,
	KSU_NOMOUNT_CMD_CLEAR_ALL,
	KSU_NOMOUNT_CMD_ADD_UID,
	KSU_NOMOUNT_CMD_DEL_UID,
	KSU_NOMOUNT_CMD_GET_LIST,
	__KSU_NOMOUNT_CMD_MAX,
};
#define KSU_NOMOUNT_CMD_MAX (__KSU_NOMOUNT_CMD_MAX - 1)

/*
 * Command payload exchanged with the userspace client.  The client hands the
 * kernel the address of this structure through the key payload; the kernel
 * reads it, applies the command and writes the result back.
 *
 *   u64 magic        KSU_NOMOUNT_MAGIC_SIG
 *   u32 cmd          enum ksu_nomount_cmd
 *   u32 target_uid   uid argument of the UID commands
 *   s32 status       result of the command, 0 on success
 *   u32 data_size    number of valid bytes in buffer
 *   u64 arg1         command argument, continuation token of the rule dump
 *   u8  buffer[]     command payload
 *
 * The layout is identical on 32 bit and 64 bit clients, so the client uses
 * fixed width types for the 64 bit members.
 */
#define KSU_NOMOUNT_PAYLOAD_BUFFER_SIZE 8160

struct ksu_nomount_payload {
	u64 magic;
	u32 cmd;
	u32 target_uid;
	s32 status;
	u32 data_size;
	u64 arg1;
	char buffer[KSU_NOMOUNT_PAYLOAD_BUFFER_SIZE];
};

struct ksu_nomount_version {
	u32 abi;
	u32 transport;
};

struct ksu_nomount_dump_state {
	u32 bucket;
	u32 index;
};

/* Stack-owned by branch-link wrappers while a *at() operation resolves a
 * relative name.  The filename constructor uses the innermost scope so a
 * directory fd, rather than current->fs->pwd, supplies the base path. */
struct ksu_nomount_lookup_scope {
	struct hlist_node node;
	struct task_struct *task;
	int dfd;
	bool active;
};

struct filename;
struct inode;
struct kstat;
struct kstatfs;
struct path;
struct vm_area_struct;

bool ksu_nomount_relative_rule_may_match(const char *path, size_t len);
void ksu_nomount_init(void);
void ksu_nomount_exit(void);

int ksu_nomount_add_rule(const char *virtual_path, const char *real_path,
			 u32 flags);
int ksu_nomount_del_rule(const char *virtual_path);
int ksu_nomount_del_rules(char **virtual_paths, unsigned int count);
void ksu_nomount_clear_all(void);
int ksu_nomount_add_uid(uid_t uid);
int ksu_nomount_del_uid(uid_t uid);
int ksu_nomount_get_dump_rule(struct ksu_nomount_dump_state *state,
			      char *virtual_path, size_t virtual_size,
			      char *real_path, size_t real_size, u32 *flags);

/* Called from the runtime hooks in hooks.c. */
struct filename *ksu_nomount_handle_getname(struct filename *name);
void ksu_nomount_lookup_scope_enter(struct ksu_nomount_lookup_scope *scope,
				    int dfd);
void ksu_nomount_lookup_scope_exit(struct ksu_nomount_lookup_scope *scope);
bool ksu_nomount_lookup_scope_matches(int dfd);
int ksu_nomount_handle_iterate_dir(struct file *file,
				   struct dir_context *ctx);
bool ksu_nomount_handle_permission(struct inode *inode, int mask);
void ksu_nomount_permission_kretprobes_retire(void);
void ksu_nomount_dpath_kretprobe_retire(void);
void ksu_nomount_getattr_kretprobe_retire(void);
void ksu_nomount_redirect_kprobes_retire(void);
struct filename *ksu_nomount_getname_flags(const char __user *filename,
					   int flags, int *empty);
struct filename *ksu_nomount_getname_kernel(const char *filename);
int ksu_nomount_iterate_dir(struct file *file, struct dir_context *ctx);
char *ksu_nomount_handle_dpath(const struct path *path, char *buf, int buflen,
			       const char *native_path);
void ksu_nomount_handle_getattr(long ret, const struct path *path,
				struct kstat *stat);
bool ksu_nomount_getattr_runtime_ready(void);
void ksu_nomount_handle_fd_getattr(long ret, const struct path *path,
				   struct kstat *stat);
void ksu_nomount_handle_stat_result(long ret, unsigned long native_ino,
				    dev_t native_dev, struct kstat *stat);
void ksu_nomount_handle_statfs(long ret, const struct path *path,
			       struct kstatfs *statfs);
void ksu_nomount_handle_statfs_path(long ret, const struct path *path,
				    struct kstatfs *statfs);
bool ksu_nomount_fdinfo_identity(struct file *file, unsigned long *ino);
bool ksu_nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev,
				     unsigned long *ino);
bool ksu_nomount_active_for_current(void);
bool ksu_nomount_bypass_active(void);

int ksu_nomount_hooks_init(void);
void ksu_nomount_hooks_exit(void);
int ksu_nomount_keyring_init(void);
void ksu_nomount_keyring_exit(void);

#endif /* __KSU_NOMOUNT_H */
