#ifndef __KSU_NOMOUNT_H
#define __KSU_NOMOUNT_H

#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/types.h>

#define KSU_NOMOUNT_VERSION 13
#define KSU_NOMOUNT_GENL_NAME "nomount"
#define KSU_NOMOUNT_GENL_VERSION 1

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

enum ksu_nomount_attr {
	KSU_NOMOUNT_ATTR_UNSPEC = 0,
	KSU_NOMOUNT_ATTR_VIRTUAL_PATH,
	KSU_NOMOUNT_ATTR_REAL_PATH,
	KSU_NOMOUNT_ATTR_FLAGS,
	KSU_NOMOUNT_ATTR_UID,
	KSU_NOMOUNT_ATTR_VERSION,
	KSU_NOMOUNT_ATTR_PAYLOAD,
	__KSU_NOMOUNT_ATTR_MAX,
};
#define KSU_NOMOUNT_ATTR_MAX (__KSU_NOMOUNT_ATTR_MAX - 1)

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
bool ksu_nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev,
				     unsigned long *ino);
bool ksu_nomount_active_for_current(void);
bool ksu_nomount_bypass_active(void);

int ksu_nomount_hooks_init(void);
void ksu_nomount_hooks_exit(void);
int ksu_nomount_netlink_init(void);
void ksu_nomount_netlink_exit(void);

#endif /* __KSU_NOMOUNT_H */
