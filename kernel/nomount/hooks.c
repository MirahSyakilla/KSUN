// SPDX-License-Identifier: GPL-2.0
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/cpumask.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <asm/ptrace.h>

#include "include/arch.h"
#include "nomount/nomount.h"
#include "susfs/kstat.h"
#include "susfs/susfs.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
static inline void regs_set_return_value(struct pt_regs *regs,
					 unsigned long value)
{
	regs->regs[0] = value;
}
#endif

#define KSU_NOMOUNT_EMBEDDED_NAME_MAX \
	(KSU_NOMOUNT_MAX_PATH - offsetof(struct filename, iname))

static inline void ksu_nomount_filename_ref_init(struct filename *name)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	atomic_set(&name->refcnt, 1);
#else
	name->refcnt = 1;
#endif
}

/*
 * These are deliberately complete replacements for the two filename
 * constructors.  Calling the original through an entry redirect would recurse,
 * and changing the pathname after audit_getname() would lose audit's filename
 * association.  Keeping the native constructor ordering also makes the
 * replacement visible to audit exactly where the upstream NoMount patch does.
 */
static struct filename *notrace ksu_nomount_getname_flags(
	const char __user *filename, int flags, int *empty)
{
	struct filename *result;
	char *kname;
	int len;

	result = audit_reusename(filename);
	if (result)
		/* audit_reusename() already owns a reference and has an audit entry;
		 * still run the pathname policy so repeated lookups in one syscall
		 * cannot bypass a newly published redirect/whiteout. */
		return ksu_nomount_handle_getname(result);
	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	kname = (char *)result->iname;
	result->name = kname;
	len = strncpy_from_user(kname, filename,
				KSU_NOMOUNT_EMBEDDED_NAME_MAX);
	if (unlikely(len < 0)) {
		__putname(result);
		return ERR_PTR(len);
	}
	if (unlikely(len == KSU_NOMOUNT_EMBEDDED_NAME_MAX)) {
		const size_t size = offsetof(struct filename, iname[1]);
		char *embedded = (char *)result;

		result = kzalloc(size, GFP_KERNEL);
		if (unlikely(!result)) {
			__putname(embedded);
			return ERR_PTR(-ENOMEM);
		}
		result->name = embedded;
		len = strncpy_from_user(embedded, filename, KSU_NOMOUNT_MAX_PATH);
		if (unlikely(len < 0)) {
			__putname(embedded);
			kfree(result);
			return ERR_PTR(len);
		}
		if (unlikely(len == KSU_NOMOUNT_MAX_PATH)) {
			__putname(embedded);
			kfree(result);
			return ERR_PTR(-ENAMETOOLONG);
		}
	}

	ksu_nomount_filename_ref_init(result);
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		if (!(flags & LOOKUP_EMPTY)) {
			putname(result);
			return ERR_PTR(-ENOENT);
		}
	}
	result->uptr = filename;
	result->aname = NULL;
	result = ksu_nomount_handle_getname(result);
	if (!IS_ERR(result))
		audit_getname(result);
	return result;
}

static struct filename *notrace ksu_nomount_getname_kernel(
	const char *filename)
{
	struct filename *result;
	int len = strlen(filename) + 1;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);
	if (len <= KSU_NOMOUNT_EMBEDDED_NAME_MAX) {
		result->name = (char *)result->iname;
	} else if (len <= KSU_NOMOUNT_MAX_PATH) {
		const size_t size = offsetof(struct filename, iname[1]);
		struct filename *tmp = kmalloc(size, GFP_KERNEL);

		if (!tmp) {
			__putname(result);
			return ERR_PTR(-ENOMEM);
		}
		tmp->name = (char *)result;
		result = tmp;
	} else {
		__putname(result);
		return ERR_PTR(-ENAMETOOLONG);
	}
	memcpy((char *)result->name, filename, len);
	result->uptr = NULL;
	result->aname = NULL;
	ksu_nomount_filename_ref_init(result);
	result = ksu_nomount_handle_getname(result);
	if (!IS_ERR(result))
		audit_getname(result);
	return result;
}

struct ksu_nomount_redirect_probe {
	struct kprobe kp;
	unsigned long replacement;
	bool registered;
};

static int ksu_nomount_redirect_pre_handler(struct kprobe *kp,
					    struct pt_regs *regs)
{
	struct ksu_nomount_redirect_probe *probe =
		container_of(kp, struct ksu_nomount_redirect_probe, kp);

	instruction_pointer_set(regs, probe->replacement);
	return 1;
}

/* A post handler suppresses jump optimization, which ignores a changed PC. */
static void ksu_nomount_redirect_post_handler(struct kprobe *kp,
					      struct pt_regs *regs,
					      unsigned long flags)
{
	(void)kp;
	(void)regs;
	(void)flags;
}

static struct ksu_nomount_redirect_probe ksu_nomount_getname_flags_probe;
static struct ksu_nomount_redirect_probe ksu_nomount_getname_kernel_probe;
static struct ksu_nomount_redirect_probe ksu_nomount_iterate_dir_probe;

static int notrace ksu_nomount_iterate_dir(struct file *file,
					   struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	int res = -ENOTDIR;

#ifdef KSU_NOMOUNT_ITERATE_SHARED_ONLY
	if (!file->f_op->iterate_shared)
		return res;
	res = security_file_permission(file, MAY_READ);
	if (res)
		return res;
	res = down_read_killable(&inode->i_rwsem);
	if (res)
		return res;
	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		res = ksu_nomount_handle_iterate_dir(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
	inode_unlock_shared(inode);
	return res;
#else
	bool shared = false;

#ifdef KSU_SUSFS_HAS_ITERATE_SHARED
	if (file->f_op->iterate_shared)
		shared = true;
#endif
#ifdef KSU_SUSFS_HAS_ITERATE
	if (!shared && !file->f_op->iterate)
		return res;
#else
	if (!shared)
		return res;
#endif
	res = security_file_permission(file, MAY_READ);
	if (res)
		return res;
	if (shared)
		res = down_read_killable(&inode->i_rwsem);
	else
		res = down_write_killable(&inode->i_rwsem);
	if (res)
		return res;
	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		res = ksu_nomount_handle_iterate_dir(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
	if (shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
	return res;
#endif
}

static struct kretprobe ksu_nomount_permission_rp;
static struct kretprobe ksu_nomount_generic_permission_rp;
static struct kretprobe ksu_nomount_dpath_rp;
static struct kretprobe ksu_nomount_getattr_rp;
static struct kretprobe ksu_nomount_statfs_rp;
static bool ksu_nomount_permission_registered;
static bool ksu_nomount_generic_permission_registered;
static bool ksu_nomount_dpath_registered;
static bool ksu_nomount_getattr_registered;
static bool ksu_nomount_statfs_registered;

bool ksu_nomount_getattr_runtime_ready(void)
{
	return READ_ONCE(ksu_nomount_getattr_registered);
}

struct ksu_nomount_permission_ctx {
	struct inode *inode;
	int mask;
};

struct ksu_nomount_dpath_ctx {
	const struct path *path;
	char *buf;
	int buflen;
};

struct ksu_nomount_statfs_ctx {
	const struct path *path;
	struct kstatfs *statfs;
};

struct ksu_nomount_getattr_ctx {
	const struct path *path;
	struct kstat *stat;
};

static int ksu_nomount_permission_entry(struct kretprobe_instance *ri,
						struct pt_regs *regs)
{
	struct ksu_nomount_permission_ctx *ctx =
		(struct ksu_nomount_permission_ctx *)ri->data;

	ctx->inode = (struct inode *)PT_REGS_PARM1(regs);
	ctx->mask = (int)PT_REGS_PARM2(regs);
	return ksu_nomount_handle_permission(ctx->inode, ctx->mask) ? 0 : 1;
}

static int ksu_nomount_permission_handler(struct kretprobe_instance *ri,
						 struct pt_regs *regs)
{
	(void)ri;
	regs_set_return_value(regs, 0);
	return 0;
}

static int ksu_nomount_dpath_entry(struct kretprobe_instance *ri,
					   struct pt_regs *regs)
{
	struct ksu_nomount_dpath_ctx *ctx =
		(struct ksu_nomount_dpath_ctx *)ri->data;

	if (ksu_nomount_bypass_active())
		return 1;
	if (!ksu_nomount_active_for_current() &&
	    !ksu_susfs_open_redirect_active())
		return 1;
	ctx->path = (const struct path *)PT_REGS_PARM1(regs);
	ctx->buf = (char *)PT_REGS_PARM2(regs);
	ctx->buflen = (int)PT_REGS_PARM3(regs);
	return 0;
}

static int ksu_nomount_dpath_handler(struct kretprobe_instance *ri,
					    struct pt_regs *regs)
{
	struct ksu_nomount_dpath_ctx *ctx =
		(struct ksu_nomount_dpath_ctx *)ri->data;
	const char *native_path =
		(const char *)regs_return_value(regs);
	char *spoofed;

	spoofed = ksu_nomount_handle_dpath(ctx->path, ctx->buf, ctx->buflen,
					   native_path);
	if (!spoofed)
		spoofed = ksu_susfs_open_redirect_dpath(
			ctx->path, ctx->buf, ctx->buflen);
	if (spoofed)
		regs_set_return_value(regs, (unsigned long)spoofed);
	return 0;
}

static int ksu_nomount_statfs_entry(struct kretprobe_instance *ri,
						    struct pt_regs *regs)
{
	struct ksu_nomount_statfs_ctx *ctx =
		(struct ksu_nomount_statfs_ctx *)ri->data;

	if (ksu_nomount_bypass_active())
		return 1;
	if (!ksu_nomount_active_for_current() &&
	    !ksu_susfs_open_redirect_active())
		return 1;
	ctx->path = (const struct path *)PT_REGS_PARM1(regs);
	ctx->statfs = (struct kstatfs *)PT_REGS_PARM2(regs);
	return 0;
}

static int ksu_nomount_statfs_handler(struct kretprobe_instance *ri,
						     struct pt_regs *regs)
{
	struct ksu_nomount_statfs_ctx *ctx =
		(struct ksu_nomount_statfs_ctx *)ri->data;

	if (!regs_return_value(regs) && ctx->path && ctx->path->dentry)
		ksu_susfs_open_redirect_apply_statfs(
			d_backing_inode(ctx->path->dentry), ctx->statfs);
	ksu_nomount_handle_statfs((long)regs_return_value(regs), ctx->path,
				  ctx->statfs);
	return 0;
}

static int ksu_nomount_getattr_entry(struct kretprobe_instance *ri,
						     struct pt_regs *regs)
{
	struct ksu_nomount_getattr_ctx *ctx =
		(struct ksu_nomount_getattr_ctx *)ri->data;

	if (ksu_nomount_bypass_active())
		return 1;
	if (!ksu_nomount_active_for_current() &&
	    !ksu_susfs_open_redirect_active() &&
	    !ksu_susfs_kstat_active_for_current())
		return 1;
	ctx->path = (const struct path *)PT_REGS_PARM1(regs);
	ctx->stat = (struct kstat *)PT_REGS_PARM2(regs);
	return 0;
}

static int ksu_nomount_getattr_handler(struct kretprobe_instance *ri,
					       struct pt_regs *regs)
{
	struct ksu_nomount_getattr_ctx *ctx =
		(struct ksu_nomount_getattr_ctx *)ri->data;

	if (!regs_return_value(regs) && ctx->path && ctx->path->dentry) {
#ifdef CONFIG_KSU_HACK_ARM64_BRANCH_LINK
		/* Branch-link mode leaves SUSFS' own getattr return probe disabled.
		 * Reuse this already-required NoMount probe so direct callers of
		 * vfs_getattr_nosec still receive the full SUSFS metadata layer. */
		ksu_susfs_handle_vfs_getattr_nosec(
			ctx->path, ctx->stat, (long)regs_return_value(regs));
#else
		ksu_susfs_open_redirect_apply_kstat(
			d_backing_inode(ctx->path->dentry), ctx->stat);
		ksu_nomount_handle_getattr((long)regs_return_value(regs),
					   ctx->path, ctx->stat);
#endif
	}
	return 0;
}

static int ksu_nomount_register_redirect(
	struct ksu_nomount_redirect_probe *probe, const char *symbol,
	unsigned long replacement)
{
	int err;

	memset(probe, 0, sizeof(*probe));
	probe->replacement = replacement;
	probe->kp.symbol_name = symbol;
	probe->kp.pre_handler = ksu_nomount_redirect_pre_handler;
	probe->kp.post_handler = ksu_nomount_redirect_post_handler;
	err = register_kprobe(&probe->kp);
	if (!err)
		probe->registered = true;
	return err;
}

static void ksu_nomount_unregister_redirect(
	struct ksu_nomount_redirect_probe *probe)
{
	if (!probe->registered)
		return;
	unregister_kprobe(&probe->kp);
	probe->registered = false;
}

static int ksu_nomount_init_kretprobe(struct kretprobe *rp,
					      const char *symbol,
					      kretprobe_handler_t entry,
					      kretprobe_handler_t handler,
					      size_t data_size)
{
	memset(rp, 0, sizeof(*rp));
	rp->kp.symbol_name = symbol;
	rp->entry_handler = entry;
	rp->handler = handler;
	rp->data_size = data_size;
	/* Keep metadata hiding reliable during short, highly parallel app bursts. */
	rp->maxactive = max_t(int, 128, 8 * num_possible_cpus());
	return register_kretprobe(rp);
}

static void ksu_nomount_unregister_kretprobe(struct kretprobe *rp,
					      const char *symbol,
					      bool *registered)
{
	if (!*registered)
		return;
	unregister_kretprobe(rp);
	*registered = false;
	if (rp->nmissed)
		pr_warn("NoMount: %s return probe missed %d calls\n",
			symbol, rp->nmissed);
}

int ksu_nomount_hooks_init(void)
{
	int err;

	err = ksu_nomount_register_redirect(
		&ksu_nomount_getname_flags_probe, "getname_flags",
		(unsigned long)ksu_nomount_getname_flags);
	if (err)
		return err;
	err = ksu_nomount_register_redirect(
		&ksu_nomount_getname_kernel_probe, "getname_kernel",
		(unsigned long)ksu_nomount_getname_kernel);
	if (err)
		goto fail;
	err = ksu_nomount_register_redirect(
		&ksu_nomount_iterate_dir_probe, "iterate_dir",
		(unsigned long)ksu_nomount_iterate_dir);
	if (err)
		goto fail;

	err = ksu_nomount_init_kretprobe(
		&ksu_nomount_permission_rp, "inode_permission",
		ksu_nomount_permission_entry, ksu_nomount_permission_handler,
		sizeof(struct ksu_nomount_permission_ctx));
	if (err)
		goto fail;
	ksu_nomount_permission_registered = true;
	err = ksu_nomount_init_kretprobe(
		&ksu_nomount_generic_permission_rp, "generic_permission",
		ksu_nomount_permission_entry, ksu_nomount_permission_handler,
		sizeof(struct ksu_nomount_permission_ctx));
	if (err)
		goto fail;
	ksu_nomount_generic_permission_registered = true;
	err = ksu_nomount_init_kretprobe(
		&ksu_nomount_dpath_rp, "d_path", ksu_nomount_dpath_entry,
		ksu_nomount_dpath_handler, sizeof(struct ksu_nomount_dpath_ctx));
	if (err)
		goto fail;
	ksu_nomount_dpath_registered = true;
	err = ksu_nomount_init_kretprobe(
		&ksu_nomount_getattr_rp, "vfs_getattr_nosec",
		ksu_nomount_getattr_entry,
		ksu_nomount_getattr_handler,
		sizeof(struct ksu_nomount_getattr_ctx));
	if (err)
		goto fail;
	ksu_nomount_getattr_registered = true;
	err = ksu_nomount_init_kretprobe(
		&ksu_nomount_statfs_rp, "vfs_statfs", ksu_nomount_statfs_entry,
		ksu_nomount_statfs_handler, sizeof(struct ksu_nomount_statfs_ctx));
	if (err)
		goto fail;
	ksu_nomount_statfs_registered = true;
	return 0;

fail:
	ksu_nomount_hooks_exit();
	return err;
}

void ksu_nomount_hooks_exit(void)
{
	/* Stop entry redirection before tearing down policy callbacks. */
	ksu_nomount_unregister_redirect(&ksu_nomount_iterate_dir_probe);
	ksu_nomount_unregister_redirect(&ksu_nomount_getname_kernel_probe);
	ksu_nomount_unregister_redirect(&ksu_nomount_getname_flags_probe);
	ksu_nomount_unregister_kretprobe(
		&ksu_nomount_statfs_rp, "vfs_statfs",
		&ksu_nomount_statfs_registered);
	ksu_nomount_unregister_kretprobe(
		&ksu_nomount_getattr_rp, "vfs_getattr_nosec",
		&ksu_nomount_getattr_registered);
	ksu_nomount_unregister_kretprobe(
		&ksu_nomount_dpath_rp, "d_path", &ksu_nomount_dpath_registered);
	ksu_nomount_unregister_kretprobe(
		&ksu_nomount_generic_permission_rp, "generic_permission",
		&ksu_nomount_generic_permission_registered);
	ksu_nomount_unregister_kretprobe(
		&ksu_nomount_permission_rp, "inode_permission",
		&ksu_nomount_permission_registered);
}
