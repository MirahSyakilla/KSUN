#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/version.h>

#include "compat/kernel_compat.h"
#include "compiler_compat.h"
#include "hook/lsm_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "selinux/execmem_compat.h"

#define KSU_HMA_MODULE_DIR "/data/adb/modules/hma_oss_zygisk"
#define KSU_HMA_MODULE_PROP KSU_HMA_MODULE_DIR "/module.prop"
#define KSU_HMA_ZYGISK_LIB KSU_HMA_MODULE_DIR "/zygisk/arm64-v8a.so"
#define KSU_HMA_ANDROID_TARGET KSU_HMA_MODULE_DIR "/packages/android"
#define KSU_HMA_DISABLE KSU_HMA_MODULE_DIR "/disable"
#define KSU_HMA_REMOVE KSU_HMA_MODULE_DIR "/remove"
#define KSU_HMA_MAX_CODE_BLOB SZ_64K

typedef int (*selinux_file_mprotect_fn)(struct vm_area_struct *vma,
					unsigned long reqprot,
					unsigned long prot);

static bool ksu_hma_execmem_allowed __read_mostly;
static unsigned long ksu_hma_next_probe __read_mostly;
static bool ksu_hma_allow_logged __read_mostly;

static int ksu_execmem_kern_path(const char *name, unsigned int flags,
				 struct path *path)
{
	const struct cred *saved = NULL;
	int err;

	if (ksu_cred)
		saved = override_creds(ksu_cred);
	err = kern_path(name, flags, path);
	if (saved)
		revert_creds(saved);
	return err;
}

static bool ksu_path_exists(const char *name)
{
	struct path path;

	if (ksu_execmem_kern_path(name, LOOKUP_FOLLOW, &path))
		return false;

	path_put(&path);
	return true;
}

static bool ksu_path_regular_root(const char *name, bool allow_empty)
{
	struct inode *inode;
	struct path path;
	bool ok;

	if (ksu_execmem_kern_path(name, LOOKUP_FOLLOW, &path))
		return false;

	inode = d_inode(path.dentry);
	ok = inode && S_ISREG(inode->i_mode) && i_uid_read(inode) == 0 &&
	     !(inode->i_mode & S_IWOTH) &&
	     (allow_empty || i_size_read(inode) > 0);
	path_put(&path);
	return ok;
}

static bool ksu_file_contains(const char *name, const char *needle)
{
	char buf[512];
	struct file *fp;
	const struct cred *saved = NULL;
	loff_t pos = 0;
	ssize_t nr;
	bool found = false;

	if (ksu_cred)
		saved = override_creds(ksu_cred);
	fp = filp_open(name, O_RDONLY, 0);
	if (!IS_ERR(fp)) {
		nr = ksu_kernel_read_compat(fp, buf, sizeof(buf) - 1, &pos);
		if (nr > 0) {
			buf[nr] = '\0';
			found = strstr(buf, needle) != NULL;
		}
		filp_close(fp, NULL);
	}
	if (saved)
		revert_creds(saved);

	return found;
}

static bool ksu_hma_android_module_active(void)
{
	if (ksu_path_exists(KSU_HMA_DISABLE) ||
	    ksu_path_exists(KSU_HMA_REMOVE))
		return false;

	if (!ksu_path_regular_root(KSU_HMA_ANDROID_TARGET, true) ||
	    !ksu_path_regular_root(KSU_HMA_ZYGISK_LIB, false))
		return false;

	return ksu_file_contains(KSU_HMA_MODULE_PROP, "id=hma_oss_zygisk") &&
	       ksu_file_contains(KSU_HMA_MODULE_PROP,
				 "entrypoint=org.frknkrc44.hma_oss.zygote.ZygoteEntry");
}

void ksu_execmem_compat_refresh(void)
{
	bool enabled = ksu_hma_android_module_active();
	bool was_enabled = READ_ONCE(ksu_hma_execmem_allowed);

	WRITE_ONCE(ksu_hma_execmem_allowed, enabled);
	if (enabled && !was_enabled)
		pr_info("execmem_compat: HMA system_server RX anon mprotect enabled\n");
}

static bool ksu_execmem_hma_allowed_cached(void)
{
	unsigned long now;

	if (likely(READ_ONCE(ksu_hma_execmem_allowed)))
		return true;

	now = jiffies;
	if (time_before(now, READ_ONCE(ksu_hma_next_probe)))
		return false;

	WRITE_ONCE(ksu_hma_next_probe, now + 5 * HZ);
	ksu_execmem_compat_refresh();
	return READ_ONCE(ksu_hma_execmem_allowed);
}

static bool ksu_current_is_system_server(void)
{
	const struct task_struct *leader = current->group_leader;

	if (unlikely(!current->mm || current->flags & PF_KTHREAD))
		return false;
	if (current_uid().val != 1000)
		return false;

	return leader && !strcmp(leader->comm, "system_server");
}

static bool ksu_hma_execmem_vma_shape_allowed(struct vm_area_struct *vma,
					      unsigned long prot)
{
	unsigned long size;

	if (!vma || vma->vm_mm != current->mm)
		return false;
	if (!(prot & PROT_EXEC) || (prot & PROT_WRITE))
		return false;
	if ((vma->vm_flags & (VM_EXEC | VM_SHARED)) || vma->vm_file)
		return false;

	size = vma->vm_end - vma->vm_start;
	if (!size || size > KSU_HMA_MAX_CODE_BLOB)
		return false;

	if (vma->vm_start >= vma->vm_mm->start_brk &&
	    vma->vm_end <= vma->vm_mm->brk)
		return false;
	if ((vma->vm_start <= vma->vm_mm->start_stack &&
	     vma->vm_end >= vma->vm_mm->start_stack) ||
	    vma_is_stack_for_current(vma))
		return false;

	return true;
}

static bool ksu_hma_execmem_compat_allowed(struct vm_area_struct *vma,
					   unsigned long prot)
{
	if (!ksu_current_is_system_server())
		return false;
	if (!ksu_hma_execmem_vma_shape_allowed(vma, prot))
		return false;

	return ksu_execmem_hma_allowed_cached();
}

int ksu_handle_selinux_file_mprotect(struct vm_area_struct *vma,
				     unsigned long reqprot,
				     unsigned long prot);

static struct ksu_lsm_hook ksu_selinux_file_mprotect_hook =
	KSU_LSM_HOOK_INIT(file_mprotect, "selinux_file_mprotect",
			  ksu_handle_selinux_file_mprotect, 0);

int __nocfi ksu_handle_selinux_file_mprotect(struct vm_area_struct *vma,
					     unsigned long reqprot,
					     unsigned long prot)
{
	selinux_file_mprotect_fn orig;

	if (unlikely(ksu_hma_execmem_compat_allowed(vma, prot))) {
		if (!READ_ONCE(ksu_hma_allow_logged)) {
			WRITE_ONCE(ksu_hma_allow_logged, true);
			pr_info("execmem_compat: allowing HMA system_server RX code blob\n");
		}
		return 0;
	}

	orig = (selinux_file_mprotect_fn)ksu_selinux_file_mprotect_hook.original;
	return orig ? orig(vma, reqprot, prot) : 0;
}

void ksu_execmem_compat_init(void)
{
	int ret;

	ret = ksu_lsm_hook(&ksu_selinux_file_mprotect_hook);
	if (ret && ret != -EALREADY)
		pr_err("execmem_compat: file_mprotect hook failed: %d\n", ret);
}

void ksu_execmem_compat_exit(void)
{
	ksu_lsm_unhook(&ksu_selinux_file_mprotect_hook);
}
