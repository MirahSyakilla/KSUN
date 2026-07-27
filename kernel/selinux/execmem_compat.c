#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mutex.h>
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
#define KSU_HMA_PROP_ID "id=hma_oss_zygisk"
#define KSU_HMA_PROP_ENTRYPOINT "entrypoint=org.frknkrc44.hma_oss.zygote.ZygoteEntry"
#define KSU_HMA_MAX_CODE_BLOB SZ_64K

typedef int (*selinux_file_mprotect_fn)(struct vm_area_struct *vma,
					unsigned long reqprot,
					unsigned long prot);

static bool ksu_hma_execmem_allowed __read_mostly;
static bool ksu_hma_execmem_hooked __read_mostly;
static bool ksu_hma_allow_logged __read_mostly;
static bool ksu_hma_execmem_sealed __read_mostly;
static selinux_file_mprotect_fn ksu_orig_file_mprotect __read_mostly;
static DEFINE_MUTEX(ksu_execmem_compat_lock);

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

static bool ksu_hma_prop_valid(void)
{
	char buf[512];
	struct file *fp;
	const struct cred *saved = NULL;
	loff_t pos = 0;
	ssize_t nr;
	bool found = false;

	if (ksu_cred)
		saved = override_creds(ksu_cred);
	fp = filp_open(KSU_HMA_MODULE_PROP, O_RDONLY, 0);
	if (!IS_ERR(fp)) {
		nr = ksu_kernel_read_compat(fp, buf, sizeof(buf) - 1, &pos);
		if (nr > 0) {
			buf[nr] = '\0';
			found = strstr(buf, KSU_HMA_PROP_ID) &&
				strstr(buf, KSU_HMA_PROP_ENTRYPOINT);
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

	return ksu_hma_prop_valid();
}

static __always_inline bool ksu_current_is_system_server(void)
{
	const struct task_struct *leader = current->group_leader;

	if (likely(current_uid().val != 1000))
		return false;
	if (unlikely(!current->mm || current->flags & PF_KTHREAD))
		return false;

	return leader &&
	       !memcmp(leader->comm, "system_server", sizeof("system_server"));
}

static __always_inline bool
ksu_hma_execmem_vma_shape_allowed(struct vm_area_struct *vma,
				  unsigned long prot)
{
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
	unsigned long size;
	unsigned long flags;

	if (!(prot & PROT_EXEC) || (prot & PROT_WRITE))
		return false;
	if (!vma)
		return false;

	flags = vma->vm_flags;
	if ((flags & (VM_EXEC | VM_SHARED)) || vma->vm_file)
		return false;

	mm = current->mm;
	if (!mm || vma->vm_mm != mm)
		return false;

	start = vma->vm_start;
	end = vma->vm_end;
	if (end <= start)
		return false;

	size = end - start;
	if (size > KSU_HMA_MAX_CODE_BLOB)
		return false;

	if (start >= mm->start_brk && end <= mm->brk)
		return false;
	if ((start <= mm->start_stack && end >= mm->start_stack) ||
	    vma_is_stack_for_current(vma))
		return false;

	return true;
}

static bool ksu_hma_execmem_compat_allowed(struct vm_area_struct *vma,
					   unsigned long prot)
{
	if (unlikely(!READ_ONCE(ksu_hma_execmem_allowed)))
		return false;
	if (likely(!ksu_current_is_system_server()))
		return false;

	return ksu_hma_execmem_vma_shape_allowed(vma, prot);
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

	orig = READ_ONCE(ksu_orig_file_mprotect);
	return orig ? orig(vma, reqprot, prot) : 0;
}

static void ksu_execmem_compat_enable_hook(bool enabled)
{
	bool allowed;
	bool hooked;
	int ret;

	mutex_lock(&ksu_execmem_compat_lock);

	hooked = READ_ONCE(ksu_hma_execmem_hooked);
	if (READ_ONCE(ksu_hma_execmem_sealed))
		enabled = false;

	if (enabled) {
		if (hooked)
			goto allow;

		ret = ksu_lsm_hook(&ksu_selinux_file_mprotect_hook);
		if (ret && ret != -EALREADY) {
			pr_err("execmem_compat: file_mprotect hook failed: %d\n",
			       ret);
			goto out;
		}

		WRITE_ONCE(ksu_orig_file_mprotect,
			   (selinux_file_mprotect_fn)
				   ksu_selinux_file_mprotect_hook.original);
		WRITE_ONCE(ksu_hma_execmem_hooked, true);
allow:
		allowed = READ_ONCE(ksu_hma_execmem_allowed);
		WRITE_ONCE(ksu_hma_execmem_allowed, true);
		if (!allowed)
			pr_info("execmem_compat: HMA system_server RX anon mprotect enabled\n");
	} else if (hooked) {
		WRITE_ONCE(ksu_hma_execmem_allowed, false);
		ksu_lsm_unhook(&ksu_selinux_file_mprotect_hook);
		WRITE_ONCE(ksu_orig_file_mprotect, NULL);
		WRITE_ONCE(ksu_hma_execmem_hooked, false);
		WRITE_ONCE(ksu_hma_allow_logged, false);
	} else {
		WRITE_ONCE(ksu_hma_execmem_allowed, false);
	}

out:
	mutex_unlock(&ksu_execmem_compat_lock);
}

void ksu_execmem_compat_refresh(void)
{
	if (likely(READ_ONCE(ksu_hma_execmem_sealed)))
		return;

	ksu_execmem_compat_enable_hook(ksu_hma_android_module_active());
}

void ksu_execmem_compat_seal(void)
{
	if (READ_ONCE(ksu_hma_execmem_sealed))
		return;
	if (!READ_ONCE(ksu_hma_execmem_hooked))
		return;
	if (!READ_ONCE(ksu_hma_allow_logged))
		return;

	pr_info("execmem_compat: sealing HMA system_server mprotect hook\n");
	WRITE_ONCE(ksu_hma_execmem_sealed, true);
	ksu_execmem_compat_enable_hook(false);
}

void ksu_execmem_compat_init(void)
{
	ksu_execmem_compat_refresh();
}

void ksu_execmem_compat_exit(void)
{
	ksu_execmem_compat_enable_hook(false);
}
