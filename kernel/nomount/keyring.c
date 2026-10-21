/*
 * NoMount control transport: the "nomount" key type.
 *
 * The transport is the same one upstream NoMount uses: a one-shot command is
 * carried by the payload of a key of a custom key type and is applied while
 * the key type parses ("preparses") that payload.  The key itself is never
 * instantiated, so the type behaves like a command channel rather than a
 * keyring.
 *
 * The permission check lives in the preparse callback and requires
 * CAP_SYS_ADMIN in the *initial* user namespace.  capable() resolves against
 * init_user_ns, so a process that only owns CAP_SYS_ADMIN inside a user
 * namespace it created itself is rejected.  That property is the reason this
 * transport replaces the retired Generic Netlink family: a netlink family
 * registered with GENL_ADMIN_PERM checks ns_capable(sock_net(skb)->user_ns,
 * CAP_NET_ADMIN), which an app satisfies by unsharing a user and a network
 * namespace, and NoMount rules are global, so such an app could install
 * system-wide rules.
 */
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/key-type.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "klog.h" // IWYU pragma: keep
#include "nomount/nomount.h"

struct ksu_nomount_dump_scratch {
	char virtual_path[KSU_NOMOUNT_MAX_PATH];
	char real_path[KSU_NOMOUNT_MAX_PATH];
};

/*
 * Wire format of the rule batches.  These helpers are the ones the retired
 * Generic Netlink transport used, kept verbatim so that both transports
 * agreed on the layout:
 *
 *   add rule: u32 flags | u16 v_len | u16 r_len | vpath | rpath
 *   del rule: u16 v_len | vpath
 *
 * Paths are length prefixed and never NUL terminated.
 */
static int ksu_nomount_copy_payload_path(const char *data, int len,
					 char **out)
{
	if (len <= 0)
		return -EINVAL;
	if (len >= KSU_NOMOUNT_MAX_PATH)
		return -ENAMETOOLONG;
	if (memchr(data, '\0', len))
		return -EINVAL;

	*out = kstrndup(data, len, GFP_KERNEL);
	return *out ? 0 : -ENOMEM;
}

static int ksu_nomount_validate_add_payload(const char *data, int len)
{
	int pos = 0;

	if (len <= 0)
		return -EINVAL;
	while (pos < len) {
		u32 flags;
		u16 virtual_len, real_len;

		if (len - pos < 8)
			return -EINVAL;
		flags = get_unaligned((const u32 *)(data + pos));
		virtual_len = get_unaligned((const u16 *)(data + pos + 4));
		real_len = get_unaligned((const u16 *)(data + pos + 6));
		pos += 8;

		if (!virtual_len || virtual_len >= KSU_NOMOUNT_MAX_PATH ||
		    real_len >= KSU_NOMOUNT_MAX_PATH ||
		    (!(flags & KSU_NOMOUNT_FLAG_WHITEOUT) && !real_len) ||
		    virtual_len > len - pos ||
		    real_len > len - pos - virtual_len)
			return -EINVAL;
		if (memchr(data + pos, '\0', virtual_len) ||
		    (real_len &&
		     memchr(data + pos + virtual_len, '\0', real_len)))
			return -EINVAL;
		pos += virtual_len + real_len;
	}
	return 0;
}

static int ksu_nomount_validate_del_payload(const char *data, int len)
{
	int pos = 0;

	if (len <= 0)
		return -EINVAL;
	while (pos < len) {
		u16 virtual_len;

		if (len - pos < 2)
			return -EINVAL;
		virtual_len = get_unaligned((const u16 *)(data + pos));
		pos += 2;
		if (!virtual_len || virtual_len >= KSU_NOMOUNT_MAX_PATH ||
		    virtual_len > len - pos ||
		    memchr(data + pos, '\0', virtual_len))
			return -EINVAL;
		pos += virtual_len;
	}
	return 0;
}

static int ksu_nomount_count_del_payload(const char *data, int len)
{
	int pos = 0;
	int count = 0;

	while (pos < len) {
		u16 virtual_len;

		virtual_len = get_unaligned((const u16 *)(data + pos));
		pos += 2 + virtual_len;
		count++;
	}
	return count;
}

static void ksu_nomount_free_path_array(char **paths, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		kfree(paths[i]);
	kfree(paths);
}

static int ksu_nomount_keyring_add_rules(const char *data, int len)
{
	int pos = 0;
	int first_err = 0;

	if (len <= 0)
		return -EINVAL;
	if (ksu_nomount_validate_add_payload(data, len))
		return -EINVAL;

	while (pos + 8 <= len) {
		char *virtual_path = NULL;
		char *real_path = NULL;
		u32 flags;
		u16 virtual_len;
		u16 real_len;
		int err;

		flags = get_unaligned((const u32 *)(data + pos));
		virtual_len = get_unaligned((const u16 *)(data + pos + 4));
		real_len = get_unaligned((const u16 *)(data + pos + 6));
		pos += 8;

		if (virtual_len == 0 || pos + virtual_len + real_len > len)
			return first_err ?: -EINVAL;

		err = ksu_nomount_copy_payload_path(data + pos, virtual_len,
						    &virtual_path);
		pos += virtual_len;
		if (!err && real_len) {
			err = ksu_nomount_copy_payload_path(data + pos,
							    real_len,
							    &real_path);
		}
		pos += real_len;

		if (!err)
			err = ksu_nomount_add_rule(virtual_path, real_path,
						   flags);
		if (err && !first_err)
			first_err = err;

		kfree(virtual_path);
		kfree(real_path);
	}

	if (pos != len)
		return first_err ?: -EINVAL;

	return first_err ?: 0;
}

static int ksu_nomount_keyring_del_rules(const char *data, int len)
{
	int pos = 0;
	int first_err = 0;
	char **paths;
	int path_count;
	unsigned int idx = 0;

	if (len <= 0)
		return -EINVAL;
	if (ksu_nomount_validate_del_payload(data, len))
		return -EINVAL;
	path_count = ksu_nomount_count_del_payload(data, len);
	if (path_count <= 0)
		return -EINVAL;
	paths = kcalloc(path_count, sizeof(*paths), GFP_KERNEL);
	if (!paths)
		return -ENOMEM;

	while (pos + 2 <= len) {
		char *virtual_path = NULL;
		u16 virtual_len;
		int err;

		virtual_len = get_unaligned((const u16 *)(data + pos));
		pos += 2;
		if (pos + virtual_len > len)
			return first_err ?: -EINVAL;

		err = ksu_nomount_copy_payload_path(data + pos, virtual_len,
						    &virtual_path);
		pos += virtual_len;
		if (!err) {
			paths[idx++] = virtual_path;
			virtual_path = NULL;
		}
		if (err && !first_err)
			first_err = err;
		kfree(virtual_path);
		if (err)
			break;
	}
	if (!first_err && pos != len)
		first_err = -EINVAL;
	if (idx) {
		int err = ksu_nomount_del_rules(paths, idx);

		if (err && !first_err)
			first_err = err;
	}
	ksu_nomount_free_path_array(paths, idx);

	return first_err ?: 0;
}

/*
 * Fill the payload buffer with as many rules as fit.  arg1 carries the
 * continuation token of the rule dump, so the client can page through the
 * rule table with repeated commands.
 */
static int ksu_nomount_keyring_get_list(struct ksu_nomount_payload *payload)
{
	struct ksu_nomount_dump_state state = {
		.bucket = (u32)(payload->arg1 >> 32),
		.index = (u32)(payload->arg1 & 0xffffffffULL),
	};
	struct ksu_nomount_dump_scratch *scratch;
	size_t used = 0;
	int err = 0;

	scratch = kzalloc(sizeof(*scratch), GFP_KERNEL);
	if (!scratch)
		return -ENOMEM;

	for (;;) {
		struct ksu_nomount_dump_state next = state;
		u32 flags = 0;
		u16 virtual_len;
		u16 real_len;
		size_t record;

		err = ksu_nomount_get_dump_rule(&next, scratch->virtual_path,
						sizeof(scratch->virtual_path),
						scratch->real_path,
						sizeof(scratch->real_path),
						&flags);
		if (err == -ENOENT) {
			err = 0;
			break;
		}
		if (err)
			break;

		virtual_len = (u16)strlen(scratch->virtual_path);
		real_len = (u16)strlen(scratch->real_path);
		record = 8 + (size_t)virtual_len + (size_t)real_len;
		if (used + record > sizeof(payload->buffer)) {
			err = 0;
			break;
		}

		put_unaligned((u32)flags, (void *)(payload->buffer + used));
		put_unaligned((u16)virtual_len,
			      (void *)(payload->buffer + used + 4));
		put_unaligned((u16)real_len,
			      (void *)(payload->buffer + used + 6));
		memcpy(payload->buffer + used + 8, scratch->virtual_path,
		       virtual_len);
		memcpy(payload->buffer + used + 8 + virtual_len,
		       scratch->real_path, real_len);
		used += record;

		state = next;
	}

	kfree(scratch);
	payload->data_size = used;
	payload->arg1 = ((u64)state.bucket << 32) | (u64)state.index;
	return err;
}

static void ksu_nomount_keyring_run(struct ksu_nomount_payload *payload)
{
	int status = 0;

	switch (payload->cmd) {
	case KSU_NOMOUNT_CMD_GET_VERSION: {
		struct ksu_nomount_version version = {
			.abi = KSU_NOMOUNT_VERSION,
			.transport = KSU_NOMOUNT_TRANSPORT_VERSION,
		};

		memcpy(payload->buffer, &version, sizeof(version));
		payload->data_size = sizeof(version);
		break;
	}

	case KSU_NOMOUNT_CMD_ADD_RULE:
		status = ksu_nomount_keyring_add_rules(payload->buffer,
						       payload->data_size);
		break;

	case KSU_NOMOUNT_CMD_DEL_RULE:
		status = ksu_nomount_keyring_del_rules(payload->buffer,
						       payload->data_size);
		break;

	case KSU_NOMOUNT_CMD_CLEAR_ALL:
		ksu_nomount_clear_all();
		break;

	case KSU_NOMOUNT_CMD_ADD_UID:
		status = ksu_nomount_add_uid(payload->target_uid);
		break;

	case KSU_NOMOUNT_CMD_DEL_UID:
		status = ksu_nomount_del_uid(payload->target_uid);
		break;

	case KSU_NOMOUNT_CMD_GET_LIST:
		status = ksu_nomount_keyring_get_list(payload);
		break;

	default:
		status = -EINVAL;
		break;
	}

	payload->status = status;
}

/*
 * Read the command payload from user space, apply it and write the result
 * back.  The client's buffer is a plain user mapping, so it is copied in and
 * out instead of being pinned.
 */
static void ksu_nomount_keyring_dispatch(unsigned long user_addr)
{
	struct ksu_nomount_payload *payload;

	payload = kmalloc(sizeof(*payload), GFP_KERNEL);
	if (!payload)
		return;

	if (copy_from_user(payload, (void __user *)user_addr,
			   sizeof(*payload)))
		goto out;
	if (payload->magic != KSU_NOMOUNT_MAGIC_SIG)
		goto out;
	if (payload->data_size > sizeof(payload->buffer)) {
		payload->status = -EINVAL;
		goto reply;
	}

	ksu_nomount_keyring_run(payload);

	/* Mark the payload as processed so that the client can tell an applied
	 * command apart from a command the kernel refused before it ran. */
	payload->magic = KSU_NOMOUNT_MAGIC_DONE;

reply:
	if (copy_to_user((void __user *)user_addr, payload, sizeof(*payload)))
		pr_warn("NoMount: failed to hand the command result back\n");
out:
	kfree(payload);
}

/*
 * One-shot command channel.  The payload is the address of the client's
 * command structure.  The key is never instantiated, so the command is
 * applied exactly once and nothing is left behind in a keyring.
 */
static int ksu_nomount_keyring_preparse(struct key_preparsed_payload *prep)
{
	unsigned long user_addr;

	/*
	 * capable() resolves against the initial user namespace.  A process
	 * that only holds CAP_SYS_ADMIN inside a user namespace it created
	 * itself is rejected here.
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (prep->datalen == sizeof(u64))
		user_addr = (unsigned long)get_unaligned((const u64 *)prep->data);
	else if (prep->datalen == sizeof(u32))
		user_addr = (unsigned long)get_unaligned((const u32 *)prep->data);
	else
		return -EINVAL;

	if (!user_addr)
		return -EINVAL;

	ksu_nomount_keyring_dispatch(user_addr);

	return -ECANCELED;
}

static void ksu_nomount_keyring_free_preparse(struct key_preparsed_payload *prep)
{
}

static int ksu_nomount_keyring_instantiate(struct key *key,
					    struct key_preparsed_payload *prep)
{
	return -EINVAL;
}

static struct key_type ksu_nomount_key_type = {
	.name = KSU_NOMOUNT_KEY_TYPE_NAME,
	.preparse = ksu_nomount_keyring_preparse,
	.free_preparse = ksu_nomount_keyring_free_preparse,
	.instantiate = ksu_nomount_keyring_instantiate,
};

int ksu_nomount_keyring_init(void)
{
	int err;

	/* The client and the kernel must agree on the payload layout. */
	BUILD_BUG_ON(sizeof(struct ksu_nomount_payload) != 8192);
	BUILD_BUG_ON(offsetof(struct ksu_nomount_payload, buffer) != 32);
	BUILD_BUG_ON(sizeof(struct ksu_nomount_version) != 8);

	err = register_key_type(&ksu_nomount_key_type);
	if (err)
		pr_warn("NoMount: failed to register key type: %d\n", err);
	return err;
}

void ksu_nomount_keyring_exit(void)
{
	unregister_key_type(&ksu_nomount_key_type);
}
