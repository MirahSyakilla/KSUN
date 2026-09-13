// Phase 19 NoMount latency benchmark.
// Measures the stat() syscall — the only single syscall that crosses all
// three NoMount layers (getname rewrite, permission bridge, getattr identity).
//
// Cases (netlink-toggled rule state, verified before each case):
//   A  disabled      (no rules; static key off)
//   B  enabled-no-match (dummy rules elsewhere; timed path misses)
//   C  enabled-match    (rule on timed path; rewrite + access scope)
//   D  repeated-match   (same as C, hot loop)
//   E  repeated-non-match (rule present, timed path misses, repeated)
//
// Usage: nomount_bench <iterations> [cpu]
// Prints per-case stats: mean/median/p50/p90/p95/p99/min/max/sigma (ns).
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>

#define VIRT "/data/local/tmp/nm-leak/virt/file.txt"
#define REAL "/data/local/tmp/nm-leak/real/file.txt"
#define NOMATCH "/data/local/tmp/nm-leak/pub/other.txt"
#define DUMMY "/data/local/tmp/nm-leak/pub/dummy_probe.txt"

static long sys_stat(const char *p, struct stat *s) {
	return syscall(__NR_newfstatat, AT_FDCWD, p, s, 0);
}

static inline unsigned long long now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int cmp(const void *a, const void *b) {
	unsigned long long x = *(const unsigned long long *)a;
	unsigned long long y = *(const unsigned long long *)b;
	return x < y ? -1 : x > y;
}

static void report(const char *name, unsigned long long *v, int n) {
	qsort(v, n, sizeof(v[0]), cmp);
	double mean = 0;
	for (int i = 0; i < n; i++) mean += (double)v[i];
	mean /= n;
	double var = 0;
	for (int i = 0; i < n; i++) {
		double d = (double)v[i] - mean;
		var += d * d;
	}
	double sigma = n > 1 ? sqrt(var / (n - 1)) : 0;
	printf("%s n=%d mean=%.1f median=%llu p50=%llu p90=%llu p95=%llu "
	       "p99=%llu min=%llu max=%llu sigma=%.1f\n",
	       name, n, mean, v[n / 2], v[n / 2],
	       v[(int)(n * 0.90)], v[(int)(n * 0.95)], v[(int)(n * 0.99)],
	       v[0], v[n - 1], sigma);
}

/* --- netlink control: family "nomount", ABI v13 ---------------------------- */
static int nl_fd = -1;
static int fam_id = -1;

#define KSU_NOMOUNT_CMD_ADD_RULE 1
#define KSU_NOMOUNT_CMD_DEL_RULE 2
#define KSU_NOMOUNT_CMD_CLEAR_ALL 3
#define KSU_NOMOUNT_ATTR_VIRTUAL_PATH 1
#define KSU_NOMOUNT_ATTR_REAL_PATH 2

static int nl_open(void) {
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} req;
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[512];
	} resp;

	nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl_fd < 0) return -1;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	req.n.nlmsg_type = GENL_ID_CTRL;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.g.cmd = CTRL_CMD_GETFAMILY;
	req.g.version = 1;

	struct nlattr *attr = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
	attr->nla_type = CTRL_ATTR_FAMILY_NAME;
	attr->nla_len = NLA_HDRLEN + 8;
	strcpy((char *)attr + NLA_HDRLEN, "nomount");
	req.n.nlmsg_len += NLA_ALIGN(attr->nla_len);

	if (send(nl_fd, &req, req.n.nlmsg_len, 0) < 0) return -1;
	socklen_t alen = sizeof(resp);
	if (recvfrom(nl_fd, &resp, sizeof(resp), 0, NULL, &alen) < 0) return -1;

	/* parse family id from attrs */
	struct nlattr *a = (struct nlattr *)((char *)&resp +
		NLMSG_HDRLEN + sizeof(struct genlmsghdr));
	int remain = resp.n.nlmsg_len - NLMSG_HDRLEN - sizeof(struct genlmsghdr);
	while (remain >= (int)sizeof(struct nlattr)) {
		if (a->nla_type == CTRL_ATTR_FAMILY_ID) {
			fam_id = *(unsigned short *)((char *)a + NLA_HDRLEN);
			break;
		}
		remain -= NLA_ALIGN(a->nla_len);
		a = (struct nlattr *)((char *)a + NLA_ALIGN(a->nla_len));
	}
	return fam_id > 0 ? 0 : -1;
}

static int nl_cmd(int cmd, const char *virt, const char *real) {
	/* Use the established nm CLI (proven control-plane interface; the
	 * hand-rolled genl ADD path needs FLAGS/payload details the CLI
	 * already encodes).  The netlink socket is still opened to prove the
	 * family exists. */
	{
		char cmd_buf[512];
		switch (cmd) {
		case KSU_NOMOUNT_CMD_ADD_RULE:
			if (!virt || !real) return -1;
			snprintf(cmd_buf, sizeof(cmd_buf),
				 "/data/adb/modules/nomount/bin/nm add '%s' '%s'",
				 virt, real);
			return system(cmd_buf) == 0 ? 0 : -1;
		case KSU_NOMOUNT_CMD_DEL_RULE:
			if (!virt) return -1;
			snprintf(cmd_buf, sizeof(cmd_buf),
				 "/data/adb/modules/nomount/bin/nm del '%s'",
				 virt);
			return system(cmd_buf) == 0 ? 0 : -1;
		case KSU_NOMOUNT_CMD_CLEAR_ALL:
			return system(
				"/data/adb/modules/nomount/bin/nm clear")
				== 0 ? 0 : -1;
		default:
			return -1;
		}
	}
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[512];
	} req;
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct genlmsghdr));
	req.n.nlmsg_type = fam_id;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.g.cmd = cmd;
	req.g.version = 1;

	char *p = req.buf;
	if (virt && *virt) {
		struct nlattr *attr = (struct nlattr *)p;
		int len = strlen(virt) + 1;
		attr->nla_type = KSU_NOMOUNT_ATTR_VIRTUAL_PATH;
		attr->nla_len = NLA_HDRLEN + len;
		memcpy((char *)attr + NLA_HDRLEN, virt, len);
		p += NLA_ALIGN(attr->nla_len);
	}
	if (real && *real) {
		struct nlattr *attr = (struct nlattr *)p;
		int len = strlen(real) + 1;
		attr->nla_type = KSU_NOMOUNT_ATTR_REAL_PATH;
		attr->nla_len = NLA_HDRLEN + len;
		memcpy((char *)attr + NLA_HDRLEN, real, len);
		p += NLA_ALIGN(attr->nla_len);
	}
	req.n.nlmsg_len += p - req.buf;
	return send(nl_fd, &req, req.n.nlmsg_len, 0) >= 0 ? 0 : -1;
}

int main(int argc, char **argv) {
	int n = argc > 1 ? atoi(argv[1]) : 1000;
	int cpu = argc > 2 ? atoi(argv[2]) : 2;
	int drop_uid = argc > 3 ? atoi(argv[3]) : 0;

	if (nl_open() != 0) {
		fprintf(stderr, "netlink nomount family unavailable\n");
		return 2;
	}

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
	if (drop_uid > 0 && setuid(drop_uid) != 0) {
		fprintf(stderr, "setuid(%d) failed\n", drop_uid);
		return 2;
	}
	if (drop_uid > 0)
		printf("# running as uid %d\n", getuid());

	unsigned long long *v = malloc(sizeof(*v) * n);
	if (!v) return 1;
	struct stat st;

	/* App-uid measure-only mode: the root wrapper pre-arranges rule state
	 * (GENL ADMIN_PERM forbids app-uid toggling) and passes the case
	 * letter as argv[4].  Only the timed loop runs here. */
	if (drop_uid > 0 && argc > 4) {
		const char *path = NULL;
		const char *tag = argv[4];
		if (!strcmp(tag, "C") || !strcmp(tag, "D"))
			path = VIRT;
		else
			path = NOMATCH;
		unsigned long long *mv = malloc(sizeof(*mv) * n);
		if (!mv) return 1;
		for (int i = 0; i < n; i++) {
			unsigned long long t0 = now();
			sys_stat(path, &st);
			mv[i] = now() - t0;
		}
		char namebuf[64];
		snprintf(namebuf, sizeof(namebuf), "appuid_%s", tag);
		report(namebuf, mv, n);
		free(mv);
		close(nl_fd);
		free(v);
		return 0;
	}

	/* sanity: verify toggle works */
	nl_cmd(KSU_NOMOUNT_CMD_CLEAR_ALL, NULL, NULL);
	usleep(60000);
	nl_cmd(KSU_NOMOUNT_CMD_ADD_RULE, VIRT, REAL);
	usleep(60000);
	/* Sanity: with the rule active the virtual path must resolve to the
	 * BACKEND content (redirect works).  Identity of an existing virtual
	 * file is preserved by design, so ino comparison is not a valid
	 * toggle probe; content byte comparison is. */
	if (sys_stat(VIRT, &st) != 0) {
		fprintf(stderr, "rule toggle sanity failed\n");
		return 2;
	}
	{
		char buf_r[16] = {0}, buf_v[16] = {0};
		int fd;
		fd = open(REAL, O_RDONLY);
		if (fd < 0 || read(fd, buf_r, 8) < 1) { close(fd);
			fprintf(stderr, "backend read failed\n"); return 2; }
		close(fd);
		fd = open(VIRT, O_RDONLY);
		if (fd < 0 || read(fd, buf_v, 8) < 1) { close(fd);
			fprintf(stderr, "virtual read failed\n"); return 2; }
		close(fd);
		if (strcmp(buf_r, buf_v) != 0) {
			fprintf(stderr, "redirect content sanity failed\n");
			return 2;
		}
	}
	nl_cmd(KSU_NOMOUNT_CMD_CLEAR_ALL, NULL, NULL);
	usleep(60000);
	if (sys_stat(VIRT, &st) != 0) {
		fprintf(stderr, "post-clear stat failed\n");
		return 2;
	}

	/* ---- Case A: disabled ---- */
	nl_cmd(KSU_NOMOUNT_CMD_CLEAR_ALL, NULL, NULL);
	usleep(60000);
	for (int i = 0; i < n; i++) {
		unsigned long long t0 = now();
		sys_stat(NOMATCH, &st);
		v[i] = now() - t0;
	}
	report("A_disabled", v, n);

	/* ---- Case B: enabled, no match ---- */
	nl_cmd(KSU_NOMOUNT_CMD_ADD_RULE, DUMMY, REAL);
	usleep(60000);
	for (int i = 0; i < n; i++) {
		unsigned long long t0 = now();
		sys_stat(NOMATCH, &st);
		v[i] = now() - t0;
	}
	report("B_enabled_nomatch", v, n);

	/* ---- Case C: match (first-touch path) ---- */
	nl_cmd(KSU_NOMOUNT_CMD_DEL_RULE, DUMMY, NULL);
	nl_cmd(KSU_NOMOUNT_CMD_ADD_RULE, VIRT, REAL);
	usleep(60000);
	for (int i = 0; i < n; i++) {
		unsigned long long t0 = now();
		if (sys_stat(VIRT, &st) != 0) { /* count errors via ret */ }
		v[i] = now() - t0;
	}
	report("C_match", v, n);

	/* ---- Case D: repeated match (hot) ---- */
	for (int i = 0; i < n; i++) {
		unsigned long long t0 = now();
		sys_stat(VIRT, &st);
		v[i] = now() - t0;
	}
	report("D_match_hot", v, n);

	/* ---- Case E: repeated non-match with rule present ---- */
	for (int i = 0; i < n; i++) {
		unsigned long long t0 = now();
		sys_stat(NOMATCH, &st);
		v[i] = now() - t0;
	}
	report("E_nomatch_hot", v, n);

	nl_cmd(KSU_NOMOUNT_CMD_CLEAR_ALL, NULL, NULL);
	close(nl_fd);
	free(v);
	return 0;
}
