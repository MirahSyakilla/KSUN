/* bl_edge_tester.c — C-level edge case tests for the branch-link migration.
 * Tests O_NOFOLLOW, O_PATH, execveat AT_EMPTY_PATH, statx, and error paths
 * that shell utilities cannot exercise.
 *
 * Build (AArch64): aarch64-linux-android33-clang -static -O2
 * Build (AArch32): armv7a-linux-androideabi33-clang -static -O2
 * Usage: bl_edge_tester <test-dir>
 * Exit 0 = all pass.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdlib.h>

#ifndef O_PATH
#define O_PATH 010000000
#endif

/* Minimal statx buffer — layout matches struct statx from linux/stat.h */
struct statx_buf {
	unsigned int stx_mask;
	unsigned int stx_blksize;
	unsigned long long stx_attributes;
	unsigned int stx_nlink;
	unsigned int stx_uid;
	unsigned int stx_gid;
	unsigned short stx_mode;
	unsigned short pad1;
	unsigned long long stx_ino;
	unsigned long long stx_size;
	unsigned long long stx_blocks;
	unsigned long long stx_attributes_mask;
	unsigned long long stx_atime;
	unsigned int stx_atime_nsec;
	unsigned long long stx_btime;
	unsigned int stx_btime_nsec;
	unsigned long long stx_ctime;
	unsigned int stx_ctime_nsec;
	unsigned long long stx_mtime;
	unsigned int stx_mtime_nsec;
	unsigned int stx_rdev_major;
	unsigned int stx_rdev_minor;
	unsigned int stx_dev_major;
	unsigned int stx_dev_minor;
	unsigned long long stx_mnt_id;
	unsigned int pad2[14];
};

static int fails = 0;
static int passes = 0;

static void record(const char *name, int ok) {
	printf("%s: %s\n", ok ? "PASS" : "FAIL", name);
	if (ok) passes++; else fails++;
}

static void test_onofollow(const char *dir) {
	char link_path[512], target_path[512];
	snprintf(target_path, sizeof(target_path), "%s/onofollow_target", dir);
	snprintf(link_path, sizeof(link_path), "%s/onofollow_link", dir);

	int fd = open(target_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);
	unlink(link_path);
	symlink(target_path, link_path);

	/* O_NOFOLLOW on a symlink should fail with ELOOP */
	int f = open(link_path, O_RDONLY | O_NOFOLLOW);
	if (f < 0 && errno == ELOOP)
		record("O_NOFOLLOW symlink -> ELOOP", 1);
	else {
		if (f >= 0) close(f);
		record("O_NOFOLLOW symlink -> ELOOP", 0);
	}

	/* O_NOFOLLOW on a regular file should succeed */
	f = open(target_path, O_RDONLY | O_NOFOLLOW);
	if (f >= 0) { close(f); record("O_NOFOLLOW regular file", 1); }
	else record("O_NOFOLLOW regular file", 0);

	unlink(link_path);
	unlink(target_path);
}

static void test_opath(const char *dir) {
	char path[512];
	snprintf(path, sizeof(path), "%s/opath_test", dir);
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);

	/* O_PATH: open, but only for path resolution */
	fd = open(path, O_PATH);
	if (fd < 0) {
		/* O_PATH = 010000000 on generic Linux */
		fd = open(path, 010000000);
	}
	if (fd >= 0) {
		/* Should be able to fstat the fd */
		struct stat st;
		if (fstat(fd, &st) == 0)
			record("O_PATH open + fstat", 1);
		else
			record("O_PATH open + fstat", 0);
		/* Should NOT be able to read */
		char buf[1];
		ssize_t r = read(fd, buf, 1);
		if (r < 0)
			record("O_PATH read -> EBADF/EINVAL", 1);
		else
			record("O_PATH read -> EBADF/EINVAL", 0);
		close(fd);
	} else {
		record("O_PATH open", 0);
	}
	unlink(path);
}

static void test_statx(const char *dir) {
	char path[512];
	snprintf(path, sizeof(path), "%s/statx_test", dir);
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);

	/* statx syscall (nr 291 on arm64) */
	struct statx_buf {
		unsigned int stx_mask;
		unsigned int stx_blksize;
		unsigned long long stx_attributes;
		unsigned int stx_nlink;
		unsigned int stx_uid;
		unsigned int stx_gid;
		unsigned short stx_type;
		unsigned short pad1;
		unsigned long long stx_ino;
		unsigned long long stx_size;
		/* ... more fields ... */
		unsigned char raw[256];
	} sb;
	memset(&sb, 0, sizeof(sb));

	long ret = syscall(291 /* __NR_statx */,
			   -100 /* AT_FDCWD */,
			   path,
			   0 /* flags */,
			   0x7ff /* STATX_BASIC_STATS */,
			   &sb);
	if (ret == 0) {
		record("statx syscall", 1);
		if (sb.stx_size == 0 || sb.stx_size < 4096)
			record("statx size sane", 1);
		else
			record("statx size sane", 0);
	} else {
		printf("  statx errno=%d\n", errno);
		record("statx syscall", 0);
	}
	unlink(path);
}

static void test_execveat_atempty(const char *dir) {
	char path[512];
	snprintf(path, sizeof(path), "%s/execveat_test", dir);

	/* Create a small executable */
	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (fd < 0) { record("execveat setup", 0); return; }
	write(fd, "\177ELF", 4); /* magic only, will fail with ENOEXEC */
	close(fd);

	/* Open the file to get a fd */
	fd = open(path, O_RDONLY);
	if (fd < 0) { record("execveat setup open", 0); return; }

	/* execveat(fd, "", AT_EMPTY_PATH) — should fail with ENOEXEC
	 * because the file has no valid binfmt */
	long ret = syscall(281 /* __NR_execveat */,
			   fd,
			   "" /* empty pathname */,
			   NULL, NULL,
			   0x1000 /* AT_EMPTY_PATH */);
	if (ret < 0 && (errno == ENOEXEC || errno == ENOENT))
		record("execveat AT_EMPTY_PATH -> ENOEXEC", 1);
	else {
		char msg[64];
		snprintf(msg, sizeof(msg), "execveat AT_EMPTY_PATH (ret=%ld errno=%d)", ret, errno);
		record(msg, ret == 0);
	}

	close(fd);
	unlink(path);
}

static void test_lstat_vs_stat(const char *dir) {
	char target[512], link[512];
	snprintf(target, sizeof(target), "%s/lstat_target", dir);
	snprintf(link, sizeof(link), "%s/lstat_link", dir);

	int fd = open(target, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd >= 0) close(fd);
	unlink(link);
	symlink(target, link);

	struct stat st_link, st_target;
	if (lstat(link, &st_link) == 0 && stat(link, &st_target) == 0) {
		/* lstat should report symlink, stat should report regular file */
		int ok = S_ISLNK(st_link.st_mode) && S_ISREG(st_target.st_mode);
		record("lstat vs stat mode distinction", ok);
	} else {
		record("lstat vs stat", 0);
	}

	/* statx on symlink with AT_SYMLINK_NOFOLLOW */
	struct statx_buf sx;
	memset(&sx, 0, sizeof(sx));
	long ret = syscall(291, -100, link, 0x100 /* AT_SYMLINK_NOFOLLOW */,
			   0x001 /* STATX_TYPE */, &sx);
	if (ret == 0 && (sx.stx_mask & 1) && ((sx.stx_mode & S_IFMT) == S_IFLNK))
		record("statx AT_SYMLINK_NOFOLLOW detects symlink", 1);
	else
		record("statx AT_SYMLINK_NOFOLLOW", 0);  /* May not be supported */

	unlink(link);
	unlink(target);
}

int main(int argc, char *argv[]) {
	const char *dir = (argc > 1) ? argv[1] : "/data/local/tmp/bl-test";

	printf("=== bl_edge_tester ===\n");
	printf("uid=%d dir=%s\n", getuid(), dir);

	test_onofollow(dir);
	test_opath(dir);
	test_statx(dir);
	test_execveat_atempty(dir);
	test_lstat_vs_stat(dir);

	printf("---\n");
	printf("bl_edge_tester: %s (PASS=%d FAIL=%d)\n",
	       fails ? "FAIL" : "PASS", passes, fails);
	return fails;
}
