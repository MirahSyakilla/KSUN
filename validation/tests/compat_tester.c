/* compat_tester.c — minimal AArch32 compat syscall tester
 * Build: armv7a-linux-androideabi33-clang -static -O2
 * Exit code 0 = all pass
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string.h>

int main(int argc, char *argv[]) {
	int fails = 0;
	const char *path = (argc > 1) ? argv[1] : "/data/local/tmp/bl-test/test_file";

	/* creat */
	int fd = creat("/data/local/tmp/bl-test/compat_creat.txt", 0644);
	if (fd < 0) { printf("FAIL: creat\n"); fails++; }
	else close(fd);

	/* open O_RDONLY */
	fd = open(path, O_RDONLY);
	if (fd < 0) { printf("FAIL: open(%s)\n", path); fails++; }
	else close(fd);

	/* stat */
	struct stat st;
	if (stat(path, &st) < 0) { printf("FAIL: stat(%s)\n", path); fails++; }

	/* readlink /proc/self/exe */
	char buf[256];
	ssize_t r = readlink("/proc/self/exe", buf, sizeof(buf)-1);
	if (r > 0) { buf[r] = '\0'; printf("readlink: %s\n", buf); }
	else { printf("FAIL: readlink\n"); fails++; }

	/* faccessat */
	long ret = syscall(__NR_faccessat, -100 /*AT_FDCWD*/, path, R_OK, 0);
	if (ret < 0) { printf("FAIL: faccessat\n"); fails++; }

	/* execve /system/bin/true */
	if (fails == 0) {
		char *argv2[] = { "/system/bin/true", NULL };
		char *envp[] = { NULL };
		execve("/system/bin/true", argv2, envp);
		printf("FAIL: execve\n"); fails++;
	}

	printf("compat_tester: %s (%d failures)\n", fails ? "FAIL" : "PASS", fails);
	return fails;
}
