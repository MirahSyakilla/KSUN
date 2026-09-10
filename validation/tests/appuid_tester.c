/* appuid_tester.c — AArch64 static binary run from an Android app process.
 * Reports uid, SELinux context, and exercises SUSFS/redirect-relevant syscalls.
 * Deployed inside an APK's native lib dir and invoked via Runtime.exec().
 *
 * Build: aarch64-linux-android33-clang -static -O2
 * Output: structured lines parseable from the app.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>

static int uid;
static char ctx[256];

static void get_identity(void) {
	uid = getuid();
	/* Read SELinux context */
	int fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd >= 0) {
		ssize_t r = read(fd, ctx, sizeof(ctx) - 1);
		if (r > 0) ctx[r] = '\0';
		else strcpy(ctx, "unknown");
		close(fd);
	} else {
		strcpy(ctx, "unknown");
	}
	printf("UID=%d\n", uid);
	printf("CTX=%s\n", ctx);
}

static void test_path_visibility(const char *path, const char *label) {
	struct stat st;
	int ret = stat(path, &st);
	if (ret == 0) {
		printf("VIS_%s=VISIBLE ino=%lu size=%ld\n", label,
		       (unsigned long)st.st_ino, (long)st.st_size);
	} else {
		printf("VIS_%s=%s\n", label, strerror(errno));
	}
}

static void test_open(const char *path, const char *label, int flags) {
	int fd = open(path, flags, 0644);
	if (fd >= 0) {
		char buf[64];
		ssize_t r = read(fd, buf, sizeof(buf) - 1);
		if (r > 0) buf[r] = '\0'; else buf[0] = '\0';
		printf("OPEN_%s=OK content=%s\n", label, buf);
		close(fd);
	} else {
		printf("OPEN_%s=%s\n", label, strerror(errno));
	}
}

static void test_readlink(const char *path, const char *label) {
	char buf[512];
	ssize_t r = readlink(path, buf, sizeof(buf) - 1);
	if (r > 0) { buf[r] = '\0'; printf("LINK_%s=%s\n", label, buf); }
	else printf("LINK_%s=%s\n", label, strerror(errno));
}

int main(int argc, char *argv[]) {
	setvbuf(stdout, NULL, _IONBF, 0);
	get_identity();

	/* SUSFS path visibility probes
	 * These paths are interesting because SUSFS may hide them from apps
	 * but not from root.  The app should see different results than root.
	 */
	printf("--- SUSFS visibility ---\n");
	test_path_visibility("/data/adb", "data_adb");
	test_path_visibility("/data/adb/ksud", "ksud");
	test_path_visibility("/data/adb/modules", "modules");
	test_path_visibility("/system/bin/su", "system_su");
	test_path_visibility("/sbin/su", "sbin_su");

	/* SUSFS hidden-path open test */
	printf("--- SUSFS open ---\n");
	test_open("/system/bin/su", "system_su", O_RDONLY);

	/* Open redirect: the app tests a path that might be redirected */
	if (argc > 2) {
		printf("--- open_redirect ---\n");
		printf("REDIR_TARGET=%s\n", argv[2]);
		test_open(argv[2], "redirect_target", O_RDONLY);
	}

	/* /proc links */
	printf("--- proc links ---\n");
	test_readlink("/proc/self/exe", "self_exe");
	test_readlink("/proc/self/cmdline", "self_cmdline");

	printf("DONE\n");
	return 0;
}
