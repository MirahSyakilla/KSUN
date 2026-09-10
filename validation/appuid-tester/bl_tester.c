#include <jni.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>

static char result_buf[4096];
static int result_pos = 0;

static void emit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    result_pos += vsnprintf(result_buf + result_pos,
                            sizeof(result_buf) - result_pos, fmt, ap);
    va_end(ap);
}

JNIEXPORT jstring JNICALL
Java_com_bl_validation_TestActivity_runTests(JNIEnv *env, jclass cls) {
    result_pos = 0;
    struct stat st;
    char path[512];
    const char *files_dir;

    /* Get app-internal files dir */
    files_dir = "/data/user/0/com.bl.validation/files";

    emit("UID=%d\n", getuid());
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) {
        char ctx[256];
        ssize_t r = read(fd, ctx, sizeof(ctx)-1);
        if (r > 0) { ctx[r] = 0; emit("CTX=%s\n", ctx); }
        close(fd);
    }

    /* SUSFS visibility probes */
    emit("--- SUSFS visibility ---\n");
    const char *probe_paths[] = {
        "/data/adb", "/data/adb/ksud", "/data/adb/modules",
        "/system/bin/su", "/sbin/su", NULL
    };
    const char *probe_names[] = {
        "data_adb", "ksud", "modules", "system_su", "sbin_su", NULL
    };
    for (int i = 0; probe_paths[i]; i++) {
        if (stat(probe_paths[i], &st) == 0)
            emit("VIS_%s=VISIBLE ino=%lu\n", probe_names[i], (unsigned long)st.st_ino);
        else
            emit("VIS_%s=%s\n", probe_names[i], strerror(errno));
    }

    /* open test on /system/bin/su */
    emit("--- open ---\n");
    fd = open("/system/bin/su", O_RDONLY);
    if (fd >= 0) {
        char buf[32];
        ssize_t r = read(fd, buf, sizeof(buf)-1);
        if (r > 0) buf[r] = 0; else buf[0] = 0;
        emit("OPEN_su=OK content=%s\n", buf);
        close(fd);
    } else {
        emit("OPEN_su=%s\n", strerror(errno));
    }

    /* Open redirect test: target path is passed via a well-known location */
    emit("--- redirect ---\n");
    snprintf(path, sizeof(path), "%s/redir_target.txt", files_dir);
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        ssize_t r = read(fd, buf, sizeof(buf)-1);
        if (r > 0) buf[r] = 0; else buf[0] = 0;
        emit("REDIR_RESULT=%s\n", buf);
        close(fd);
    } else {
        emit("REDIR_RESULT=%s\n", strerror(errno));
    }

    /* stat on various paths for identity comparison */
    emit("--- stat ---\n");
    snprintf(path, sizeof(path), "%s/stat_target.txt", files_dir);
    if (stat(path, &st) == 0)
        emit("STAT_target=OK ino=%lu dev=%lu\n", (unsigned long)st.st_ino, (unsigned long)st.st_dev);
    else
        emit("STAT_target=%s\n", strerror(errno));

    return (*env)->NewStringUTF(env, result_buf);
}
