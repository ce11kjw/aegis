/*
 * root_detect.c - Root / KernelSU / Magisk 检测模块
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#ifdef __ANDROID__
#include <sys/system_properties.h>
static int get_prop(const char *key, char *out, size_t size) {
    return __system_property_get(key, out);
}
#else
static int get_prop(const char *key, char *out, size_t size) {
    (void)key; (void)out; (void)size;
    return 0;
}
#endif

static int check_su_binary(aegis_result_t *r) {
    static const char *paths[] = {
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/su/bin/su", "/system/bin/.ext/.su",
        "/data/local/bin/su", "/data/local/xbin/su",
        "/system/bin/debuggerd", "/system/bin/failsafe/su"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 su 可执行文件: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

static int check_magisk(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/adb/magisk", "/data/adb/magisk.db",
        "/data/adb/magisk/busybox", "/data/adb/ksu",
        "/data/adb/ksu.db", "/data/adb/apd",
        "/sbin/magisk", "/debug_ramdisk/magisk",
        "/sbin/.magisk", "/sbin/.magisk/mirror"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Root 管理器特征: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

static int check_build_testkey(aegis_result_t *r) {
    char buf[128];
    get_prop("ro.build.tags", buf, sizeof(buf));
    if (strstr(buf, "test-keys")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统为 test-keys 签名 (常见于自定义 ROM)");
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

static int check_mount_rw(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/mounts", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    if (strstr(buf, "/system rw") || strstr(buf, " / rw")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统分区以 rw 挂载 (Root 常见特征)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

static int check_exec_su(aegis_result_t *r) {
    /* 尝试 fork 一个 su 进程, 能成功说明有 root */
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/su", "su", "-c", "true", NULL);
        execl("/system/xbin/su", "su", "-c", "true", NULL);
        _exit(127);
    }
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "su 命令可正常执行 (Root 权限已授予)");
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

int aegis_root_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "su二进制检测"); check_su_binary(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Root管理器特征"); check_magisk(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "test-keys签名"); check_build_testkey(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "系统分区rw挂载"); check_mount_rw(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "su执行测试"); check_exec_su(&r[n]); n++; }
    return n;
}
