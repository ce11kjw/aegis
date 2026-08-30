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


static int check_magisk_policy(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/magisk/magiskpolicy")) {
        snprintf(r->evidence, sizeof(r->evidence), "发现 magiskpolicy (Magisk SELinux 策略工具)");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT; return 1;
    } r->detected = 0; return 0;
}
static int check_ksu_service(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/ksu/"))
        { r->detected = 1; r->level = AEGIS_LEVEL_CRIT; snprintf(r->evidence, sizeof(r->evidence), "发现 KernelSU 模块目录"); return 1; }
    r->detected = 0; return 0;
}
static int check_apatch(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/apd"))
        { r->detected = 1; r->level = AEGIS_LEVEL_CRIT; snprintf(r->evidence, sizeof(r->evidence), "发现 APatch 特征"); return 1; }
    r->detected = 0; return 0;
}
static int check_busybox(aegis_result_t *r) {
    if (aegis_file_exists("/system/xbin/busybox") || aegis_file_exists("/sbin/busybox"))
        { r->detected = 1; r->level = AEGIS_LEVEL_HIGH; snprintf(r->evidence, sizeof(r->evidence), "发现 busybox (提权工具链)"); return 1; }
    r->detected = 0; return 0;
}
static int check_magisk_mirror(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/mounts", buf, sizeof(buf));
    if (n > 0 && strstr(buf, "magisk"))
        { r->detected = 1; r->level = AEGIS_LEVEL_CRIT; snprintf(r->evidence, sizeof(r->evidence), "发现 Magisk 镜像挂载"); return 1; }
    r->detected = 0; return 0;
}
static int check_dm_verity(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.config.verity", buf);
    if (strstr(buf, "disabled") || strstr(buf, "0"))
        { r->detected = 1; r->level = AEGIS_LEVEL_HIGH; snprintf(r->evidence, sizeof(r->evidence), "dm-verity 被禁用 (系统分区可被篡改)"); return 1; }
    #endif
    r->detected = 0; return 0;
}
static int check_denylist(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/magisk/denylist"))
        { r->detected = 1; r->level = AEGIS_LEVEL_MED; snprintf(r->evidence, sizeof(r->evidence), "Magisk DenyList 已配置 (隐藏 Root 特征)"); return 1; }
    r->detected = 0; return 0;
}
static int check_app_process_r(aegis_result_t *r) {
    r->detected = 0; return 0;
}

/* 前向声明 */
static int check_magisk_policy(aegis_result_t *r);
static int check_ksu_service(aegis_result_t *r);
static int check_apatch(aegis_result_t *r);
static int check_busybox(aegis_result_t *r);
static int check_magisk_mirror(aegis_result_t *r);
static int check_dm_verity(aegis_result_t *r);
static int check_denylist(aegis_result_t *r);
static int check_app_process_r(aegis_result_t *r);
static int check_bootloader(aegis_result_t *r);
static int check_vbmeta(aegis_result_t *r);
static int check_magisk_env(aegis_result_t *r);
static int check_kernel_cmdline(aegis_result_t *r);
static int check_manager_apk(aegis_result_t *r);
static int check_sys_rw_detail(aegis_result_t *r);
static int check_zygisk_env(aegis_result_t *r);

int aegis_root_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "su二进制检测"); check_su_binary(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Root管理器特征"); check_magisk(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "test-keys签名"); check_build_testkey(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "系统分区rw挂载"); check_mount_rw(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "su执行测试"); check_exec_su(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "magiskpolicy检测"); check_magisk_policy(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "KernelSU检测"); check_ksu_service(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "APatch检测"); check_apatch(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "busybox检测"); check_busybox(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Magisk镜像"); check_magisk_mirror(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "dm-verity检测"); check_dm_verity(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "DenyList检测"); check_denylist(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "app_process替换"); check_app_process_r(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "bootloader解锁"); check_bootloader(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "vbmeta校验"); check_vbmeta(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Magisk环境变量"); check_magisk_env(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "内核cmdline"); check_kernel_cmdline(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "管理器APK"); check_manager_apk(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "系统分区rw细查"); check_sys_rw_detail(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Zygisk环境"); check_zygisk_env(&r[n]); n++; }
    return n;
}

/* ====== 增强: bootloader/内核/管理器APK 检测 ====== */

/* 14. bootloader 解锁检测: verifiedbootstate=orange/red 说明解锁 */
static int check_bootloader(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.boot.verifiedbootstate", buf);
    if (strstr(buf, "orange") || strstr(buf, "red")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "Bootloader 已解锁 (verifiedbootstate=%s)", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    __system_property_get("ro.boot.flash.locked", buf);
    if (strcmp(buf, "0") == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "设备 flash.locked=0 (Bootloader 未锁定)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}

/* 15. vbmeta 状态: device_state=unlocked 说明解锁 */
static int check_vbmeta(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.boot.vbmeta.device_state", buf);
    if (strstr(buf, "unlocked")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "vbmeta device_state=unlocked (系统完整性校验被关)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}

/* 16. Magisk 环境变量: MAGISKTMP 等特征变量 */
static int check_magisk_env(aegis_result_t *r) {
    extern char **environ;
    for (int i = 0; environ && environ[i]; i++) {
        if (strncmp(environ[i], "MAGISKTMP", 9) == 0 ||
            strncmp(environ[i], "MAGISK_", 7) == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Magisk 环境变量: %s", environ[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 17. 内核 cmdline 检测: 含 magisk/root 特征 */
static int check_kernel_cmdline(aegis_result_t *r) {
    char buf[2048];
    long n = aegis_read_file("/proc/cmdline", buf, sizeof(buf));
    if (n > 0) {
        if (aegis_strcasestr(buf, "magisk") ||
            aegis_strcasestr(buf, "androidboot.verifiedbootstate=orange") ||
            aegis_strcasestr(buf, "androidboot.flash.locked=0")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "内核 cmdline 含 Root 特征");
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 18. 管理器 APK 检测: 已知 Root 管理器包名路径 */
static int check_manager_apk(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/app/com.topjohnwu.magisk",
        "/data/app/me.weishu.kernelsu",
        "/data/app/com.youhua.ksu",
        "/data/app/com.superuser",
        "/data/app/eu.chainfire.supersu",
        "/data/app/com.kunkun.ksu",
        "/data/app/io.github.a13e300.ksuide",
        "/data/app/org.lsposed.manager"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Root 管理器应用: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 19. 系统分区可写检测: 通过 /proc/mounts 细查 */
static int check_sys_rw_detail(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/mounts", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    const char *p = buf;
    while ((p = strstr(p, " /system ")) != NULL) {
        /* 检查 mount 选项是否含 rw */
        const char *opt = strchr(p, ' ');
        if (opt) {
            opt = strchr(opt + 1, ' ');
            if (opt && strstr(opt, " rw") != NULL) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "/system 以 rw 挂载 (Root 特征)");
                r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
                return 1;
            }
        }
        p += 8;
    }
    r->detected = 0;
    return 0;
}

/* 20. Zygisk 环境: 检测 zygisk 的 socket/挂载 */
static int check_zygisk_env(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/mounts", buf, sizeof(buf));
    if (n > 0 && aegis_strcasestr(buf, "zygisk")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 Zygisk 相关挂载 (Magisk Zygisk 环境)");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}
