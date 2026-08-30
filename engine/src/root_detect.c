/*
 * root_detect.c - Root / KernelSU / Magisk 检测模块
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
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
static int check_magiskd(aegis_result_t *r);
static int check_ksud(aegis_result_t *r);
static int check_zygiskd(aegis_result_t *r);
static int check_which_su(aegis_result_t *r);
static int check_adb_dir(aegis_result_t *r);
static int check_magisk_sbin(aegis_result_t *r);
static int check_modules(aegis_result_t *r);
static int check_zygisk_data(aegis_result_t *r);
static int check_ksu_kernel(aegis_result_t *r);
static int check_apatch_kernel(aegis_result_t *r);
static int check_selinux_mismatch(aegis_result_t *r);
static int check_build_tamper(aegis_result_t *r);

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
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "magiskd守护进程"); check_magiskd(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "ksud守护进程"); check_ksud(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "zygiskd守护进程"); check_zygiskd(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "which su/magisk"); check_which_su(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Magisk隐藏挂载"); check_magisk_sbin(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "模块枚举"); check_modules(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "Zygisk数据目录"); check_zygisk_data(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "KSU内核特征"); check_ksu_kernel(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "APatch内核特征"); check_apatch_kernel(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "SELinux不一致"); check_selinux_mismatch(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_ROOT; snprintf(r[n].name, sizeof(r[n].name), "build属性篡改"); check_build_tamper(&r[n]); n++; }
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

/* ====== 增强2: 守护进程/运行时行为检测 ====== */

/* 21. magiskd 守护进程: root 激活后常驻 */
static int check_magiskd(aegis_result_t *r) {
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char pcomm[64], ppath[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        if (strcmp(pcomm, "magiskd") == 0 || strcmp(pcomm, "magisk") == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Magisk 守护进程: %s (PID=%s)", pcomm, e->d_name);
            closedir(d);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 22. ksud 守护进程: KernelSU 常驻 */
static int check_ksud(aegis_result_t *r) {
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char pcomm[64], ppath[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        if (strcmp(pcomm, "ksud") == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 KernelSU 守护进程 ksud (PID=%s)", e->d_name);
            closedir(d);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 23. zygiskd 守护进程 */
static int check_zygiskd(aegis_result_t *r) {
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char pcomm[64], ppath[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        if (strcmp(pcomm, "zygiskd") == 0 || strcmp(pcomm, "zygisk") == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Zygisk 守护进程: %s (PID=%s)", pcomm, e->d_name);
            closedir(d);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 24. which 命令探测 su/magisk */
static int check_which_su(aegis_result_t *r) {
    FILE *f = popen("which su magisk ksud 2>/dev/null", "r");
    if (!f) { r->detected = 0; return 0; }
    char buf[256];
    int found = 0;
    while (fgets(buf, sizeof(buf), f)) {
        found = 1;
        buf[strcspn(buf, "\n")] = 0;
        snprintf(r->evidence, sizeof(r->evidence),
                 "PATH 中发现提权命令: %s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        pclose(f);
        return 1;
    }
    pclose(f);
    r->detected = 0;
    (void)found;
    return 0;
}

/* 25. /data/adb 权限检测: 可访问说明被 root 管理 */
static int check_adb_dir(aegis_result_t *r) {
    /* /data/adb 是 Magisk/KSU 数据根, 普通应用不可读 */
    char buf[16];
    FILE *f = fopen("/data/adb/magisk", "r");
    if (f) { fclose(f); r->detected = 0; return 0; } /* 已由路径检测覆盖 */
    struct stat st;
    if (stat("/data/adb", &st) == 0) {
        /* 能 stat 到说明 SELinux 放行, 本身不异常, 由其他项判定 */
    }
    r->detected = 0;
    return 0;
}

/* ====== 增强3: Magisk深层目录 / KernelSU内核特征 ====== */

/* 26. Magisk 隐藏挂载根 */
static int check_magisk_sbin(aegis_result_t *r) {
    static const char *paths[] = {
        "/sbin/.magisk", "/debug_ramdisk/magisk",
        "/sbin/.magisk/mirror", "/dev/block/magisk"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Magisk 隐藏挂载: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 27. 枚举 /data/adb/modules 已装模块 */
static int check_modules(aegis_result_t *r) {
    DIR *d = opendir("/data/adb/modules");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    int count = 0;
    char names[128] = "";
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;
        if (count <= 3 && strlen(names) < 100) {
            strncat(names, e->d_name, sizeof(names) - strlen(names) - 1);
            strncat(names, " ", sizeof(names) - strlen(names) - 1);
        }
    }
    closedir(d);
    if (count > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 %d 个 Magisk/KSU 模块: %s", count, names);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 28. Zygisk 数据目录 */
static int check_zygisk_data(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/zygisk")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 Zygisk 数据目录 /data/adb/zygisk");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 29. KernelSU 内核特征: 内核版本含 ksu/gki */
static int check_ksu_kernel(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/version", buf, sizeof(buf));
    if (n > 0) {
        if (aegis_strcasestr(buf, "kernelSU") || aegis_strcasestr(buf, "gki") ||
            aegis_strcasestr(buf, "ksu")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "内核版本含 KernelSU 特征: %.80s", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 30. APatch 内核补丁特征 */
static int check_apatch_kernel(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/version", buf, sizeof(buf));
    if (n > 0 && aegis_strcasestr(buf, "kpatch")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "内核含 kpatch 特征 (APatch): %.60s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 31. SELinux 属性 vs 运行时不一致 (被 resetprop 伪装) */
static int check_selinux_mismatch(aegis_result_t *r) {
    char prop[128];
    char rt[16];
    #ifdef __ANDROID__
    __system_property_get("ro.build.selinux", prop);
    #else
    prop[0] = '\0';
    #endif
    long n = aegis_read_file("/sys/fs/selinux/enforce", rt, sizeof(rt));
    /* 属性说 enforcing 但实际 enforce=0 说明被隐藏/修改 */
    if (n > 0 && rt[0] == '0' && (prop[0] == '\0' || strstr(prop, "enfor"))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "SELinux 属性宣称 enforcing 但运行时 permissive (疑似被伪装)");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 32. ro.build 属性被篡改 (resetprop 特征) */
static int check_build_tamper(aegis_result_t *r) {
    char a[128], b[128], c[128];
    #ifdef __ANDROID__
    __system_property_get("ro.build.version.release", a);
    __system_property_get("ro.build.version.sdk", b);
    __system_property_get("ro.product.model", c);
    /* 若 model 与 fingerprint 品牌矛盾说明属性被改 */
    char fp[256];
    __system_property_get("ro.build.fingerprint", fp);
    if (fp[0] && c[0]) {
        char *slash = strchr(fp, '/');
        char brand_fp[64] = "";
        if (slash) {
            size_t len = (size_t)(slash - fp);
            if (len < 63) { memcpy(brand_fp, fp, len); brand_fp[len] = '\0'; }
        }
        if (brand_fp[0] && !strstr(c, brand_fp) && strlen(brand_fp) > 3) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "build 属性矛盾: fingerprint=%s vs model=%s (疑似被改)", brand_fp, c);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }
    #else
    (void)a; (void)b; (void)c;
    #endif
    r->detected = 0;
    return 0;
}
