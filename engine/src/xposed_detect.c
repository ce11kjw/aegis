/*
 * xposed_detect.c - Xposed / LSPosed / Zygisk 注入检测模块
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <dirent.h>

static int check_native_bridge(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    static const char *sigs[] = {
        "xposed", "lsposed", "edposed", "taichi", "zygisk",
        "riru", "libxposed", "dexposed", "pandora"
    };
    for (int i = 0; i < (int)(sizeof(sigs)/sizeof(sigs[0])); i++) {
        if (aegis_strcasestr(buf, sigs[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "内存映射发现 Xposed/Zygisk 特征: %s", sigs[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

static int check_system_prop(aegis_result_t *r) {
    char buf[256];
    FILE *f = popen("getprop ro.dalvik.vm.native.bridge 2>/dev/null", "r");
    if (!f) { r->detected = 0; return 0; }
    if (fgets(buf, sizeof(buf), f) && buf[0] && buf[0] != '\n' &&
        strstr(buf, "0") == NULL) {
        buf[strcspn(buf, "\n")] = 0;
        snprintf(r->evidence, sizeof(r->evidence),
                 "native.bridge 属性异常: %s (可能被 Xposed 框架修改)", buf);
        pclose(f);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    pclose(f);
    r->detected = 0;
    return 0;
}

static int check_packages(aegis_result_t *r) {
    /* 检查已安装的 Xposed 模块包名 */
    /* App 无 QUERY_ALL_PACKAGES 时只能检查已知路径 */
    static const char *paths[] = {
        "/data/data/de.robv.android.xposed.installer",
        "/data/data/com.solohsu.xposed.installer",
        "/data/data/org.lsposed.lsposed",
        "/data/data/com.termux/.zygisk",
        "/data/adb/modules/riru_",
        "/data/adb/modules/zygisk_",
        "/data/adb/modules/lsposed",
        "/data/adb/modules/taichi",
        "/data/adb/modules/edxposed"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Xposed/LSPosed 特征路径: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

static int check_zygisk_libs(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    /* Magisk Zygisk 加载的 so 通常有特征 */
    if (aegis_strcasestr(buf, "zygisk")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程内存中加载了 Zygisk 模块");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

int aegis_xposed_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "内存映射Xposed特征"); check_native_bridge(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "系统属性检测"); check_system_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Xposed模块路径"); check_packages(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Zygisk注入检测"); check_zygisk_libs(&r[n]); n++; }
    return n;
}
