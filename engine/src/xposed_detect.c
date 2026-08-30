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

/* 前向声明 */
static int check_xposed_jar(aegis_result_t *r);
static int check_libxposed(aegis_result_t *r);
static int check_installer_data(aegis_result_t *r);
static int check_shamiko(aegis_result_t *r);
static int check_classloader(aegis_result_t *r);
static int check_taichi(aegis_result_t *r);

/* 前向声明 */
static int check_dobby(aegis_result_t *r);
static int check_xhook(aegis_result_t *r);
static int check_libart_mod(aegis_result_t *r);
static int check_tmp_so(aegis_result_t *r);
static int check_xposed_props(aegis_result_t *r);
static int check_dalvik_cache(aegis_result_t *r);

int aegis_xposed_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "内存映射Xposed特征"); check_native_bridge(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "系统属性检测"); check_system_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Xposed模块路径"); check_packages(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Zygisk注入检测"); check_zygisk_libs(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "xposed.jar检测"); check_xposed_jar(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "libxposed检测"); check_libxposed(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Installer数据"); check_installer_data(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Shamiko隐藏"); check_shamiko(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "类加载器异常"); check_classloader(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Taichi模块"); check_taichi(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Dobby hook"); check_dobby(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "xhook/ehook"); check_xhook(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "libart异常"); check_libart_mod(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "tmp注入so"); check_tmp_so(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "Xposed属性"); check_xposed_props(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_XPOSED; snprintf(r[n].name, sizeof(r[n].name), "dalvik缓存"); check_dalvik_cache(&r[n]); n++; }
    return n;
}

static int check_xposed_jar(aegis_result_t *r) {
    if (aegis_file_exists("/system/framework/xposed.jar")) {
        snprintf(r->evidence, sizeof(r->evidence), "存在 /system/framework/xposed.jar");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT; return 1;
    }
    r->detected = 0; return 0;
}
static int check_libxposed(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0 && (strstr(buf, "libxposed_art") || strstr(buf, "libxposed_common"))) {
        snprintf(r->evidence, sizeof(r->evidence), "进程加载了 libxposed 库");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT; return 1;
    }
    r->detected = 0; return 0;
}
static int check_installer_data(aegis_result_t *r) {
    if (aegis_file_exists("/data/data/de.robv.android.xposed.installer")) {
        snprintf(r->evidence, sizeof(r->evidence), "发现 Xposed Installer 数据目录");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    r->detected = 0; return 0;
}
static int check_shamiko(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/modules/shamiko")) {
        snprintf(r->evidence, sizeof(r->evidence), "发现 Shamiko 隐藏模块 (Zygisk 隐藏绕过)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    r->detected = 0; return 0;
}
static int check_classloader(aegis_result_t *r) {
    r->detected = 0; return 0;  /* 需要 Java 层配合 */
}
static int check_taichi(aegis_result_t *r) {
    if (aegis_file_exists("/data/adb/modules/taichi")) {
        snprintf(r->evidence, sizeof(r->evidence), "发现 Taichi 模块");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT; return 1;
    }
    r->detected = 0; return 0;
}

/* 11. Dobby hook 框架检测 */
static int check_dobby(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0 && (aegis_strcasestr(buf, "libdobby") || aegis_strcasestr(buf, "dobby"))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 Dobby hook 框架映射");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 12. xhook/ehook 框架检测 */
static int check_xhook(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0 && (aegis_strcasestr(buf, "xhook") || aegis_strcasestr(buf, "ehook") ||
        aegis_strcasestr(buf, "bhook"))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 GOT hook 框架映射 (xhook/ehook/bhook)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 13. 系统框架被替换: libart 改动 */
static int check_libart_mod(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0) {
        /* 检测 libart 是否从非标准路径加载 */
        const char *p = aegis_strcasestr(buf, "libart");
        if (p && !strstr(p, "/system/") && !strstr(p, "/apex/")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "libart 从异常路径加载 (框架注入特征): %.80s", p);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 14. /data/local/tmp 注入 so 检测 */
static int check_tmp_so(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0 && strstr(buf, "/data/local/tmp") && strstr(buf, ".so")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "从 /data/local/tmp 加载 so (注入特征): %.80s",
                 strstr(buf, "/data/local/tmp"));
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 15. 系统属性框架特征: xposed 相关属性 */
static int check_xposed_props(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.modversion", buf);
    if (strstr(buf, "xposed") || strstr(buf, "Xposed")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统属性含 Xposed 特征: ro.modversion=%s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}

/* 16. 模块激活残留: dalvik 缓存异常 */
static int check_dalvik_cache(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/dalvik-cache/arm64/xposed", "/data/dalvik-cache/xposed",
        "/cache/xposed", "/data/user/0/org.lsposed.manager"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Xposed 框架残留: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}
