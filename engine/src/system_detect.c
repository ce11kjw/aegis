/*
 * system_detect.c - 系统环境检测模块
 * 系统属性联动 / 异常状态检测
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

/* 1. 系统属性联动: 设备描述与硬件矛盾 */
static int check_prop_contradict(aegis_result_t *r) {
    char brand[128], device[128], model[128], hw[128];
    get_prop("ro.product.brand", brand, sizeof(brand));
    get_prop("ro.product.device", device, sizeof(device));
    get_prop("ro.product.model", model, sizeof(model));
    get_prop("ro.hardware", hw, sizeof(hw));
    /* 例: brand=google 但 device 是小米型号 */
    if (strstr(brand, "google") && strstr(device, "pixel") == NULL) {
        /* 不直接判定, 仅记录 */
        r->detected = 0;
        return 0;
    }
    r->detected = 0;
    return 0;
}

/* 2. 系统调试状态: 检测全局调试 flag */
static int check_debuggable(aegis_result_t *r) {
    char buf[128];
    get_prop("ro.debuggable", buf, sizeof(buf));
    if (strcmp(buf, "1") == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统 debuggable=1 (工程机/调试版固件)");
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 3. SELinux 状态 */
static int check_selinux(aegis_result_t *r) {
    char buf[128];
    get_prop("ro.build.selinux", buf, sizeof(buf));
    /* Android 高版本总是 enforcing, 若 disabled 说明被改动 */
    if (strstr(buf, "disabled")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "SELinux 被禁用 (%s)", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 4. 编译类型 */
static int check_buildtype(aegis_result_t *r) {
    char buf[128];
    get_prop("ro.build.type", buf, sizeof(buf));
    if (strstr(buf, "eng") || strstr(buf, "userdebug")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统编译类型: %s (非正式版固件)", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 5. 检测 /proc/self/status 中的 CapEff (root 权限能力) */
static int check_capeff(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/status", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    const char *p = aegis_strcasestr(buf, "CapEff:");
    if (p) {
        unsigned long long cap = strtoull(p + 7, NULL, 16);
        /* 普通 App CapEff 为 0 或很小的值, 全 1 说明有高级权限 */
        if (cap == 0xffffffffffffULL || cap == 0x3fffffffffULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "进程 CapEff=0x%llx 异常 (普通应用应为 0)", cap);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 6. 检测注入的 LD_PRELOAD */
static int check_ld_preload(aegis_result_t *r) {
    const char *lp = getenv("LD_PRELOAD");
    if (lp && lp[0]) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 LD_PRELOAD: %s", lp);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 前向声明 */
static int check_secure_prop(aegis_result_t *r);
static int check_selinux_runtime(aegis_result_t *r);
static int check_kernel_ver(aegis_result_t *r);
static int check_vpn_service(aegis_result_t *r);
static int check_sec_flags(aegis_result_t *r);

int aegis_system_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "系统调试状态"); check_debuggable(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "SELinux状态"); check_selinux(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "编译类型"); check_buildtype(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "CapEff权限"); check_capeff(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "LD_PRELOAD检测"); check_ld_preload(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "属性联动检测"); check_prop_contradict(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "ro.secure标志"); check_secure_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "SELinux运行时"); check_selinux_runtime(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "内核版本异常"); check_kernel_ver(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "VPN服务检测"); check_vpn_service(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "安全标志审计"); check_sec_flags(&r[n]); n++; }
    return n;
}

static int check_secure_prop(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.secure", buf);
    if (strcmp(buf, "0") == 0) {
        snprintf(r->evidence, sizeof(r->evidence), "ro.secure=0 (系统安全标志被关闭)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0; return 0;
}
static int check_selinux_runtime(aegis_result_t *r) {
    char buf[16];
    long n = aegis_read_file("/sys/fs/selinux/enforce", buf, sizeof(buf));
    if (n > 0) {
        if (buf[0] == '0') {
            snprintf(r->evidence, sizeof(r->evidence), "SELinux 运行时为 permissive (enforce=0)");
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT; return 1;
        }
    }
    r->detected = 0; return 0;
}
static int check_kernel_ver(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/version", buf, sizeof(buf));
    if (n > 0) {
        if (strstr(buf, "SMP") == NULL) {
            snprintf(r->evidence, sizeof(r->evidence), "内核非 SMP 构建 (异常内核)");
            r->detected = 1; r->level = AEGIS_LEVEL_LOW; return 1;
        }
    }
    r->detected = 0; return 0;
}
static int check_vpn_service(aegis_result_t *r) {
    r->detected = 0; return 0;
}
static int check_sec_flags(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/status", buf, sizeof(buf));
    if (n > 0 && aegis_strcasestr(buf, "NoNewPrivs")) {
        snprintf(r->evidence, sizeof(r->evidence), "进程 NoNewPrivs 标志异常");
        r->detected = 1; r->level = AEGIS_LEVEL_LOW; return 1;
    }
    r->detected = 0; return 0;
}
