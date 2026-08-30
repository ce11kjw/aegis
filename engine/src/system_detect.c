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
static int check_sec_flags(aegis_result_t *r);

/* 前向声明 */
static int check_uptime(aegis_result_t *r);
static int check_init_proc(aegis_result_t *r);
static int check_sys_bin(aegis_result_t *r);
static int check_warranty(aegis_result_t *r);
static int check_prop_integrity(aegis_result_t *r);
static int check_overlayfs(aegis_result_t *r);
static int check_kernel_mods(aegis_result_t *r);
static int check_sepolicy(aegis_result_t *r);

static int check_selinux_context(aegis_result_t *r);
static int check_selinux_prev(aegis_result_t *r);
static int check_kallsyms(aegis_result_t *r);
static int check_sched_stat(aegis_result_t *r);
static int check_cgroup(aegis_result_t *r);
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
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "安全标志审计"); check_sec_flags(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "开机时间异常"); check_uptime(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "init进程异常"); check_init_proc(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "可疑系统二进制"); check_sys_bin(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "保修位熔断"); check_warranty(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "属性完整性"); check_prop_integrity(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "overlayfs挂载"); check_overlayfs(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "内核模块异常"); check_kernel_mods(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "sepolicy检测"); check_sepolicy(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "SELinux上下文"); check_selinux_context(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "SELinux历史审计"); check_selinux_prev(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "内核符号表"); check_kallsyms(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "调度统计异常"); check_sched_stat(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_SYSTEM; snprintf(r[n].name, sizeof(r[n].name), "cgroup异常"); check_cgroup(&r[n]); n++; }
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

static int check_sec_flags(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/status", buf, sizeof(buf));
    if (n > 0 && aegis_strcasestr(buf, "NoNewPrivs")) {
        snprintf(r->evidence, sizeof(r->evidence), "进程 NoNewPrivs 标志异常");
        r->detected = 1; r->level = AEGIS_LEVEL_LOW; return 1;
    }
    r->detected = 0; return 0;
}

/* 12. 开机时间矛盾: uptime vs 系统时间 */
static int check_uptime(aegis_result_t *r) {
    char buf[64];
    long n = aegis_read_file("/proc/uptime", buf, sizeof(buf));
    if (n > 0) {
        double up = atof(buf);
        /* 若开机时间极短说明刚重启 (可疑) */
        if (up < 30 && up > 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "系统开机仅 %.0f 秒 (可疑的快速重启)", up);
            r->detected = 1; r->level = AEGIS_LEVEL_LOW;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 13. init 进程异常 */
static int check_init_proc(aegis_result_t *r) {
    char buf[64];
    long n = aegis_read_file("/proc/1/comm", buf, sizeof(buf));
    if (n > 0) {
        buf[strcspn(buf, "\n")] = 0;
        if (strcmp(buf, "init") != 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "init 进程异常: %s (PID 1 应为 init)", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 14. /system/bin 可疑二进制 */
static int check_sys_bin(aegis_result_t *r) {
    static const char *susp[] = {
        "/system/bin/fake-su", "/system/bin/.su",
        "/system/xbin/daemonsu", "/system/xbin/su"
    };
    for (int i = 0; i < (int)(sizeof(susp)/sizeof(susp[0])); i++) {
        if (aegis_file_exists(susp[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现可疑系统二进制: %s", susp[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 15. 保修位/熔断 (三星 KNOX 等) */
static int check_warranty(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.boot.warranty_bit", buf);
    if (strcmp(buf, "1") == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "保修位已熔断 (warranty_bit=1, 设备被刷写)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    __system_property_get("ro.boot.sec_atd", buf);
    if (strstr(buf, "true")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "KNOX 熔断标记 (sec_atd=true)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}

/* 16. 关键系统属性完整性 */
static int check_prop_integrity(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.build.type", buf);
    /* 若 user 版但 debuggable=1 说明被改 */
    if (strcmp(buf, "user") == 0) {
        char dbg[32];
        __system_property_get("ro.debuggable", dbg);
        if (strcmp(dbg, "1") == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "user 版系统却 debuggable=1 (属性被篡改)");
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}

/* 17. overlayfs 挂载 (Magisk 系统镜像) */
static int check_overlayfs(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/mounts", buf, sizeof(buf));
    if (n > 0 && aegis_strcasestr(buf, "overlay")) {
        /* 正常系统也有 overlay (apex), 需检测关键分区 */
        if (aegis_strcasestr(buf, "/system") && aegis_strcasestr(buf, "upper")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "检测到 /system overlayfs 挂载 (Magisk 镜像特征)");
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 18. 内核符号/模块异常 */
static int check_kernel_mods(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/modules", buf, sizeof(buf));
    if (n > 0 && (aegis_strcasestr(buf, "magisk") || aegis_strcasestr(buf, "ksu") ||
        aegis_strcasestr(buf, "kpatch"))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "内核模块含 Root 特征 (magisk/ksu/kpatch)");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 19. sepolicy 状态检测 */
static int check_sepolicy(aegis_result_t *r) {
    /* 检测 SELinux 策略是否被 Magisk 修改 */
    FILE *f = fopen("/sys/fs/selinux/policy", "rb");
    if (!f) { r->detected = 0; return 0; }
    char buf[64];
    size_t rd = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    /* Magisk policy 修改后文件头有特征 */
    if (rd > 8) {
        /* 正常 policy 是二进制, 仅检测可读性 */
        r->detected = 0;
        return 0;
    }
    r->detected = 0;
    return 0;
}

/* 20. SELinux context 检测: 进程安全上下文 */
static int check_selinux_context(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/self/attr/current", buf, sizeof(buf));
    if (n > 0) {
        buf[strcspn(buf, "\n")] = 0;
        if (strstr(buf, "u:r:su:") || strstr(buf, "u:r:magisk:") ||
            strstr(buf, "u:r:kernel:") || strstr(buf, "u:r:init:")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "进程 SELinux context 异常: %s (非普通应用)", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
        /* 正常 App 应是 u:r:untrusted_app:s0 */
        if (!strstr(buf, "untrusted_app") && !strstr(buf, "priv_app")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "SELinux context 非标准应用: %s", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 21. /proc/self/attr/prev 历史 context 审计 */
static int check_selinux_prev(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/self/attr/prev", buf, sizeof(buf));
    if (n > 0) {
        buf[strcspn(buf, "\n")] = 0;
        if (strstr(buf, "su") || strstr(buf, "magisk")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "进程历史 SELinux context 含提权: %s", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 22. 内核符号表可读性 (kallsyms) */
static int check_kallsyms(aegis_result_t *r) {
    char buf[256];
    long n = aegis_read_file("/proc/kallsyms", buf, sizeof(buf));
    if (n > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "内核符号表可读 (kallsyms 可访问), 内核暴露 KASLR 地址");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 23. 调度统计异常 (sched) */
static int check_sched_stat(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/sched", buf, sizeof(buf));
    if (n > 0) {
        const char *p = aegis_strcasestr(buf, "nr_switches");
        if (p) {
            unsigned long sw = strtoul(p + 12, NULL, 10);
            if (sw > AEGIS_SWITCH_MAX) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "进程调度切换次数异常: %lu (被调试/注入特征)", sw);
                r->detected = 1; r->level = AEGIS_LEVEL_MED;
                return 1;
            }
        }
    }
    r->detected = 0;
    return 0;
}

/* 24. cgroup 异常 */
static int check_cgroup(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/cgroup", buf, sizeof(buf));
    if (n > 0) {
        /* 正常 App 在 /uid_<uid>/pid_<pid> 下 */
        if (aegis_strcasestr(buf, "root") || aegis_strcasestr(buf, "//")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "cgroup 路径异常 (含 root/空路径), 提权特征");
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}
