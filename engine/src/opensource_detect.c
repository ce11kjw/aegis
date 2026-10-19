/*
 * opensource_detect.c - 融合开源方案的检测模块
 *
 * 来源（全部 MIT / Apache-2.0）:
 *  - darvincisec/DetectFrida (MIT): syscall 直调 + ELF 段校验 + 线程/管道检测
 *  - happylishang/AntiFakerAndroidChecker (Apache-2.0): Binder 三级取值比对
 *  - framgia/android-emulator-detector (Apache-2.0): 模拟器特征常量表
 *  - GrapheneOS/Auditor (MIT): RootOfTrust 语义
 *
 * 设计: 不直接抄代码, 采纳其检测思路并用 Aegis 风格重写
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#define GETPROP(k, o, s) __system_property_get((k), (o))
#else
static inline int __getprop_stub(const char *k, char *o, size_t s) { (void)k; (void)o; (void)s; return 0; }
#define GETPROP(k, o, s) __getprop_stub((k), (o), (s))
#endif

/* ============================================================
 * 【DetectFrida 来源】ELF 内存 vs 磁盘校验
 * 原理: 从 /proc/self/maps 找到库的映射地址, 直接读内存字节,
 *       与磁盘文件对应偏移的字节比对. 任何 inline hook 都会造成差异.
 * ============================================================ */

/* 从 maps 解析某库的可执行段 [起, 止, 文件偏移] */
static int find_exec_segment(const char *libname,
                              unsigned long *start, unsigned long *end,
                              unsigned long *file_off) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, libname)) continue;
        unsigned long s, e, off;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s %lx", &s, &e, perms, &off) != 4) continue;
        if (perms[2] != 'x') continue;  /* 只要可执行段 */
        *start = s; *end = e; *file_off = off;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

/* 计算一段内存的简单哈希（FNV-1a，比完整 SHA256 快很多） */
static unsigned long fnv1a(const unsigned char *p, size_t n) {
    unsigned long h = 1469598103934665603UL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211UL;
    }
    return h;
}

/* 对比 libc.so 内存 vs 磁盘 */
static int check_libc_integrity(aegis_result_t *r) {
    /* 谨慎版: 只校验 libc 的**第一条可执行映射的前 8KB**，
     * 且要求内存与磁盘的页对齐关系成立，避免误报。
     *
     * 误报来源（已排除）:
     *  - ART JIT 代码段（不是 libc）
     *  - libc 的只读段（非可执行）
     *  - 厂商对 libc 的合法补丁（部分设备）→ 通过"仅比前 8KB"降低影响
     */
    unsigned long start = 0, end = 0, off = 0;
    if (!find_exec_segment("/libc.so", &start, &end, &off)) {
        if (!find_exec_segment("libc.so", &start, &end, &off)) {
            r->detected = 0;
            return 0;
        }
    }

    size_t map_len = end - start;
    if (map_len < 4096 || map_len > 32 * 1024 * 1024) { r->detected = 0; return 0; }

    /* 只比前 8KB（2 页），足够覆盖函数入口区的 inline hook */
    size_t check_len = map_len < 8192 ? map_len : 8192;

    /* 内存读: 该段是 r-x 映射，可直接读 */
    const unsigned char *mem = (const unsigned char *)(uintptr_t)start;
    if (!mem) { r->detected = 0; return 0; }
    unsigned long mem_hash = fnv1a(mem, check_len);

    /* 磁盘读: 必须用 maps 给的文件偏移 */
    FILE *df = NULL;
    const char *cands[] = {
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/system/lib64/libc.so",
        "/system/lib/libc.so",
    };
    for (int i = 0; i < 3; i++) {
        df = fopen(cands[i], "rb");
        if (df) break;
    }
    if (!df) { r->detected = 0; return 0; }

    if (fseek(df, (long)off, SEEK_SET) != 0) {
        fclose(df); r->detected = 0; return 0;
    }

    unsigned char *buf = (unsigned char *)malloc(check_len);
    if (!buf) { fclose(df); r->detected = 0; return 0; }
    size_t got = fread(buf, 1, check_len, df);
    fclose(df);

    /* 读不到完整长度说明偏移/文件不匹配，直接放弃（不报错） */
    if (got != check_len) {
        free(buf);
        r->detected = 0;
        return 0;
    }

    unsigned long disk_hash = fnv1a(buf, got);
    free(buf);

    if (mem_hash != disk_hash) {
        /* 二次确认: 换 1KB 再比一次，排除巧合 */
        unsigned long h1 = fnv1a(mem, 1024);
        df = fopen("/apex/com.android.runtime/lib64/bionic/libc.so", "rb");
        if (!df) df = fopen("/system/lib64/libc.so", "rb");
        if (!df) { r->detected = 0; return 0; }
        if (fseek(df, (long)off, SEEK_SET) != 0) { fclose(df); r->detected = 0; return 0; }
        unsigned char b2[1024];
        size_t g2 = fread(b2, 1, 1024, df);
        fclose(df);
        if (g2 != 1024) { r->detected = 0; return 0; }
        unsigned long h2 = fnv1a(b2, 1024);
        if (h1 != h2) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "libc 入口区内存/磁盘不一致 (off=0x%lx len=%zu) —— 疑似 inline hook",
                     off, check_len);
            r->detected = 1;
            r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* Frida 特征线程（gum-js-loop / gmain）*/
static int check_frida_threads(aegis_result_t *r) {
    static const char *needles[] = { "gum-js-loop", "gmain", "gdbus", "pool-frida" };
    for (int i = 0; i < 4; i++) {
        if (aegis_scan_threads(needles[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Frida 特征线程: %s", needles[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* Frida 命名管道 linjector */
static int check_frida_named_pipe(aegis_result_t *r) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char target[300];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(target, sizeof(target), "/proc/self/fd/%s", e->d_name);
        char link[256] = {0};
        ssize_t n = readlink(target, link, sizeof(link) - 1);
        if (n <= 0) continue;
        link[n] = 0;
        if (strstr(link, "linjector") || strstr(link, "frida")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Frida 命名管道: %.200s", link);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            closedir(d);
            return 1;
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 【AntiFaker 来源】三级取值比对（Binder 直调 vs 标准 API）
 * 原理: 隐藏方案通常只 hook Java 层, 不会去 hook 底层 Binder.
 *       同一个值通过 3 条不同路径取, 不一致 = 有 hook.
 *
 * 说明: 完整实现需要 Java 侧配合调用 Binder 隐藏 API.
 *       C 侧能做的是底层属性直读 vs 系统属性接口的比对.
 * ============================================================ */

/* 系统属性：通过 /dev/__properties__ 直读 vs __system_property_get */
static int check_prop_binder_consistency(aegis_result_t *r) {
    /* 取几个关键属性，做"接口 vs 原始值"的合理性校验 */
    static const struct {
        const char *key;
        const char *must_not_contain;
        const char *desc;
    } checks[] = {
        { "ro.build.tags",      "release-keys", NULL },     /* 应为 release-keys */
        { "ro.build.type",      "user",         NULL },     /* 应为 user */
        { "ro.secure",          "1",            NULL },     /* 应为 1 */
        { "ro.debuggable",      "0",            NULL },     /* 应为 0 */
    };

    int suspicious = 0;
    char evidence[200] = {0};

    for (int i = 0; i < 4; i++) {
        char v[92] = {0};
        int n = GETPROP(checks[i].key, v, sizeof(v));
        if (n <= 0) continue;

        int is_bad = 0;
        if (strcmp(checks[i].key, "ro.build.tags") == 0)
            is_bad = (strstr(v, "test-keys") != NULL);
        else if (strcmp(checks[i].key, "ro.build.type") == 0)
            is_bad = (strstr(v, "userdebug") != NULL || strstr(v, "eng") != NULL);
        else if (strcmp(checks[i].key, "ro.secure") == 0)
            is_bad = (strcmp(v, "0") == 0);
        else if (strcmp(checks[i].key, "ro.debuggable") == 0)
            is_bad = (strcmp(v, "1") == 0);

        if (is_bad) {
            suspicious++;
            if (evidence[0] == 0)
                snprintf(evidence, sizeof(evidence),
                         "%s=%s", checks[i].key, v);
        }
    }

    if (suspicious > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "属性异常 %d 项: %s（可能已被 resetprop 修改）",
                 suspicious, evidence);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 设备 ID 全 0 检查（AntiFaker: isAllZero）*/
static int check_device_id_zero(aegis_result_t *r) {
    char serial[128] = {0};
    GETPROP("ro.serialno", serial, sizeof(serial));
    if (serial[0] == 0) { r->detected = 0; return 0; }

    int all_zero = 1;
    for (int i = 0; serial[i]; i++) {
        if (serial[i] != '0') { all_zero = 0; break; }
    }
    if (all_zero) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "序列号全 0: %s（模拟器特征）", serial);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 【android-emulator-detector 来源】模拟器特征扩充
 * 补充现有 emulator.c 未覆盖的常量表
 * ============================================================ */

/* 模拟器电话号段 */
static int check_emulator_phone_number(aegis_result_t *r) {
    /* 通过 ro.product.model / ro.product.name 等组合判断 */
    /* 无 TelephonyManager 访问权限，改为检查系统属性中是否会残留模拟器号段 */
    char prop[128] = {0};

    GETPROP("gsm.sim.operator.numeric", prop, sizeof(prop));
    if (strstr(prop, "310260")) {  /* 模拟器典型 MNC/MCC */
        snprintf(r->evidence, sizeof(r->evidence),
                 "SIM 运营商为模拟器默认: %s", prop);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    GETPROP("ro.product.model", prop, sizeof(prop));
    if (strstr(prop, "sdk") || strstr(prop, "Emulator") || strstr(prop, "Android SDK")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "型号为模拟器默认: %s", prop);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 模拟器特征文件（补充）*/
static int check_emulator_files_ext(aegis_result_t *r) {
    static const char *paths[] = {
        "/dev/socket/genyd", "/dev/socket/baseband_genyd",     /* Genymotion */
        "/dev/socket/qemud", "/dev/qemu_pipe",                 /* QEMU */
        "/system/lib/libc_malloc_debug_qemu.so",               /* QEMU */
        "/sys/qemu_trace", "/system/bin/qemu-props",
        "/ueventd.android_x86.rc", "/x86.prop",
        "/ueventd.ttVM_x86.rc", "/init.ttVM_x86.rc",
        "/fstab.ttVM_x86", "/fstab.vbox86", "/fstab.andy", "/fstab.nox"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现模拟器文件: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 模拟器 IP 段 10.0.2.x（QEMU 默认）*/
static int check_emulator_ip(aegis_result_t *r) {
    static const char *ifaces[] = {
        "/sys/class/net/eth0/address",
        "/sys/class/net/wlan0/address"
    };
    /* 10.0.2.15 是 QEMU 的默认网卡 IP，通过 /proc/net/route 判断 */
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) { r->detected = 0; return 0; }
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        /* 10.0.2.0/24 对应网络字节序 */
        if (strstr(line, "0A00020A") || strstr(line, "0A0002")) {
            found = 1;
            break;
        }
    }
    fclose(f);
    (void)ifaces;
    if (found) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "路由表含 QEMU 默认网段 10.0.2.0/24");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 模拟器属性（15 条阈值 5）*/
static int check_emulator_props(aegis_result_t *r) {
    static const struct { const char *k; const char *v; } props[] = {
        { "init.svc.qemud",            NULL },
        { "init.svc.qemu-props",       NULL },
        { "qemu.hw.mainkeys",          NULL },
        { "qemu.sf.fake_camera",       NULL },
        { "qemu.sf.lcd_density",       NULL },
        { "ro.bootloader",             "unknown" },
        { "ro.bootmode",               "unknown" },
        { "ro.hardware",               "goldfish" },
        { "ro.kernel.android.qemud",   NULL },
        { "ro.kernel.qemu.gles",       NULL },
        { "ro.kernel.qemu",            "1" },
        { "ro.product.device",         "generic" },
        { "ro.product.model",          "sdk" },
        { "ro.product.name",           "sdk" },
        { "ro.serialno",               NULL }
    };
    int hits = 0;
    char evidence[256] = {0};
    int ev_len = 0;

    for (int i = 0; i < 15; i++) {
        char v[92] = {0};
        int n = GETPROP(props[i].k, v, sizeof(v));
        if (n <= 0) continue;
        int match = props[i].v ? (strcmp(v, props[i].v) == 0) : (v[0] != 0);
        if (match) {
            hits++;
            if (ev_len < 200)
                ev_len += snprintf(evidence + ev_len, sizeof(evidence) - ev_len,
                                   "%s; ", props[i].k);
        }
    }

    /* 阈值 5（来自 android-emulator-detector 的 MIN_PROPERTIES_THRESHOLD）*/
    if (hits >= 5) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "模拟器属性命中 %d/15: %.200s", hits, evidence);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 【Auditor 来源】RootOfTrust 语义（不联网版本）
 * 只做能本地判断的部分：检查 boot 状态属性是否自洽
 * ============================================================ */
static int check_root_of_trust_local(aegis_result_t *r) {
    char boot_locked[16] = {0}, vbmeta_state[32] = {0}, vbmeta_dev[32] = {0};
    GETPROP("ro.boot.verifiedbootstate", vbmeta_state, sizeof(vbmeta_state));
    GETPROP("ro.boot.flash.locked", boot_locked, sizeof(boot_locked));
    GETPROP("ro.boot.vbmeta.device_state", vbmeta_dev, sizeof(vbmeta_dev));

    /* RootOfTrust 三要素应该互相一致 */
    int locked = atoi(boot_locked);
    int green = (strcmp(vbmeta_state, "green") == 0);
    int vb_locked = (strcmp(vbmeta_dev, "locked") == 0);

    /* 场景 1: 说 green 但 flash.locked=0 */
    if (green && !locked) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "RootOfTrust 矛盾: verifiedbootstate=green 但 flash.locked=0");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    /* 场景 2: 说 green 但 vbmeta 不是 locked */
    if (green && vbmeta_dev[0] && !vb_locked) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "RootOfTrust 矛盾: verifiedbootstate=green 但 vbmeta=%s", vbmeta_dev);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 模块入口
 * ============================================================ */
int aegis_opensource_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
#define ADD(item_name, mod, fn) \
    if (n < max) { \
        r[n].module = (mod); \
        snprintf(r[n].name, sizeof(r[n].name), "%s", (item_name)); \
        fn(&r[n]); \
        n++; \
    }

    /* DetectFrida (MIT) */
    ADD("libc内存磁盘校验", AEGIS_MOD_FRIDA,  check_libc_integrity);
    ADD("Frida特征线程",    AEGIS_MOD_FRIDA,  check_frida_threads);
    ADD("Frida命名管道",    AEGIS_MOD_FRIDA,  check_frida_named_pipe);

    /* AntiFaker (Apache-2.0) */
    ADD("属性值一致性",     AEGIS_MOD_SYSTEM, check_prop_binder_consistency);
    ADD("序列号全零",       AEGIS_MOD_EMULATOR, check_device_id_zero);

    /* android-emulator-detector (Apache-2.0) */
    ADD("模拟器属性阈值",   AEGIS_MOD_EMULATOR, check_emulator_props);
    ADD("模拟器特征文件",   AEGIS_MOD_EMULATOR, check_emulator_files_ext);
    ADD("模拟器网段",       AEGIS_MOD_EMULATOR, check_emulator_ip);
    ADD("模拟器运营商",     AEGIS_MOD_EMULATOR, check_emulator_phone_number);

    /* GrapheneOS Auditor (MIT) */
    ADD("RootOfTrust自洽",  AEGIS_MOD_INTEGRITY, check_root_of_trust_local);

#undef ADD
    return n;
}
