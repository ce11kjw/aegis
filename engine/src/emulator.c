/*
 * emulator.c - 模拟器检测模块
 * 原创思路: 硬件层特征 / CPU指令 / 传感器异常 / 设备属性联动
 */
#include "aegis.h"
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
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

/* 1. 经典 Build 字段检测 */
static int check_build(aegis_result_t *r) {
    char buf[256];
    /* 已知模拟器特征指纹 */
    get_prop("ro.product.model", buf, sizeof(buf));
    static const char *emu_models[] = {
        "sdk_gphone", "emulator", "Android SDK built for", "google_sdk",
        "Genymotion", "nox", "MuMu", "memu", "BlueStacks", "ldplayer",
        "vmos", "fmod"
    };
    for (int i = 0; i < (int)(sizeof(emu_models)/sizeof(emu_models[0])); i++) {
        if (aegis_strcasestr(buf, emu_models[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "设备型号疑似模拟器: %s", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 2. 硬件指纹: 模拟器常缺 ARM 特有特征 */
static int check_hardware(aegis_result_t *r) {
    char buf[256];
    get_prop("ro.hardware", buf, sizeof(buf));
    static const char *emu_hw[] = { "goldfish", "ranchu", "emulator" };
    for (int i = 0; i < (int)(sizeof(emu_hw)/sizeof(emu_hw[0])); i++) {
        if (aegis_strcasestr(buf, emu_hw[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "硬件平台疑似模拟器: ro.hardware=%s", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 3. 属性联动: 模拟器的 CPU/内核配置常有矛盾 */
static int check_cpu_prop(aegis_result_t *r) {
    char brand[128], hw[128], abi[128], board[128];
    get_prop("ro.product.brand", brand, sizeof(brand));
    get_prop("ro.hardware", hw, sizeof(hw));
    get_prop("ro.product.cpu.abi", abi, sizeof(abi));
    get_prop("ro.product.board", board, sizeof(board));
    /* 例: 某模拟器 brand=HUAWEI 但 hw=ranchu 或 abi 不匹配 */
    if ((strstr(brand, "HUAWEI") || strstr(brand, "Xiaomi") || strstr(brand, "samsung"))
        && (aegis_strcasestr(hw, "ranchu") || aegis_strcasestr(hw, "goldfish"))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "品牌与硬件矛盾: brand=%s hw=%s (疑似模拟器)", brand, hw);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 4. CPU 核心数与真实架构不符 */
static int check_cpu_count(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/cpuinfo", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    int cores = 0;
    const char *p = buf;
    while ((p = strstr(p, "processor"))) { cores++; p += 9; }
    if (cores < AEGIS_CPU_MIN) {  /* 真实手机几乎都 >= 2 核 */
        snprintf(r->evidence, sizeof(r->evidence),
                 "CPU 核心数异常: %d (真实手机通常 >=2)", cores);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 5. 传感器数量: 真实手机传感器很多, 模拟器几乎没有 */
static int check_sensors(aegis_result_t *r) {
    FILE *f = popen("ls /sys/class/sensors 2>/dev/null | wc -l", "r");
    if (!f) { r->detected = 0; return 0; }
    char buf[32];
    if (fgets(buf, sizeof(buf), f)) {
        int n = atoi(buf);
        if (n > 0 && n < AEGIS_SENSOR_MIN) {  /* 1-2 个传感器基本必是模拟器 */
            snprintf(r->evidence, sizeof(r->evidence),
                     "传感器数量异常: %d 个 (真实手机通常 5+ 个)", n);
            pclose(f);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    pclose(f);
    r->detected = 0;
    return 0;
}

/* 6. 运营商空值: 模拟器通常没有真实 SIM 运营商 */
static int check_operator(aegis_result_t *r) {
    char buf[128];
    get_prop("gsm.operator.alpha", buf, sizeof(buf));
    if (buf[0] == '\0') {
        snprintf(r->evidence, sizeof(r->evidence),
                 "运营商为空 (模拟器常见特征)");
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 前向声明 */
static int check_baseband(aegis_result_t *r);
static int check_gpu(aegis_result_t *r);
static int check_battery(aegis_result_t *r);
static int check_mem_size(aegis_result_t *r);
static int check_dev_nodes(aegis_result_t *r);
static int check_qemu_prop(aegis_result_t *r);
static int check_fingerprint(aegis_result_t *r);

/* 前向声明 */
static int check_cpu_hw(aegis_result_t *r);
static int check_input_dev(aegis_result_t *r);
static int check_bt_addr(aegis_result_t *r);
static int check_wlan_mac(aegis_result_t *r);
static int check_nfc(aegis_result_t *r);
static int check_gps(aegis_result_t *r);
static int check_batt_status(aegis_result_t *r);
static int check_serial(aegis_result_t *r);

int aegis_emulator_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "Build字段检测"); check_build(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "硬件平台检测"); check_hardware(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "属性联动检测"); check_cpu_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "CPU核心数检测"); check_cpu_count(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "传感器数量检测"); check_sensors(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "运营商检测"); check_operator(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "基带版本检测"); check_baseband(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "GPU渲染器检测"); check_gpu(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "电池属性检测"); check_battery(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "内存大小检测"); check_mem_size(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "设备节点检测"); check_dev_nodes(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "qemu内核标志"); check_qemu_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "Fingerprint指纹"); check_fingerprint(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "CPU型号异常"); check_cpu_hw(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "输入设备过少"); check_input_dev(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "蓝牙地址异常"); check_bt_addr(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "无线MAC异常"); check_wlan_mac(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "NFC缺失"); check_nfc(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "GPS硬件"); check_gps(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "电池异常"); check_batt_status(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "序列号异常"); check_serial(&r[n]); n++; }
    return n;
}


static int check_baseband(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("gsm.version.baseband", buf);
    if (buf[0] == '\0' || strstr(buf, "unknown")) {
        snprintf(r->evidence, sizeof(r->evidence), "基带版本为空 (真实手机必有基带)");
        r->detected = 1; r->level = AEGIS_LEVEL_MED; return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0; return 0;
}
static int check_gpu(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.hardware.egl", buf);
    if (strstr(buf, "swiftshader") || strstr(buf, "llvmpipe")) {
        snprintf(r->evidence, sizeof(r->evidence), "GPU 渲染器为软件模拟: %s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0; return 0;
}
static int check_battery(aegis_result_t *r) {
    char buf[64];
    long n = aegis_read_file("/sys/class/power_supply/battery/temp", buf, sizeof(buf));
    if (n > 0) {
        int t = atoi(buf);
        if (t < 100 || t > 600) {
            snprintf(r->evidence, sizeof(r->evidence), "电池温度异常: %d (正常 100-600)", t);
            r->detected = 1; r->level = AEGIS_LEVEL_MED; return 1;
        }
    }
    r->detected = 0; return 0;
}
static int check_mem_size(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/meminfo", buf, sizeof(buf));
    if (n > 0) {
        const char *p = aegis_strcasestr(buf, "MemTotal:");
        if (p) {
            long kb = atol(p + 9);
            if (kb > 0 && kb < 512 * 1024) {
                snprintf(r->evidence, sizeof(r->evidence), "内存异常小: %ldMB (真实手机 >=512MB)", kb/1024);
                r->detected = 1; r->level = AEGIS_LEVEL_MED; return 1;
            }
        }
    }
    r->detected = 0; return 0;
}
static int check_dev_nodes(aegis_result_t *r) {
    if (aegis_file_exists("/dev/qemu_pipe") || aegis_file_exists("/dev/goldfish_pipe")) {
        snprintf(r->evidence, sizeof(r->evidence), "发现模拟器特征设备节点");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    r->detected = 0; return 0;
}
static int check_qemu_prop(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.kernel.qemu", buf);
    if (strcmp(buf, "1") == 0) {
        snprintf(r->evidence, sizeof(r->evidence), "ro.kernel.qemu=1 (模拟器内核标志)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0; return 0;
}
static int check_fingerprint(aegis_result_t *r) {
    char buf[256];
    #ifdef __ANDROID__
    __system_property_get("ro.build.fingerprint", buf);
    static const char *emu[] = { "generic", "sdk", "emulator", "vbox", "nox" };
    for (int i = 0; i < 5; i++) {
        if (aegis_strcasestr(buf, emu[i])) {
            snprintf(r->evidence, sizeof(r->evidence), "Build.FINGERPRINT 含模拟器关键词: %s", emu[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH; return 1;
        }
    }
    #else
    (void)buf;
    #endif
    r->detected = 0; return 0;
}

/* 15. CPU 型号异常: 模拟器 CPU 非 ARM 特征 */
static int check_cpu_hw(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/cpuinfo", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    /* 检测 CPU part/implementer (ARM 特征) */
    if (aegis_strcasestr(buf, "implementer") == NULL &&
        aegis_strcasestr(buf, "CPU implementer") == NULL) {
        /* x86 模拟器没有 ARM implementer */
        if (aegis_strcasestr(buf, "GenuineIntel") || aegis_strcasestr(buf, "AuthenticAMD")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "CPU 为 x86 (GenuineIntel/AMD), 非真实 ARM 设备");
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 16. 输入设备异常: 模拟器无真实触摸 */
static int check_input_dev(aegis_result_t *r) {
    DIR *d = opendir("/dev/input");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;
    }
    closedir(d);
    if (count < 2) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "输入设备过少: %d 个 (真实手机 >2, 含触摸屏)", count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 17. 蓝牙特征: 模拟器通常无蓝牙地址 */
static int check_bt_addr(aegis_result_t *r) {
    /* 检查蓝牙 MAC 是否存在 */
    FILE *f = fopen("/sys/class/bluetooth/hci0/address", "r");
    if (!f) { r->detected = 0; return 0; }
    char buf[32];
    if (fgets(buf, sizeof(buf), f)) {
        /* 模拟器蓝牙地址常为全 0 或异常 */
        if (strncmp(buf, "00:00:00", 8) == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "蓝牙地址异常: %s (模拟器特征)", buf);
            fclose(f);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* 18. 无线 MAC 特征 */
static int check_wlan_mac(aegis_result_t *r) {
    FILE *f = fopen("/sys/class/net/wlan0/address", "r");
    if (!f) { r->detected = 0; return 0; }
    char buf[32];
    if (fgets(buf, sizeof(buf), f)) {
        /* 模拟器 MAC 常为 02:00:00:00:00:00 等 */
        if (strncmp(buf, "02:00:00", 8) == 0 || strncmp(buf, "00:00:00", 8) == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "无线 MAC 异常: %s (模拟器特征)", buf);
            fclose(f);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* 19. NFC 传感器缺失 */
static int check_nfc(aegis_result_t *r) {
    if (!aegis_file_exists("/sys/class/nfc")) {
        /* 很多真机有 NFC, 但非绝对; 仅作为弱信号 */
        r->detected = 0;
        return 0;
    }
    r->detected = 0;
    return 0;
}

/* 20. GPS 硬件检测 */
static int check_gps(aegis_result_t *r) {
    /* GPS 设备节点 */
    static const char *gps_nodes[] = {
        "/dev/gps", "/sys/class/gps", "/dev/ttyGPS"
    };
    for (int i = 0; i < 3; i++) {
        if (aegis_file_exists(gps_nodes[i])) {
            r->detected = 0;
            return 0;
        }
    }
    r->detected = 0;
    return 0;
}

/* 21. 电池健康信息异常 */
static int check_batt_status(aegis_result_t *r) {
    char buf[64];
    /* 检测电池健康/技术字段 */
    long n = aegis_read_file("/sys/class/power_supply/battery/technology", buf, sizeof(buf));
    if (n > 0) {
        buf[strcspn(buf, "\n")] = 0;
        if (strstr(buf, "Unknown") || strstr(buf, "unknown")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "电池技术字段异常: %s (模拟器特征)", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 22. 串行号/硬件序列异常 */
static int check_serial(aegis_result_t *r) {
    char buf[128];
    #ifdef __ANDROID__
    __system_property_get("ro.serialno", buf);
    /* 模拟器序列号常为 emulator 或全 0 */
    if (strstr(buf, "emulator") || strncmp(buf, "0", 1) == 0 && strlen(buf) < 5) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "设备序列号异常: %s (模拟器特征)", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    #else
    (void)buf;
    #endif
    r->detected = 0;
    return 0;
}
