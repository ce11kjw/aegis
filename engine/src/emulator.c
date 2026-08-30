/*
 * emulator.c - 模拟器检测模块
 * 原创思路: 硬件层特征 / CPU指令 / 传感器异常 / 设备属性联动
 */
#include "aegis.h"
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
    if (cores < 2) {  /* 真实手机几乎都 >= 2 核 */
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
        if (n > 0 && n < 3) {  /* 1-2 个传感器基本必是模拟器 */
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

int aegis_emulator_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "Build字段检测"); check_build(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "硬件平台检测"); check_hardware(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "属性联动检测"); check_cpu_prop(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "CPU核心数检测"); check_cpu_count(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "传感器数量检测"); check_sensors(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_EMULATOR; snprintf(r[n].name, sizeof(r[n].name), "运营商检测"); check_operator(&r[n]); n++; }
    return n;
}
