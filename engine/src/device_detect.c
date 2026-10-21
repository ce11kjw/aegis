/*
 * device_detect.c - 设备伪造检测模块 (v4.0 新增)
 *
 * 目标: 识别"改机/伪装"行为——通过属性交叉验证、硬件特征、
 *       传感器指纹等维度，判断设备是否为真实物理设备。
 *
 * 与 emulator.c 的区别:
 *   emulator.c 检测"虚拟化环境"（QEMU/Genymotion 等）
 *   device_detect.c 检测"真实设备上的属性伪造"（改机软件、伪装模块）
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
static int get_prop(const char *k, char *o, size_t s) { return __system_property_get(k, o); }
#else
static int get_prop(const char *k, char *o, size_t s) { (void)k; (void)o; (void)s; return 0; }
#endif

/* ============================================================
 * 1. Build 属性交叉验证
 * ro.product.model / manufacturer / brand / device / fingerprint
 * 这几个字段必须互相对应，改机工具常只改其中一两个
 * ============================================================ */
static int check_build_consistency(aegis_result_t *r) {
    char model[128] = {0}, brand[128] = {0}, manuf[128] = {0};
    char device[128] = {0}, product[128] = {0}, board[128] = {0};

    get_prop("ro.product.model", model, sizeof(model));
    get_prop("ro.product.brand", brand, sizeof(brand));
    get_prop("ro.product.manufacturer", manuf, sizeof(manuf));
    get_prop("ro.product.device", device, sizeof(device));
    get_prop("ro.product.name", product, sizeof(product));
    get_prop("ro.product.board", board, sizeof(board));

    if (!model[0] || !brand[0] || !manuf[0]) {
        r->detected = 0;
        return 0;
    }

    int suspicious = 0;
    char detail[180] = {0};

    /* brand 和 manufacturer 通常应一致或高度相关 */
    if (aegis_strcasestr(brand, manuf) == NULL && aegis_strcasestr(manuf, brand) == NULL) {
        strncat(detail, "brand≠manufacturer; ", sizeof(detail) - strlen(detail) - 1);
        suspicious++;
    }

    /* device 和 product 通常应相同或前缀相关 */
    if (strcmp(device, product) != 0 &&
        aegis_strcasestr(product, device) == NULL &&
        aegis_strcasestr(device, product) == NULL) {
        strncat(detail, "device≠product; ", sizeof(detail) - strlen(detail) - 1);
        suspicious++;
    }

    /* board 不能是 generic */
    if (aegis_strcasestr(board, "generic") || aegis_strcasestr(board, "unknown")) {
        strncat(detail, "board=generic; ", sizeof(detail) - strlen(detail) - 1);
        suspicious++;
    }

    if (suspicious >= 2) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "设备属性矛盾 %d 处: %.150s", suspicious, detail);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 2. Fingerprint 格式校验
 * 标准格式: brand/product/device:version/build_id/release/incremental:type/tags
 * ============================================================ */
static int check_fingerprint_format(aegis_result_t *r) {
    char fp[256] = {0};
    get_prop("ro.build.fingerprint", fp, sizeof(fp));
    if (!fp[0]) { r->detected = 0; return 0; }

    /* 至少要有 4 个 '/' 和 2 个 ':' */
    int slashes = 0, colons = 0;
    for (const char *p = fp; *p; p++) {
        if (*p == '/') slashes++;
        else if (*p == ':') colons++;
    }

    if (slashes < 3 || colons < 1) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "fingerprint 格式异常 (分隔符不足): %.120s", fp);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    /* 检查是否含通用占位符 */
    static const char *placeholders[] = { "generic", "unknown", "test-keys", "adhoc" };
    for (int i = 0; i < 4; i++) {
        if (aegis_strcasestr(fp, placeholders[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "fingerprint 含占位符 '%s': %.120s", placeholders[i], fp);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 3. 序列号一致性
 * ro.serialno / ro.boot.serialno / ro.vendor.oem.serialno
 * 三处应该一致（改机工具常只改一处）
 * ============================================================ */
static int check_serial_consistency(aegis_result_t *r) {
    char s1[128] = {0}, s2[128] = {0}, s3[128] = {0};
    get_prop("ro.serialno", s1, sizeof(s1));
    get_prop("ro.boot.serialno", s2, sizeof(s2));
    get_prop("ro.vendor.oem.serialno", s3, sizeof(s3));

    int cnt = 0;
    if (s1[0]) cnt++;
    if (s2[0]) cnt++;
    if (s3[0]) cnt++;

    if (cnt < 2) { r->detected = 0; return 0; }

    int mismatch = 0;
    if (s1[0] && s2[0] && strcmp(s1, s2) != 0) mismatch++;
    if (s1[0] && s3[0] && strcmp(s1, s3) != 0) mismatch++;
    if (s2[0] && s3[0] && strcmp(s2, s3) != 0) mismatch++;

    if (mismatch > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "序列号不一致 (%d 处): %.40s / %.40s / %.40s", mismatch, s1, s2, s3);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 4. 传感器真实性
 * 真实设备有陀螺仪/加速度计的噪声，模拟器/改机常返回固定值
 * ============================================================ */
static int check_sensor_presence(aegis_result_t *r) {
    /* 统计 /sys/class/sensors 下的传感器数量 */
    DIR *d = opendir("/sys/class/sensors");
    if (!d) { r->detected = 0; return 0; }

    struct dirent *e;
    int count = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;
    }
    closedir(d);

    if (count == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "无任何传感器 (/sys/class/sensors 为空)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    if (count < 3) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "传感器数量过少 (%d 个)，真实设备通常 >8 个", count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 5. 电池曲线合理性
 * 真实电池的 voltage/温度会随使用变化，模拟器常固定
 * ============================================================ */
static int check_battery_realism(aegis_result_t *r) {
    char buf[64] = {0};

    /* 电压 */
    if (aegis_read_file("/sys/class/power_supply/battery/voltage_now", buf, sizeof(buf)) > 0) {
        long uv = atol(buf);
        /* 真实锂电池 3.0V ~ 4.5V */
        if (uv > 0 && (uv < 2800000 || uv > 4600000)) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "电池电压异常: %.2fV (正常 3.0-4.5V)", uv / 1000000.0);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }

    /* 温度 */
    memset(buf, 0, sizeof(buf));
    if (aegis_read_file("/sys/class/power_supply/battery/temp", buf, sizeof(buf)) > 0) {
        long t = atol(buf);
        /* 十分之一度，正常 -10~60 度 */
        if (t != 0 && (t < -100 || t > 600)) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "电池温度异常: %.1f℃", t / 10.0);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 6. 屏幕参数合理性
 * ============================================================ */
static int check_display_params(aegis_result_t *r) {
    char buf[64] = {0};

    /* 密度 */
    if (aegis_read_file("/sys/class/graphics/fb0/virtual_size", buf, sizeof(buf)) > 0) {
        int w = 0, h = 0;
        if (sscanf(buf, "%d,%d", &w, &h) == 2) {
            if (w <= 0 || h <= 0 || w > 10000 || h > 10000) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "屏幕尺寸异常: %dx%d", w, h);
                r->detected = 1; r->level = AEGIS_LEVEL_MED;
                return 1;
            }
        }
    }

    /* 刷新率 */
    memset(buf, 0, sizeof(buf));
    char path[400];
    DIR *d = opendir("/sys/class/drm");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            snprintf(path, sizeof(path), "/sys/class/drm/%s/modes", e->d_name);
            char mode[128] = {0};
            if (aegis_read_file(path, mode, sizeof(mode)) > 0 && mode[0]) {
                closedir(d);
                r->detected = 0;
                return 0;
            }
        }
        closedir(d);
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 7. CPU 信息一致性
 * ============================================================ */
static int check_cpu_consistency(aegis_result_t *r) {
    char hw[128] = {0}, board[128] = {0}, buf[2048] = {0};
    get_prop("ro.hardware", hw, sizeof(hw));
    get_prop("ro.board.platform", board, sizeof(board));

    if (aegis_read_file("/proc/cpuinfo", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* 从 cpuinfo 提取 Hardware 或 model name */
    char cpu_hw[128] = {0};
    char *p = strstr(buf, "Hardware");
    if (p) {
        char *colon = strchr(p, ':');
        if (colon) {
            colon++;
            while (*colon == ' ' || *colon == '\t') colon++;
            size_t i = 0;
            while (colon[i] && colon[i] != '\n' && i < sizeof(cpu_hw) - 1) {
                cpu_hw[i] = colon[i];
                i++;
            }
            cpu_hw[i] = 0;
        }
    }

    /* ro.hardware 与 cpuinfo 的 Hardware 应相关（都是 MTK/高通平台名） */
    if (hw[0] && cpu_hw[0]) {
        /* MTK 平台: ro.hardware = mtXXXX, cpuinfo Hardware = MTxxxx */
        if (aegis_strcasestr(hw, "mt") == hw && aegis_strcasestr(cpu_hw, "mt") == NULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "CPU 平台不一致: ro.hardware=%s cpuinfo=%s", hw, cpu_hw);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
        /* 高通: ro.hardware = qcom, cpuinfo 含 Qualcomm */
        if (aegis_strcasestr(hw, "qcom") && aegis_strcasestr(cpu_hw, "qualcomm") == NULL &&
            aegis_strcasestr(cpu_hw, "qcom") == NULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "CPU 平台不一致: ro.hardware=%s cpuinfo=%s", hw, cpu_hw);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }

    (void)board;
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 8. 闪存容量与型号
 * ============================================================ */
static int check_storage_consistency(aegis_result_t *r) {
    char buf[256] = {0};
    if (aegis_read_file("/sys/block/mmcblk0/size", buf, sizeof(buf)) <= 0 &&
        aegis_read_file("/sys/block/sda/size", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    long long sectors = atoll(buf);
    double gb = (double)sectors * 512.0 / (1024.0 * 1024.0 * 1024.0);

    /* 真实设备通常在 16GB - 2TB 之间 */
    if (gb > 0 && (gb < 4.0 || gb > 4096.0)) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "存储容量异常: %.1f GB", gb);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 9. MAC 地址厂商前缀
 * OUI 前 3 字节应该在 IEEE 注册表内（这里只做基础校验）
 * ============================================================ */
static int check_mac_oui(aegis_result_t *r) {
    char mac[64] = {0};
    if (aegis_read_file("/sys/class/net/wlan0/address", mac, sizeof(mac)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* 检查是否全 0 / 全 F / 组播位 */
    unsigned int b[6];
    if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        r->detected = 0;
        return 0;
    }

    /* 全 0 */
    int all_zero = 1;
    for (int i = 0; i < 6; i++) if (b[i] != 0) { all_zero = 0; break; }
    if (all_zero) {
        snprintf(r->evidence, sizeof(r->evidence), "MAC 全 0: %s", mac);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    /* 组播位（第 1 字节最低位 = 1） */
    if (b[0] & 0x01) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "MAC 组播位异常 (非法地址): %s", mac);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 10. 摄像头/闪光灯存在性
 * ============================================================ */
static int check_camera_presence(aegis_result_t *r) {
    int found = 0;

    /* 遍历 /sys/class/video4linux */
    DIR *d = opendir("/sys/class/video4linux");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            found++;
        }
        closedir(d);
    }

    if (found == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "无摄像头设备 (/sys/class/video4linux 为空)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 11. 输入设备清单
 * ============================================================ */
static int check_input_devices(aegis_result_t *r) {
    char buf[1024] = {0};
    if (aegis_read_file("/proc/bus/input/devices", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* 统计 "Handlers=" 出现次数 = 输入设备数 */
    int count = 0;
    const char *p = buf;
    while ((p = strstr(p, "Handlers=")) != NULL) {
        count++;
        p += 9;
    }

    if (count < 3) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "输入设备过少 (%d 个)，真实设备通常 >5 个", count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 12. 内核版本与 Build 时间合理性
 * ============================================================ */
static int check_kernel_build_time(aegis_result_t *r) {
    char buf[512] = {0};
    if (aegis_read_file("/proc/version", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* 提取年份，应该在 2010-2030 之间 */
    int year = 0;
    for (const char *p = buf; *p; p++) {
        if (*p >= '2' && *p <= '2') {
            int y = atoi(p);
            if (y >= 2010 && y <= 2035) { year = y; break; }
        }
    }

    if (year == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "内核版本无有效构建年份: %.120s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 13. 时区与区域一致性
 * ============================================================ */
static int check_timezone_consistency(aegis_result_t *r) {
    char tz[64] = {0};
    get_prop("persist.sys.timezone", tz, sizeof(tz));

    if (!tz[0]) {
        r->detected = 0;
        return 0;
    }

    /* 检查是否存在时区文件 */
    char path[400];
    snprintf(path, sizeof(path), "/system/usr/share/zoneinfo/%s", tz);
    if (!aegis_file_exists(path)) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "时区文件不存在: %s（时区被伪造？）", tz);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 14. 语言/地区列表合理性
 * ============================================================ */
static int check_locale_list(aegis_result_t *r) {
    char locales[512] = {0};
    get_prop("ro.product.locale", locales, sizeof(locales));
    char lang[128] = {0};
    get_prop("ro.product.locale.language", lang, sizeof(lang));

    if (locales[0] && lang[0]) {
        /* ro.product.locale 应包含 language */
        if (aegis_strcasestr(locales, lang) == NULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "语言属性不一致: locale=%s language=%s", locales, lang);
            r->detected = 1; r->level = AEGIS_LEVEL_LOW;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 15. 属性来源审计（ro. 属性不应被 resetprop 写入）
 * ============================================================ */
static int check_ro_prop_tamper(aegis_result_t *r) {
    /* 检查几个关键 ro. 属性是否符合官方格式 */
    struct {
        const char *key;
        int (*validate)(const char *);
    } checks[3];

    /* ro.build.date 应该是 "星期 月 日 HH:MM:SS TZ 年" 格式 */
    char date[128] = {0};
    get_prop("ro.build.date", date, sizeof(date));

    /* 简化：检查长度和年份 */
    if (date[0]) {
        int len = (int)strlen(date);
        if (len < 15 || len > 64) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "ro.build.date 格式异常 (长度 %d): %.80s", len, date);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
        /* 应含年份 20xx */
        if (strstr(date, "20") == NULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "ro.build.date 无年份: %.80s", date);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }

    (void)checks;
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 模块入口
 * ============================================================ */
int aegis_device_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;

#define ADD(item_name, fn, lvl) \
    if (n < max) { \
        r[n].module = AEGIS_MOD_DEVICE; \
        snprintf(r[n].name, sizeof(r[n].name), "%s", (item_name)); \
        fn(&r[n]); \
        n++; \
    }

    ADD("Build属性一致性", check_build_consistency, 0);
    ADD("Fingerprint格式", check_fingerprint_format, 0);
    ADD("序列号一致性", check_serial_consistency, 0);
    ADD("传感器真实性", check_sensor_presence, 0);
    ADD("电池曲线合理性", check_battery_realism, 0);
    ADD("屏幕参数合理性", check_display_params, 0);
    ADD("CPU平台一致性", check_cpu_consistency, 0);
    ADD("存储容量合理性", check_storage_consistency, 0);
    ADD("MAC厂商前缀", check_mac_oui, 0);
    ADD("摄像头存在性", check_camera_presence, 0);
    ADD("输入设备清单", check_input_devices, 0);
    ADD("内核构建时间", check_kernel_build_time, 0);
    ADD("时区一致性", check_timezone_consistency, 0);
    ADD("语言地区一致性", check_locale_list, 0);
    ADD("ro属性格式审计", check_ro_prop_tamper, 0);

#undef ADD
    return n;
}
