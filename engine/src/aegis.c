/*
 * aegis.c - Aegis 安全检测引擎核心实现
 * 工具函数 + 评分 + 模块调度
 */
#include "aegis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

/* ====== 工具函数 ====== */

long aegis_read_file(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return n;
}

const char *aegis_strcasestr(const char *h, const char *n) {
    if (!h || !n) return NULL;
    size_t hn = strlen(n);
    for (; *h; h++) {
        if (strncasecmp(h, n, hn) == 0)
            return h;
    }
    return NULL;
}

int aegis_scan_maps(const char *needle) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    while (fgets(buf, sizeof(buf), f)) {
        if (aegis_strcasestr(buf, needle))
            { fclose(f); return 1; }
    }
    fclose(f);
    return 0;
}

int aegis_scan_threads(const char *needle) {
    char path[256], buf[64];
    DIR *d = opendir("/proc/self/task");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(buf, sizeof(buf), f) && aegis_strcasestr(buf, needle))
            { fclose(f); closedir(d); return 1; }
        fclose(f);
    }
    closedir(d);
    return 0;
}

int aegis_file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

/* ====== 调度与评分 ====== */

void aegis_init(void) {
    /* 预留: 反调试主动对抗初始化 */
}

aegis_config_t aegis_default_config(void) {
    aegis_config_t c;
    memset(&c, 0, sizeof(c));
    c.enable_debug = 1;
    c.enable_frida = 1;
    c.enable_xposed = 1;
    c.enable_integrity = 1;
    c.enable_emulator = 1;
    c.enable_root = 1;
    c.enable_system = 1;
    c.verbose = 1;
    return c;
}

const char *aegis_module_name(aegis_module_t mod) {
    switch (mod) {
        case AEGIS_MOD_DEBUG:     return "反调试";
        case AEGIS_MOD_FRIDA:     return "Frida注入";
        case AEGIS_MOD_XPOSED:    return "Xposed/Zygisk";
        case AEGIS_MOD_INTEGRITY: return "完整性";
        case AEGIS_MOD_EMULATOR:  return "模拟器";
        case AEGIS_MOD_ROOT:      return "Root";
        case AEGIS_MOD_SYSTEM:    return "系统环境";
        default:                  return "未知";
    }
}

const char *aegis_level_str(aegis_level_t level) {
    switch (level) {
        case AEGIS_LEVEL_INFO: return "信息";
        case AEGIS_LEVEL_LOW:  return "低";
        case AEGIS_LEVEL_MED:  return "中";
        case AEGIS_LEVEL_HIGH: return "高";
        case AEGIS_LEVEL_CRIT: return "严重";
        default:               return "未知";
    }
}

int aegis_score(const aegis_result_t *results, int count) {
    static const int w[] = { 0, 10, 25, 50, 80 };
    int score = 0;
    for (int i = 0; i < count; i++)
        if (results[i].detected)
            score += w[results[i].level];
    return score > 100 ? 100 : score;
}

/* 各模块实现声明 */
int aegis_debug_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_frida_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_xposed_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_integrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_emulator_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_root_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_system_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);

int aegis_run_module(const aegis_config_t *cfg, aegis_module_t mod,
                     aegis_result_t *results, int max_results) {
    if (!cfg || !results || max_results <= 0) return 0;
    switch (mod) {
        case AEGIS_MOD_DEBUG:     return aegis_debug_detect(cfg, results, max_results);
        case AEGIS_MOD_FRIDA:     return aegis_frida_detect(cfg, results, max_results);
        case AEGIS_MOD_XPOSED:    return aegis_xposed_detect(cfg, results, max_results);
        case AEGIS_MOD_INTEGRITY: return aegis_integrity_detect(cfg, results, max_results);
        case AEGIS_MOD_EMULATOR:  return aegis_emulator_detect(cfg, results, max_results);
        case AEGIS_MOD_ROOT:      return aegis_root_detect(cfg, results, max_results);
        case AEGIS_MOD_SYSTEM:    return aegis_system_detect(cfg, results, max_results);
        default: return 0;
    }
}

int aegis_run_all(const aegis_config_t *cfg,
                  aegis_result_t *results, int max_results) {
    if (!cfg || !results || max_results <= 0) return 0;
    int total = 0;
    for (int m = 0; m < AEGIS_MOD_COUNT; m++) {
        int n = aegis_run_module(cfg, (aegis_module_t)m,
                                 results + total, max_results - total);
        total += n;
    }
    return total;
}
