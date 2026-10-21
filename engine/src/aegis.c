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
    char path[300], buf[64];
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

/* ====== 公共进程扫描 ====== */
int aegis_scan_proc_name(const char **names, int count,
                         char *matched, size_t matched_sz, char *pid_buf, size_t pid_sz) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char pcomm[64], ppath[300];
        AEGIS_SNPRINTF(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        for (int i = 0; i < count; i++) {
            if (strcmp(pcomm, names[i]) == 0) {
                if (matched && matched_sz)
                    AEGIS_SNPRINTF(matched, matched_sz, "%s", names[i]);
                if (pid_buf && pid_sz)
                    AEGIS_SNPRINTF(pid_buf, pid_sz, "%s", e->d_name);
                closedir(d);
                return 1;
            }
        }
    }
    closedir(d);
    return 0;
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
    c.enable_network = 1;
    c.enable_device = 1;
    c.enable_appintegrity = 1;
    c.enable_runtime = 1;
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
        case AEGIS_MOD_NETWORK:   return "网络环境";
        case AEGIS_MOD_DEVICE:       return "设备伪造";
        case AEGIS_MOD_APPINTEGRITY: return "应用完整性";
        case AEGIS_MOD_RUNTIME:      return "运行时行为";
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

/**
 * 风险评分 (0-100，越高越危险)
 *
 * 设计原则: 不能用"所有项直接相加"—— 155+ 项里任何 2 项 CRIT 就必然爆表，
 *           导致所有 Root 设备永远显示 100 分，失去区分度。
 *
 * 采用加权递降:
 *   - 第 1 个命中项: 全额权重
 *   - 第 2 个: 权重 × 0.6
 *   - 第 3 个: 权重 × 0.4
 *   - 第 4 个起: 权重 × 0.2
 *   同等级项只计前 3 个，避免"100 个 LOW 项"堆到高分。
 */
/**
 * 风险评分 v2（方案 C：分级 + 关键项加权）
 *
 * v1 问题：CRIT 权重 70，2 项即封顶 100，所有 Root 设备一律满分，丧失区分度。
 *
 * v2 分四层叠加：
 *   L1 Root 框架基线：命中 Magisk/KSU/APatch 任一 => 60 分起
 *                      2 个框架 +12，3 个 +10
 *   L2 Root 证据数量：CRIT 每条 +3(上限20)、HIGH +2(上限10)、MED +1(上限5)
 *   L3 Hook 框架：Frida +10、Xposed +8、Zygisk +6、Shamiko/DenyList +5
 *   L4 其他模块：按命中比例折算，上限 +15（无 Root 时最高 45）
 *
 * 分数解读：
 *    0-9   环境安全    10-29 轻微异常    30-49 可疑
 *   50-69  存在风险    70-89 危险        90-100 严重
 */
int aegis_score(const aegis_result_t *results, int count) {
    if (!results || count <= 0) return 0;

    int root_crit = 0, root_high = 0, root_med = 0;
    int has_magisk = 0, has_ksu = 0, has_apatch = 0;
    int has_xposed = 0, has_frida = 0, has_zygisk = 0, has_hide = 0;
    int other_hits = 0, other_total = 0;
    int emu_hits = 0, emu_total = 0;

    for (int i = 0; i < count; i++) {
        const aegis_result_t *r = &results[i];
        const char *n = r->name;

        if (r->module == AEGIS_MOD_ROOT) {
            if (r->detected) {
                if (r->level >= AEGIS_LEVEL_CRIT)      root_crit++;
                else if (r->level >= AEGIS_LEVEL_HIGH) root_high++;
                else if (r->level >= AEGIS_LEVEL_MED)  root_med++;

                if (strstr(n, "Magisk") || strstr(n, "magisk"))  has_magisk = 1;
                if (strstr(n, "KernelSU") || strstr(n, "KSU") || strstr(n, "ksu")) has_ksu = 1;
                if (strstr(n, "APatch"))                          has_apatch = 1;
                if (strstr(n, "DenyList") || strstr(n, "隐藏挂载")) has_hide = 1;
            }
        } else if (r->module == AEGIS_MOD_XPOSED) {
            other_total++;
            if (r->detected) {
                other_hits++;
                if (strstr(n, "Shamiko") || strstr(n, "隐藏") || strstr(n, "DenyList"))
                    has_hide = 1;
                else if (strstr(n, "Zygisk"))
                    has_zygisk = 1;
                else
                    has_xposed = 1;
            }
        } else if (r->module == AEGIS_MOD_FRIDA) {
            other_total++;
            if (r->detected) { other_hits++; has_frida = 1; }
        } else if (r->module == AEGIS_MOD_EMULATOR) {
            other_total++; emu_total++;
            if (r->detected) { other_hits++; emu_hits++; }
        } else {
            other_total++;
            if (r->detected) other_hits++;
        }
    }

    /* L1: Root 框架基线 */
    int frameworks = has_magisk + has_ksu + has_apatch;
    int score = 0;
    if (frameworks >= 1) {
        score += 60;
        if (frameworks >= 2) score += 12;
        if (frameworks >= 3) score += 10;
    }

    /* L2: Root 证据数量 */
    {
        int a = root_crit * 3; if (a > 20) a = 20; score += a;
        int b = root_high * 2; if (b > 10) b = 10; score += b;
        int c = root_med  * 1; if (c >  5) c =  5; score += c;
    }

    /* L2.5: 模拟器本身即高危环境 */
    if (emu_hits >= 8)      { if (score < 90) score = 90; }
    else if (emu_hits >= 5) { if (score < 80) score = 80; }
    else if (emu_hits >= 3) { if (score < 70) score = 70; }
    else if (emu_hits >= 1) { score += 15; }

    /* L2.8: v4.0 新模块——设备伪造/应用篡改/运行时异常都是高危 */
    {
        int dev_hits = 0, app_hits = 0, rt_hits = 0;
        for (int i = 0; i < count; i++) {
            const aegis_result_t *x = &results[i];
            if (!x->detected) continue;
            if (x->module == AEGIS_MOD_DEVICE)            dev_hits++;
            else if (x->module == AEGIS_MOD_APPINTEGRITY) app_hits++;
            else if (x->module == AEGIS_MOD_RUNTIME)      rt_hits++;
        }
        /* 设备伪造 >=3 项 => 至少 65 分 */
        if (dev_hits >= 5)      { if (score < 80) score = 80; }
        else if (dev_hits >= 3) { if (score < 65) score = 65; }
        else if (dev_hits >= 1) { score += dev_hits * 8; }
        /* 应用被篡改 >=2 项 => 至少 70 分 */
        if (app_hits >= 2)      { if (score < 70) score = 70; }
        else if (app_hits >= 1) { score += 12; }
        /* 运行时异常 >=2 项 => 至少 55 分 */
        if (rt_hits >= 3)       { if (score < 65) score = 65; }
        else if (rt_hits >= 2)  { if (score < 55) score = 55; }
        else if (rt_hits >= 1)  { score += 10; }
    }

    /* L3: Hook / 注入框架 */
    if (has_frida)  score += 10;
    if (has_xposed) score += 8;
    if (has_zygisk) score += 6;
    if (has_hide)   score += 5;

    /* L4: 其他模块（按命中比例） */
    if (other_total > 0) {
        int pct = (other_hits * 100) / other_total;
        int add = (pct * 15) / 100;
        if (score == 0 && add > 45) add = 45;  /* 无 Root 时不进危险区 */
        score += add;
    }

    if (score > 100) score = 100;
    if (score < 0)   score = 0;
    return score;
}

/* 各模块实现声明 */
int aegis_debug_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_frida_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_xposed_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_integrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_emulator_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_root_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_system_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_network_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_original_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_opensource_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_device_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_appintegrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);
int aegis_runtime_detect(const aegis_config_t *cfg, aegis_result_t *r, int max);

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
        case AEGIS_MOD_NETWORK:   return aegis_network_detect(cfg, results, max_results);
        case AEGIS_MOD_DEVICE:       return aegis_device_detect(cfg, results, max_results);
        case AEGIS_MOD_APPINTEGRITY: return aegis_appintegrity_detect(cfg, results, max_results);
        case AEGIS_MOD_RUNTIME:      return aegis_runtime_detect(cfg, results, max_results);
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
    /* 扩展模块: 原创 + 开源融合 */
    if (total < max_results) {
        int n = aegis_original_detect(cfg, results + total, max_results - total);
        total += n;
    }
    if (total < max_results) {
        int n = aegis_opensource_detect(cfg, results + total, max_results - total);
        total += n;
    }
    return total;
}
