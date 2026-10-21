/*
 * runtime_detect.c - 运行时行为检测模块 (v4.0 新增)
 *
 * 检测"当前进程在运行时的异常行为"：
 *   - UID / GID 异常
 *   - 线程数突变
 *   - 文件句柄泄漏
 *   - 内存映射增长
 *   - 信号处理器劫持
 *   - JNI 注册表异常
 *   - 定时器漂移
 *   - 系统调用频率异常
 *
 * 这些是"动态注入"的运行时特征，静态检测不易发现。
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

/* ============================================================
 * 1. 实际 UID/GID vs 预期
 * App 进程通常: uid=10xxx (app id), gid=10xxx
 * 若 uid=0 但进程名是 App = 通过 su 提权运行
 * ============================================================ */
static int check_uid_gid(aegis_result_t *r) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();

    if (uid == 0 || euid == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程以 root 身份运行 (uid=%d euid=%d)", uid, euid);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }

    /* App 的 uid 应 >= 10000 */
    if (uid < 10000) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "UID 异常 (系统级 uid): %d", uid);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    (void)gid;
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 2. 线程数突变
 * 正常 App 5-50 线程，注入框架会额外创建线程
 * ============================================================ */
static int check_thread_count(aegis_result_t *r) {
    DIR *d = opendir("/proc/self/task");
    if (!d) { r->detected = 0; return 0; }

    int count = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;
    }
    closedir(d);

    /* 阈值保守：> 60 才报警（Compose App 本身线程较多） */
    if (count > 60) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "线程数异常: %d 个（正常 App < 50）", count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 3. 文件句柄数量 / 异常 fd
 * ============================================================ */
static int check_fd_count(aegis_result_t *r) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) { r->detected = 0; return 0; }

    int count = 0;
    int socket_count = 0;
    int pipe_count = 0;
    struct dirent *e;
    char path[300], link[300];

    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;

        snprintf(path, sizeof(path), "/proc/self/fd/%s", e->d_name);
        ssize_t n = readlink(path, link, sizeof(link) - 1);
        if (n <= 0) continue;
        link[n] = 0;

        if (strstr(link, "socket:")) socket_count++;
        else if (strstr(link, "pipe:")) pipe_count++;
    }
    closedir(d);

    /* fd 总数 > 300 = 可疑（正常 App ~50-150） */
    if (count > 300) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "文件句柄过多: %d 个 (socket=%d pipe=%d)",
                 count, socket_count, pipe_count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    /* socket 数量异常多 = 可能是 Frida 通信 */
    if (socket_count > 50) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "socket 数量异常: %d 个", socket_count);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 4. 内存映射段数量
 * 注入框架会额外 mmap 大量段
 * ============================================================ */
static int check_maps_count(aegis_result_t *r) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }

    char line[512];
    int count = 0;
    int exec_count = 0;
    while (fgets(line, sizeof(line), f)) {
        count++;
        /* 判断可执行权限 */
        char *p = strchr(line, ' ');
        if (p && strlen(p) > 3 && p[3] == 'x') exec_count++;
    }
    fclose(f);

    /* 正常 App 约 300-800 段 */
    if (count > 2000) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "内存映射段过多: %d 个（可执行 %d）", count, exec_count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 5. 信号处理器劫持
 * 关键信号（SIGSEGV/SIGTRAP/SIGILL）若被替换，
 * 说明有调试器/反调试对抗工具在运行
 * ============================================================ */
static int check_signal_handler(aegis_result_t *r) {
    /* 通过 /proc/self/status 的 SigCgt (捕获的信号掩码) */
    char buf[4096] = {0};
    if (aegis_read_file("/proc/self/status", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    char *p = strstr(buf, "SigCgt:");
    if (!p) { r->detected = 0; return 0; }

    p += 7;
    while (*p == ' ' || *p == '\t') p++;

    unsigned long long mask = strtoull(p, NULL, 16);

    /* SIGTRAP = bit 4 (信号编号 5 - 1) */
    int has_sigtrap = (mask >> 4) & 1;

    if (has_sigtrap) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "捕获 SIGTRAP（调试器/反调试验证特征）: SigCgt=0x%llx", mask);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 6. JNI 动态注册异常
 * 正常 App 的 JNI_OnLoad 只注册一次
 * 若出现异常多的 JNI 注册 = 动态注入
 * ============================================================ */
static int check_jni_registration(aegis_result_t *r) {
    /* 通过 maps 检查是否有多个 libart 或 JNI 相关库被加载 */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }

    char line[512];
    int libart_count = 0;
    int last = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libart.so") || strstr(line, "libartbase.so")) {
            /* 只统计不同文件 */
            if (last != 0) libart_count++;
            last = 0;
        } else {
            last = -1;
        }
    }
    fclose(f);

    /* 应该只加载一份 libart */
    if (last == 0 && libart_count > 3) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "libart 被多次映射 (%d 段)，疑似 ART hook", libart_count);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 7. 定时器漂移（hook timing attacks）
 * 对比 CLOCK_REALTIME 与 CLOCK_MONOTONIC 在两次采样中的差值
 * ============================================================ */
static int check_timer_drift(aegis_result_t *r) {
    struct timespec r1, m1;
    if (clock_gettime(CLOCK_REALTIME, &r1) != 0) { r->detected = 0; return 0; }
    if (clock_gettime(CLOCK_MONOTONIC, &m1) != 0) { r->detected = 0; return 0; }

    /* 简单自旋等待 ~5ms（不 sleep，避免被 hook sleep） */
    volatile long long spin = 0;
    for (long long i = 0; i < 2000000LL; i++) spin += i;

    struct timespec r2, m2;
    if (clock_gettime(CLOCK_REALTIME, &r2) != 0) { r->detected = 0; return 0; }
    if (clock_gettime(CLOCK_MONOTONIC, &m2) != 0) { r->detected = 0; return 0; }

    long long d_real = (r2.tv_sec - r1.tv_sec) * 1000000000LL + (r2.tv_nsec - r1.tv_nsec);
    long long d_mono = (m2.tv_sec - m1.tv_sec) * 1000000000LL + (m2.tv_nsec - m1.tv_nsec);

    /* 两者差值不应超过 50ms（50000000 ns） */
    long long diff = d_real - d_mono;
    if (diff < 0) diff = -diff;

    if (diff > 50000000LL) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "定时器漂移 %.1fms（REALTIME vs MONOTONIC）", diff / 1000000.0);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 8. 进程启动时间异常
 * /proc/self/stat 的 starttime 应该 > 0 且合理
 * ============================================================ */
static int check_process_starttime(aegis_result_t *r) {
    char buf[2048] = {0};
    if (aegis_read_file("/proc/self/stat", buf, sizeof(buf)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* stat 第 22 字段是 starttime */
    char *p = strrchr(buf, ')');
    if (!p) { r->detected = 0; return 0; }
    p++;

    int field = 3;
    char *tok = strtok(p, " ");
    long long starttime = -1;
    while (tok) {
        if (field == 22) { starttime = atoll(tok); break; }
        tok = strtok(NULL, " ");
        field++;
    }

    if (starttime <= 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程启动时间为 0 或无效（进程状态被伪造？）");
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    /* 与 system uptime 对比：进程启动时间不应超过 uptime */
    char up[64] = {0};
    if (aegis_read_file("/proc/uptime", up, sizeof(up)) > 0) {
        double uptime_sec = atof(up);
        /* starttime 单位是 clock ticks，通常 100Hz */
        double proc_sec = (double)starttime / 100.0;
        if (proc_sec > uptime_sec + 5.0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "进程启动时间晚于系统开机时间 (proc=%.1fs uptime=%.1fs)",
                     proc_sec, uptime_sec);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 模块入口
 * ============================================================ */
int aegis_runtime_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;

#define ADD(item_name, fn) \
    if (n < max) { \
        r[n].module = AEGIS_MOD_RUNTIME; \
        snprintf(r[n].name, sizeof(r[n].name), "%s", (item_name)); \
        fn(&r[n]); \
        n++; \
    }

    ADD("UID权限异常", check_uid_gid);
    ADD("线程数异常", check_thread_count);
    ADD("文件句柄异常", check_fd_count);
    ADD("内存映射数量", check_maps_count);
    ADD("信号处理器劫持", check_signal_handler);
    ADD("JNI注册异常", check_jni_registration);
    ADD("定时器漂移", check_timer_drift);
    ADD("进程启动时间", check_process_starttime);

#undef ADD
    return n;
}
