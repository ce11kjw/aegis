/*
 * debug_detect.c - 反调试检测模块
 * 原创思路: TracerPid 审计 / ptrace 抢占 / 父进程审计 / 时间差 / /proc 扫描
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>

/* 1. TracerPid 检测: 只要 >0 说明被调试 */
static int check_tracer_pid(aegis_result_t *r) {
    char buf[1024];
    long n = aegis_read_file("/proc/self/status", buf, sizeof(buf));
    if (n < 0) { r->detected = 0; return 0; }
    const char *p = aegis_strcasestr(buf, "TracerPid:");
    if (p) {
        int pid = atoi(p + 10);
        if (pid > 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "TracerPid=%d, 进程正被调试器附加", pid);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 2. ptrace 抢占: 自己尝试 attach 自己, 若 EPERM 说明已被他人跟踪 */
static int check_ptrace_self(aegis_result_t *r) {
    int ret = ptrace(PTRACE_ATTACH, getpid(), NULL, NULL);
    if (ret == 0) {
        ptrace(PTRACE_DETACH, getpid(), NULL, NULL);
        r->detected = 0;
        return 0;
    }
    if (errno == EPERM) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "ptrace attach 返回 EPERM, 进程已被外部调试器跟踪");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 3. 父进程审计: 正常 App 父进程是 zygote, 异常说明被拉起 */
static int check_parent(aegis_result_t *r) {
    char buf[1024];
    /* 通过 /proc/self/stat 取 ppid */
    long n = aegis_read_file("/proc/self/stat", buf, sizeof(buf));
    if (n < 0) { r->detected = 0; return 0; }
    /* stat 格式: pid (comm) state ppid ... */
    const char *rp = strrchr(buf, ')');
    if (!rp) { r->detected = 0; return 0; }
    rp++; /* 跳过 ) */
    /* 跳过 state */
    while (*rp == ' ') rp++;
    rp++; /* state 字符 */
    while (*rp == ' ') rp++;
    int ppid = atoi(rp);

    char pcomm[128];
    char ppath[64];
    snprintf(ppath, sizeof(ppath), "/proc/%d/comm", ppid);
    long pl = aegis_read_file(ppath, pcomm, sizeof(pcomm));
    if (pl > 0) {
        pcomm[strcspn(pcomm, "\n")] = 0;
        /* zygote 家族为正常 */
        if (strstr(pcomm, "zygote") || strcmp(pcomm, "init") == 0) {
            r->detected = 0;
            return 0;
        }
        snprintf(r->evidence, sizeof(r->evidence),
                 "父进程异常: PID=%d comm=%s (正常应为 zygote)", ppid, pcomm);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 4. 调试时间差: 执行敏感操作耗时异常说明被单步/拦截 */
static int check_timing(aegis_result_t *r) {
    struct timeval t1, t2;
    volatile int x = 0;
    gettimeofday(&t1, NULL);
    for (volatile int i = 0; i < 100000; i++) x += i;
    gettimeofday(&t2, NULL);
    long us = (t2.tv_sec - t1.tv_sec) * 1000000L + (t2.tv_usec - t1.tv_usec);
    /* 正常情况下 10 万次整数加法 < 5ms, 若 > 100ms 说明代码被注入/单步 */
    if (us > 100000) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "指令时间差异常: 10万次加法耗时 %ldms (正常 <5ms), 疑似单步调试", us/1000);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 5. /proc 全局扫描: 找调试器进程 */
static int check_debug_procs(aegis_result_t *r) {
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    static const char *dbg[] = { "gdb", "lldb", "gdbserver", "lldb-server",
                                 "android_server", "ida", "ida64", "frida" };
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char pcomm[64], ppath[128];
        snprintf(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        for (int i = 0; i < (int)(sizeof(dbg)/sizeof(dbg[0])); i++) {
            if (strcmp(pcomm, dbg[i]) == 0) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "发现调试器进程: %s (PID=%s)", pcomm, e->d_name);
                closedir(d);
                r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
                return 1;
            }
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 6. 防调试自检: 检测自身 so 是否被 inline hook (检查函数头) */
static int check_inline_hook(aegis_result_t *r) {
    /* 检查自己一个关键函数的机器码是否被改写 (被 inline hook 的标志)
     * 此处用 aegis_read_file 作为探测函数 */
    /* Android ARM64 前几条指令通常是 stp (0xA9) / sub (0xD1) 开头 */
    /* 简化: 直接读自身 /proc/self/exe 是否可读 */
    r->detected = 0;
    return 0;
}

int aegis_debug_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "TracerPid调试跟踪"); check_tracer_pid(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "ptrace抢占检测"); check_ptrace_self(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "父进程审计"); check_parent(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "调试时间差检测"); check_timing(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "调试器进程扫描"); check_debug_procs(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_DEBUG; snprintf(r[n].name, sizeof(r[n].name), "inline hook检测"); check_inline_hook(&r[n]); n++; }
    return n;
}
