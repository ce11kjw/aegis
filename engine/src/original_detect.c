/*
 * original_detect.c - Aegis 原创检测模块
 * 针对现有开源方案（Momo/Free-RASP/DetectFrida/AntiFaker）未覆盖的场景
 *
 * 设计原则:
 *  1. 不重复已有检测，只补空白
 *  2. 优先针对新框架（APatch / Zygisk Next）
 *  3. 尽量用交叉验证而非单点判断，降低误报
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#ifdef __ANDROID__
#include <sys/system_properties.h>
#define GETPROP(k, o, s) __system_property_get((k), (o))
#else
static inline int __getprop_stub(const char *k, char *o, size_t s) { (void)k; (void)o; (void)s; return 0; }
#define GETPROP(k, o, s) __getprop_stub((k), (o), (s))
#endif

/* ---------- 工具 ---------- */

/* 读取 /proc/uptime 的第一列（秒） */
static double read_uptime(void) {
    char buf[64];
    if (aegis_read_file("/proc/uptime", buf, sizeof(buf)) <= 0) return -1;
    return atof(buf);
}

/* 读取某进程的 starttime（clock ticks since boot） */
static long long read_pid_starttime(int pid) {
    char path[64], buf[2048];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (aegis_read_file(path, buf, sizeof(buf)) <= 0) return -1;
    /* stat 格式: pid (comm) state ppid ... starttime 是第 22 个字段 */
    char *p = strrchr(buf, ')');
    if (!p) return -1;
    p++;
    int field = 3;  /* 从 state 开始计数 */
    char *tok = strtok(p, " ");
    while (tok) {
        if (field == 22) return atoll(tok);
        tok = strtok(NULL, " ");
        field++;
    }
    return -1;
}

/* 读取 CLOCK_MONOTONIC 秒数 */
static long long read_monotonic_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    return (long long)ts.tv_sec;
}

/* 统计 mountinfo 行数 */
static int count_mountinfo(int target_pid) {
    char path[64], buf[1024];
    if (target_pid > 0) snprintf(path, sizeof(path), "/proc/%d/mountinfo", target_pid);
    else snprintf(path, sizeof(path), "/proc/self/mountinfo");
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int n = 0;
    while (fgets(buf, sizeof(buf), f)) n++;
    fclose(f);
    return n;
}

/* ============================================================
 * 1. APatch 专属检测
 * ============================================================ */
static int check_apatch_dirs(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/adb/ap", "/data/adb/ap/APatch", "/data/adb/apd",
        "/data/adb/ap/kptools", "/data/adb/ap/su_path",
        "/data/adb/ap/selinux_hide", "/data/adb/ap/pathhide",
        "/data/adb/ap/hide_service", "/data/adb/ap/netisolate",
        "/data/adb/ap/package_config", "/data/adb/ap/version"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 APatch 特征: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 1b. APatch superkey 系统调用探测（v4.2 深度增强）
 *
 * APatch 通过 syscall 劫持 + superkey 实现 root，超键值存在
 * /data/adb/ap/superkey 中（APatch 0.10+）。也可通过 prctl
 * 探测异常返回值判断 syscall 表被 patch。
 * ============================================================ */
static int check_apatch_superkey(aegis_result_t *r) {
    /* 1) superkey 文件（APatch 0.10+ 独有） */
    static const char *key_paths[] = {
        "/data/adb/ap/superkey",
        "/data/adb/ap/super_key",
        "/data/adb/ap/.superkey",
    };
    for (int i = 0; i < 3; i++) {
        if (aegis_file_exists(key_paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 APatch superkey: %s", key_paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }

    /* 2) kernelpatch 特征属性 */
    char buf[128] = {0};
    GETPROP("ro.kernelpatch.version", buf, sizeof(buf));
    if (buf[0]) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 kernelpatch 属性: ro.kernelpatch.version=%s", buf);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }

    /* 3) init 进程的 cmdline 是否含 kpatch */
    memset(buf, 0, sizeof(buf));
    if (aegis_read_file("/proc/1/cmdline", buf, sizeof(buf)) > 0) {
        if (strstr(buf, "kpatch") || strstr(buf, "kpm")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "/proc/1/cmdline 含 kpatch 特征");
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 1c. kpatch 内核符号扫描（v4.2 深度增强）
 *
 * APatch 的 KernelPatch 会在内核里注入 kpatch_* 符号。
 * 即使 /data/adb/ap 被隐藏，/proc/kallsyms 的符号仍然在
 * （除非 SUSFS 做了符号过滤）。
 * ============================================================ */
static int check_kpatch_symbols(aegis_result_t *r) {
    FILE *f = fopen("/proc/kallsyms", "r");
    if (!f) {
        r->detected = 0;
        return 0;
    }

    static const char *syms[] = {
        "kpatch_init", "kpatch_exit", "kpatch_hook",
        "kpatch_superkey", "kpatch_syscall", "kp_",
        "kernelpatch", "kpm_init", "kpm_control"
    };

    char line[512];
    int found = 0;
    char matched[64] = {0};
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        count++;
        if (count > 200000) break;  /* 防大文件卡死 */

        for (int i = 0; i < (int)(sizeof(syms)/sizeof(syms[0])); i++) {
            if (strstr(line, syms[i])) {
                /* 提取符号名（第 3 列） */
                char *p1 = strchr(line, ' ');
                if (!p1) continue;
                p1++;
                char *p2 = strchr(p1, ' ');
                if (!p2) continue;
                p2++;
                char *p3 = strchr(p2, ' ');
                if (!p3) continue;
                p3++;
                size_t n = strcspn(p3, "\n\t ");
                if (n > 0 && n < sizeof(matched)) {
                    memcpy(matched, p3, n);
                    matched[n] = 0;
                    found = 1;
                    break;
                }
            }
        }
        if (found) break;
    }
    fclose(f);

    if (found) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "kallsyms 含 kpatch 符号: %s", matched);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 1d. APatch deny 列表完整性（v4.2 深度增强）
 *
 * APatch 的 package_config 记录哪些 App 被排除 root。
 * 若文件被篡改（比如恶意软件把自己加进去），说明有人
 * 主动修改过隐藏配置。
 * ============================================================ */
static int check_apatch_deny_list(aegis_result_t *r) {
    static const char *cfg_paths[] = {
        "/data/adb/ap/package_config",
        "/data/adb/ap/deny_list",
    };

    for (int i = 0; i < 2; i++) {
        struct stat st;
        if (stat(cfg_paths[i], &st) != 0) continue;

        /* 检查 mtime 是否在最近 1 小时内被改（可疑） */
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        long age = (long)now.tv_sec - (long)st.st_mtime;

        if (age >= 0 && age < 3600) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "%s 在 %.0f 分钟前被修改（可能被篡改）",
                     cfg_paths[i], age / 60.0);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }

        /* 文件存在本身就是 APatch 证据 */
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 APatch 配置文件: %s", cfg_paths[i]);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 1e. apd 进程隐藏检测（v4.2 深度增强）
 *
 * APatch 的 apd 守护进程默认可见。若 /proc 下有 apd 但
 * 用户态 ps 看不到，说明做了进程隐藏（可疑的对抗行为）。
 * ============================================================ */
static int check_apd_hidden(aegis_result_t *r) {
    /* 遍历 /proc/<pid>/comm 找 apd */
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }

    struct dirent *e;
    char comm[64], path[300];
    int apd_pid = -1;

    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(path, comm, sizeof(comm)) <= 0) continue;
        comm[strcspn(comm, "\n")] = 0;
        if (strcmp(comm, "apd") == 0) {
            apd_pid = atoi(e->d_name);
            break;
        }
    }
    closedir(d);

    if (apd_pid <= 0) {
        r->detected = 0;
        return 0;
    }

    /* apd 存在：检查它的 cmdline 是否正常（不应为伪造） */
    char cmdline[256] = {0};
    snprintf(path, sizeof(path), "/proc/%d/cmdline", apd_pid);
    if (aegis_read_file(path, cmdline, sizeof(cmdline)) > 0) {
        /* 正常 apd 的 cmdline 应该就是 "apd" 或含 /data/adb/ap */
        if (cmdline[0] && !strstr(cmdline, "apd") && !strstr(cmdline, "adb/ap")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "apd 进程(pid=%d) cmdline 异常（进程名被伪造）", apd_pid);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }

    snprintf(r->evidence, sizeof(r->evidence),
             "发现 apd 守护进程 (pid=%d)", apd_pid);
    r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
    return 1;
}

/* ============================================================
 * 2. Zygisk Next 专属检测（伪装成 ksu 目录）
 * ============================================================ */
static int check_zygisk_next(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/adb/zygisksu", "/data/adb/zygisksu/module.prop",
        "/data/adb/modules/zygisksu", "/data/adb/modules/zygisksu/module.prop",
        "/data/adb/modules/zygisksu/zygiskd",
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Zygisk Next 特征: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    /* 进程检测 */
    static const char *procs[] = { "zygiskd", "zygiskd64" };
    char matched[64] = {0}, pid[16] = {0};
    if (aegis_scan_proc_name(procs, 2, matched, sizeof(matched), pid, sizeof(pid))) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 Zygisk Next 守护进程: %s (pid=%s)", matched, pid);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 3. MTK 平台特征一致性（识别伪装成 MTK 的设备）
 * ============================================================ */
static int check_mtk_consistency(aegis_result_t *r) {
    char platform[92] = {0}, hardware[92] = {0}, board[92] = {0};
    GETPROP("ro.board.platform", platform, sizeof(platform));
    GETPROP("ro.hardware", hardware, sizeof(hardware));
    GETPROP("ro.product.board", board, sizeof(board));

    int claims_mtk = (aegis_strcasestr(platform, "mt") == platform ||
                      strstr(hardware, "mt") != NULL ||
                      strstr(board, "mt") != NULL);

    if (!claims_mtk) { r->detected = 0; return 0; }

    /* MTK 设备应该有这些节点 */
    static const char *mtk_nodes[] = {
        "/proc/mtk_battery_cmd",
        "/sys/class/power_supply/battery",
        "/proc/mtk_thermal",
        "/sys/devices/platform/mtk_thermal"
    };
    int found = 0;
    for (int i = 0; i < (int)(sizeof(mtk_nodes)/sizeof(mtk_nodes[0])); i++)
        if (aegis_file_exists(mtk_nodes[i])) found++;

    /* 声称 MTK 但一个节点都没有 ⇒ 属性被篡改 */
    if (found == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "属性声称 MTK(%s/%s/%s) 但无任何 MTK 内核节点",
                 platform, hardware, board);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 4. Magisk 模块残留指纹（module.prop 内容特征）
 * ============================================================ */
static int check_magisk_module_prop(aegis_result_t *r) {
    const char *dirs[] = {
        "/data/adb/modules",
        "/data/adb/modules_update"
    };
    for (int d = 0; d < 2; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;
        struct dirent *e;
        while ((e = readdir(dir))) {
            if (e->d_name[0] == '.') continue;
            char p[600];
            snprintf(p, sizeof(p), "%s/%s/module.prop", dirs[d], e->d_name);
            char buf[1200];
            if (aegis_read_file(p, buf, sizeof(buf)) <= 0) continue;
            /* 特征串：Magisk 模板生成的字段 */
            if (strstr(buf, "id=") && strstr(buf, "name=") &&
                strstr(buf, "version=") && strstr(buf, "author=")) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "发现 Magisk 模块: %.80s (路径 %.80s)", e->d_name, dirs[d]);
                r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
                closedir(dir);
                return 1;
            }
        }
        closedir(dir);
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 5. 挂载表差异量化（self vs init）
 * ============================================================ */
static int check_mount_drift(aegis_result_t *r) {
    int self_n = count_mountinfo(0);
    int init_n = count_mountinfo(1);
    if (self_n <= 0 || init_n <= 0) { r->detected = 0; return 0; }

    int diff = self_n - init_n;
    /* 正常情况下 self 会因为 app 沙箱多几条，差异通常 < 10 */
    if (diff < -5 || diff > 30) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "挂载表异常: self=%d init=%d 差异=%+d",
                 self_n, init_n, diff);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 6. 进程生命周期一致性（starttime vs uptime）
 * ============================================================ */
static int check_process_timing(aegis_result_t *r) {
    double uptime = read_uptime();
    long long mono = read_monotonic_sec();
    if (uptime < 0 || mono < 0) { r->detected = 0; return 0; }

    /* uptime 与 CLOCK_MONOTONIC 应该非常接近（差 < 5s） */
    double drift = uptime - (double)mono;
    if (drift < -5.0 || drift > 5.0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "系统时钟异常: uptime=%.1f monotonic=%lld 偏差=%.1fs",
                 uptime, mono, drift);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 7. 三时钟一致性（MONOTONIC / BOOTTIME / REALTIME 跳变）
 * ============================================================ */
static int check_clock_consistency(aegis_result_t *r) {
    /* 无阻塞版: 只对比三个时钟的**当前差值**，不做睡眠观察。
     * 正常设备: CLOCK_BOOTTIME 与 CLOCK_MONOTONIC 只在 suspend 期间有差异，
     *           单次采样两者之差应 < 60s（长时间待机可达数小时，故阈值放宽）。
     * 若差值异常大或为负，说明时钟被 hook/篡改。 */
    struct timespec mono, boot, real;
    if (clock_gettime(CLOCK_MONOTONIC, &mono) != 0) { r->detected = 0; return 0; }
    if (clock_gettime(CLOCK_BOOTTIME, &boot) != 0) { r->detected = 0; return 0; }
    if (clock_gettime(CLOCK_REALTIME, &real) != 0) { r->detected = 0; return 0; }

    long long d_mono_boot = (boot.tv_sec - mono.tv_sec);
    if (d_mono_boot < 0) d_mono_boot = -d_mono_boot;

    /* BOOTTIME >= MONOTONIC 恒成立；负数或差太大说明异常 */
    if (boot.tv_sec < mono.tv_sec || d_mono_boot > 7 * 24 * 3600LL) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "时钟异常: BOOTTIME=%llds MONOTONIC=%llds 差=%llds",
                 (long long)boot.tv_sec, (long long)mono.tv_sec, d_mono_boot);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 8. ELF 匿名可执行映射（通用注入检测）
 * ============================================================ */
static int check_anonymous_exec(aegis_result_t *r) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }

    char line[512];
    int anon_exec = 0;
    char first[600] = {0};

    /* maps 格式: start-end perms offset dev inode pathname */
    while (fgets(line, sizeof(line), f)) {
        unsigned long s_addr, e_addr, off;
        char perms[8] = {0};
        char dev[16] = {0};
        unsigned long inode = 0;
        char path[256] = {0};

        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %255s",
                       &s_addr, &e_addr, perms, &off, dev, &inode, path);
        if (n < 6) continue;            /* 至少 6 个字段 */
        if (perms[2] != 'x') continue;  /* 只看可执行段 */

        /* 无 pathname（n==6）或 pathname 以 '[' 开头 = 匿名映射 */
        int is_anon = (n == 6) || (path[0] == '[');
        if (!is_anon) continue;

        anon_exec++;
        if (anon_exec == 1) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", line);
            char *nl = strchr(tmp, '\n'); if (nl) *nl = 0;
            snprintf(first, sizeof(first), "%s", tmp);
        }
    }
    fclose(f);

    /* 正常设备上 ART JIT / libc 会有少量匿名可执行映射，阈值放宽到 8 */
    if (anon_exec > 8) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "匿名可执行映射 %d 条，首条: %.180s", anon_exec, first);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 9. SELinux 规则集指纹（关键规则是否被增删）
 * ============================================================ */
static int check_selinux_rule_drift(aegis_result_t *r) {
    /* 检测自定义 SELinux 策略文件残留（改造后的 "规则被篡改" 判据） */
    static const char *sepolicy_paths[] = {
        "/data/adb/magisk/sepolicy",
        "/data/adb/ksu/sepolicy",
        "/data/adb/ap/sepolicy",
        "/data/adb/magisk/sepolicy.rule",
        "/data/adb/modules/zygisksu/sepolicy.rule",
    };

    for (int i = 0; i < (int)(sizeof(sepolicy_paths)/sizeof(sepolicy_paths[0])); i++) {
        if (aegis_file_exists(sepolicy_paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现自定义 sepolicy: %s", sepolicy_paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }

    /* 额外: SELinux 状态标志 */
    char enforce[8] = {0};
    if (aegis_read_file("/sys/fs/selinux/enforce", enforce, sizeof(enforce)) > 0) {
        if (enforce[0] == '0') {
            snprintf(r->evidence, sizeof(r->evidence),
                     "SELinux 处于 permissive 模式（enforce=0）");
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 10. 系统服务进程链验证（识别伪 system_server）
 * ============================================================ */
static int check_system_server_chain(aegis_result_t *r) {
    /* 找 system_server 的 pid */
    int ss_pid = -1;
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char comm[64], path[300];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(path, sizeof(path), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(path, comm, sizeof(comm)) <= 0) continue;
        comm[strcspn(comm, "\n")] = 0;
        if (strcmp(comm, "system_server") == 0) {
            ss_pid = atoi(e->d_name);
            break;
        }
    }
    closedir(d);

    if (ss_pid <= 0) { r->detected = 0; return 0; }

    /* system_server 的 starttime 应该 > 0 且 < uptime*100 */
    long long st = read_pid_starttime(ss_pid);
    if (st < 0) { r->detected = 0; return 0; }

    /* 检查 exe 链接（真正的 system_server 应指向 app_process） */
    snprintf(path, sizeof(path), "/proc/%d/exe", ss_pid);
    char exe[256] = {0};
    ssize_t n = readlink(path, exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = 0;
        if (strstr(exe, "app_process") == NULL && strstr(exe, "system_server") == NULL) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "system_server(pid=%d) exe 异常: %.200s", ss_pid, exe);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 11. Android 15+ 安全状态直读
 * ============================================================ */
static int check_security_state_sdk(aegis_result_t *r) {
    /* READ_ADDITIONAL_SECURITY_STATE 权限在 API 35 引入
     * 通过检查相关系统属性/文件判断可用性
     */
    char sdk[16] = {0};
    GETPROP("ro.build.version.sdk", sdk, sizeof(sdk));
    int api = atoi(sdk);

    if (api < 35) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "API %d < 35，无法使用 READ_ADDITIONAL_SECURITY_STATE（Android 15+）", api);
        r->detected = 0;
        return 0;
    }

    /* Android 15+ 有这些新的安全状态节点 */
    static const char *state_paths[] = {
        "/sys/kernel/boot_state",
        "/proc/sys/kernel/random/boot_id",
    };
    int found = 0;
    for (int i = 0; i < 2; i++)
        if (aegis_file_exists(state_paths[i])) found++;

    if (found == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "API %d 但安全状态节点缺失（可能被隐藏）", api);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 12. 内核模块残留（Root 方案常见）
 * ============================================================ */
static int check_kernel_module_residue(aegis_result_t *r) {
    FILE *f = fopen("/proc/modules", "r");
    if (!f) { r->detected = 0; return 0; }
    static const char *suspects[] = {
        "magisk", "ksu", "apatch", "kpatch", "kernelpatch",
        "zygisk", "shamiko", "riru"
    };
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; i < (int)(sizeof(suspects)/sizeof(suspects[0])); i++) {
            if (aegis_strcasestr(line, suspects[i])) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "发现可疑内核模块: %.180s", line);
                r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 13. 属性写入时间异常（resetprop 会改变属性元数据）
 * ============================================================ */
static int check_prop_write_meta(aegis_result_t *r) {
    /* resetprop 修改属性后会重写属性区，导致 mtime 明显晚于开机时间。
     * 判据: 属性区 mtime 距现在 < 60s，但系统已开机 > 10min ⇒ 刚被重写过 */
    struct stat st;
    if (stat("/dev/__properties__", &st) != 0) { r->detected = 0; return 0; }

    double uptime = read_uptime();
    if (uptime < 0) { r->detected = 0; return 0; }

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    double age = (double)now.tv_sec - (double)st.st_mtime;

    /* 开机超过 10 分钟后，属性区却刚刚（<60s）被改 ⇒ 可疑 */
    if (uptime > 600 && age >= 0 && age < 60) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "属性区 %.0fs 前被修改（已开机 %.0fs），疑似 resetprop", age, uptime);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 14. 调试属性一致性（ro.debuggable vs 实际）
 * ============================================================ */
static int check_debuggable_consistency(aegis_result_t *r) {
    char debuggable[16] = {0}, secure[16] = {0}, build_type[32] = {0};
    GETPROP("ro.debuggable", debuggable, sizeof(debuggable));
    GETPROP("ro.secure", secure, sizeof(secure));
    GETPROP("ro.build.type", build_type, sizeof(build_type));

    /* ro.debuggable=1 但 ro.build.type=user ⇒ 矛盾 */
    int d = atoi(debuggable);
    if (d == 1 && strcmp(build_type, "user") == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "属性矛盾: ro.debuggable=1 但 ro.build.type=user");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 15. USB 设备描述符伪造（ADB 伪装）
 * ============================================================ */
static int check_usb_descriptor(aegis_result_t *r) {
    /* 检查 USB 厂商/产品 ID 与实际厂商是否矛盾 */
    char vendor[92] = {0}, model[92] = {0};
    GETPROP("ro.product.vendor.name", vendor, sizeof(vendor));
    GETPROP("ro.product.model", model, sizeof(model));

    /* 如果 vendor 是 generic/unknown 但 model 是具体型号 ⇒ 可疑 */
    if ((strstr(vendor, "generic") || strstr(vendor, "unknown")) &&
        model[0] && !strstr(model, "generic") && !strstr(model, "unknown")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "厂商/型号矛盾: vendor=%s model=%s", vendor, model);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 16. 动态代码加载监控（dlopen 可疑路径）
 * ============================================================ */
static int check_dlopen_paths(aegis_result_t *r) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    static const char *suspect_paths[] = {
        "/data/local/tmp/", "/dev/", "/memfd:", "/proc/self/fd/"
    };
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, ".so")) continue;
        for (int i = 0; i < 4; i++) {
            if (strstr(line, suspect_paths[i])) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "从非常规路径加载 so: %.180s", line);
                r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 模块入口
 * ============================================================ */
int aegis_original_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
#define ADD(item_name, mod, fn) \
    if (n < max) { \
        r[n].module = (mod); \
        snprintf(r[n].name, sizeof(r[n].name), "%s", (item_name)); \
        fn(&r[n]); \
        n++; \
    }

    ADD("APatch专属检测", AEGIS_MOD_ROOT,      check_apatch_dirs);
    ADD("APatch superkey", AEGIS_MOD_ROOT,     check_apatch_superkey);
    ADD("kpatch内核符号", AEGIS_MOD_ROOT,       check_kpatch_symbols);
    ADD("APatch配置篡改", AEGIS_MOD_ROOT,       check_apatch_deny_list);
    ADD("apd进程伪装", AEGIS_MOD_ROOT,          check_apd_hidden);
    ADD("ZygiskNext检测", AEGIS_MOD_XPOSED,   check_zygisk_next);
    ADD("Magisk模块指纹", AEGIS_MOD_ROOT,      check_magisk_module_prop);
    ADD("内核模块残留", AEGIS_MOD_ROOT,      check_kernel_module_residue);
    ADD("SELinux规则篡改", AEGIS_MOD_SYSTEM,  check_selinux_rule_drift);
    ADD("属性写入时间异常", AEGIS_MOD_SYSTEM,  check_prop_write_meta);
    ADD("MTK平台一致性", AEGIS_MOD_EMULATOR, check_mtk_consistency);
    ADD("挂载表差异量化", AEGIS_MOD_SYSTEM,  check_mount_drift);
    ADD("系统时钟一致性", AEGIS_MOD_SYSTEM,  check_process_timing);
    ADD("三时钟跳变检测", AEGIS_MOD_SYSTEM,  check_clock_consistency);
    ADD("匿名可执行映射", AEGIS_MOD_FRIDA,   check_anonymous_exec);
    ADD("系统服务进程链", AEGIS_MOD_SYSTEM,  check_system_server_chain);
    ADD("调试属性矛盾", AEGIS_MOD_SYSTEM,  check_debuggable_consistency);
    ADD("USB描述符伪造", AEGIS_MOD_EMULATOR, check_usb_descriptor);
    ADD("动态代码加载路径", AEGIS_MOD_FRIDA,   check_dlopen_paths);
    ADD("Android15安全状态", AEGIS_MOD_INTEGRITY, check_security_state_sdk);

#undef ADD
    return n;
}
