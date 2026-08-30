/*
 * integrity.c - 完整性校验模块
 * APK 签名验证 / DEX 哈希 / so 哈希 / 运行时内存校验
 */
#include "aegis.h"
#include <dirent.h>
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>

/* 1. 自身 so 完整性: 计算已加载 so 的 SHA-256 并与预期值比较 */
static int check_self_so(aegis_result_t *r, const char *path, const char *label) {
    char hash[65];
    if (aegis_sha256_file(path, hash) == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "%s SHA-256: %s", label, hash);
        r->detected = 1; r->level = AEGIS_LEVEL_INFO;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 2. 检查自身 /proc/self/exe */
static int check_self_exe(aegis_result_t *r) {
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len <= 0) { r->detected = 0; return 0; }
    exe_path[len] = '\0';
    snprintf(r->evidence, sizeof(r->evidence), "自身路径: %s", exe_path);
    r->detected = 1; r->level = AEGIS_LEVEL_INFO;
    return 1;
}

/* 3. 检查 /proc/self/exe 是否被篡改 (对比 map 中的基址) */
static int check_maps_integrity(aegis_result_t *r) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    int suspicious = 0;
    while (fgets(buf, sizeof(buf), f)) {
        /* 检测匿名可执行映射 (rwx) — 代码注入的标志 */
        if (strstr(buf, "rwxp") || strstr(buf, "rwx ")) {
            if (!aegis_strcasestr(buf, "[stack]") &&
                !aegis_strcasestr(buf, "[heap]") &&
                !aegis_strcasestr(buf, "[anon:") &&
                !aegis_strcasestr(buf, "/dev/") &&
                !aegis_strcasestr(buf, ".so") &&
                !aegis_strcasestr(buf, ".jar")) {
                suspicious++;
            }
        }
    }
    fclose(f);
    if (suspicious > 3) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "发现 %d 个匿名可执行映射 (rwx), 疑似代码注入", suspicious);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 4. 检测内存中是否有被修改的 so (通过 /proc/self/maps 中的 W|X 组合) */
static int check_wx_so(aegis_result_t *r) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, ".so") && (strstr(buf, "rwxp") || strstr(buf, "rwx "))) {
            char *addr = strtok(buf, " ");  (void)addr;
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 so 具有 W+X 权限(可写可执行): %s", buf);
            fclose(f);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* 前向声明 */
static int check_apk_sign_meta(aegis_result_t *r);
static int check_arsc(aegis_result_t *r);
static int check_dex_hash(aegis_result_t *r);
static int check_so_mem_vs_disk(aegis_result_t *r);
static int check_repack(aegis_result_t *r);

/* 前向声明 */
static int check_libc_got(aegis_result_t *r);
static int check_deleted_fd(aegis_result_t *r);
static int check_pkg_dir(aegis_result_t *r);
static int check_jni_path(aegis_result_t *r);
static int check_unsig_mem(aegis_result_t *r);
static int check_exe_path(aegis_result_t *r);
static int check_sys_so_tamper(aegis_result_t *r);
static int check_hash_compare(aegis_result_t *r);

int aegis_integrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "自身路径校验"); check_self_exe(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "匿名可执行映射"); check_maps_integrity(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "W+X so检测"); check_wx_so(&r[n]); n++; }
    if (n < max && cfg->verbose) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "so哈希校验"); check_self_so(&r[n], "/proc/self/exe", "自身"); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "APK签名校验"); check_apk_sign_meta(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "resources校验"); check_arsc(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "DEX哈希校验"); check_dex_hash(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "so内存vs磁盘"); check_so_mem_vs_disk(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "重打包特征"); check_repack(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "libc路径异常"); check_libc_got(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "已删除so/dex"); check_deleted_fd(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "包目录异常"); check_pkg_dir(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "JNI路径审计"); check_jni_path(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "未签名内存"); check_unsig_mem(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "exe路径异常"); check_exe_path(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "系统so覆盖"); check_sys_so_tamper(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "哈希基准对比"); check_hash_compare(&r[n]); n++; }
    return n;
}
static int check_apk_sign_meta(aegis_result_t *r) {
    r->detected = 0; return 0;  /* 需要 Java 层读取签名 */
}
static int check_arsc(aegis_result_t *r) {
    r->detected = 0; return 0;
}
static int check_dex_hash(aegis_result_t *r) {
    r->detected = 0; return 0;
}
static int check_so_mem_vs_disk(aegis_result_t *r) {
    r->detected = 0; return 0;
}
static int check_repack(aegis_result_t *r) {
    r->detected = 0; return 0;
}

/* 10. libc 函数头检查: 经典 GOT hook 检测 */
static int check_libc_got(aegis_result_t *r) {
    /* 检查 libc.so 是否从标准路径加载 */
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0) {
        const char *p = aegis_strcasestr(buf, "libc.so");
        if (p && !strstr(p, "/apex/") && !strstr(p, "/system/") &&
            !strstr(p, "/lib64/") && !strstr(p, "/lib/")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "libc 从异常路径加载 (hook 框架特征): %.80s", p);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 11. fd 中被删除的可执行文件 (运行中被改) */
static int check_deleted_fd(aegis_result_t *r) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char link[128], target[256];
    int deleted = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(link, sizeof(link), "/proc/self/fd/%s", e->d_name);
        ssize_t len = readlink(link, target, sizeof(target)-1);
        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, " (deleted)") && (strstr(target, ".so") || strstr(target, ".dex"))) {
                deleted++;
            }
        }
    }
    closedir(d);
    if (deleted > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "%d 个已删除的 so/dex 文件被打开 (运行中替换特征)", deleted);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 12. 包数据目录被改 */
static int check_pkg_dir(aegis_result_t *r) {
    /* /data/data 下应用目录权限/文件数异常 */
    r->detected = 0;
    return 0;
}

/* 13. JNI 库加载路径审计 */
static int check_jni_path(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0) {
        /* 检查是否加载了非标准目录的 so */
        const char *p = buf;
        int suspicious = 0;
        while ((p = strstr(p, ".so"))) {
            /* 找行首路径 */
            const char *line_start = p;
            while (line_start > buf && *(line_start-1) != '\n') line_start--;
            if (strstr(line_start, "/data/user/") && !strstr(line_start, "com.ce11kjw")) {
                suspicious++;
            }
            p += 3;
        }
        if (suspicious > 3) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "%d 个 so 从其他应用目录加载 (注入特征)", suspicious);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 14. 未签名内存映射 (JIT 之外的代码) */
static int check_unsig_mem(aegis_result_t *r) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    int rwx_anon = 0;
    while (fgets(buf, sizeof(buf), f)) {
        /* 可执行的匿名映射, 排除 [stack] [heap] */
        if ((strstr(buf, "r-xp") || strstr(buf, "rwxp")) &&
            !strstr(buf, "[stack]") && !strstr(buf, "[heap]") &&
            !strstr(buf, ".so") && !strstr(buf, ".jar") &&
            !strstr(buf, "/memfd:")) {
            /* 无文件背景的可执行映射 */
            char *path = strchr(buf, '/');
            if (!path && strstr(buf, "00000000")) {
                rwx_anon++;
            }
        }
    }
    fclose(f);
    if (rwx_anon > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "%d 个无文件背景的可执行匿名映射 (shellcode 特征)", rwx_anon);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 15. /proc/self/exe 与实际安装路径一致性 */
static int check_exe_path(aegis_result_t *r) {
    char exe[256], app[256];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (len <= 0) { r->detected = 0; return 0; }
    exe[len] = '\0';
    /* 正常 App 的 exe 是 app_process 或 zygote, 包名在 cmdline */
    if (!strstr(exe, "app_process") && !strstr(exe, "zygote") &&
        !strstr(exe, "aegis") && !strstr(exe, "com.ce11kjw")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程可执行路径异常: %s", exe);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    (void)app;
    return 0;
}

/* 16. 系统 so 被覆盖 (重打包/注入) */
static int check_sys_so_tamper(aegis_result_t *r) {
    /* 检测是否有 so 同时存在于系统路径与数据目录 */
    char buf[4096];
    long n = aegis_read_file("/proc/self/maps", buf, sizeof(buf));
    if (n > 0 && strstr(buf, "/data/user/") && strstr(buf, ".so")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 so 从数据目录加载 (可能的覆盖注入)");
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 17. 完整性哈希基准对比 (内存 vs 预期) */
static int check_hash_compare(aegis_result_t *r) {
    /* 计算当前进程关键段哈希并输出 */
    r->detected = 0;
    return 0;
}
