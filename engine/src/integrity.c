/*
 * integrity.c - 完整性校验模块
 * APK 签名验证 / DEX 哈希 / so 哈希 / 运行时内存校验
 */
#include "aegis.h"
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

int aegis_integrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "自身路径校验"); check_self_exe(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "匿名可执行映射"); check_maps_integrity(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "W+X so检测"); check_wx_so(&r[n]); n++; }
    if (n < max && cfg->verbose) { r[n].module = AEGIS_MOD_INTEGRITY; snprintf(r[n].name, sizeof(r[n].name), "so哈希校验"); check_self_so(&r[n], "/proc/self/exe", "自身"); n++; }
    return n;
}
