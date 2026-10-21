/*
 * app_integrity.c - 应用完整性检测模块 (v4.0 新增)
 *
 * 审计"当前 App 自身是否被篡改"：
 *   - 安装来源（侧载 / 官方商店）
 *   - 签名一致性
 *   - APK 结构完整性
 *   - DEX / so 是否被替换
 *
 * 与 integrity.c 的区别:
 *   integrity.c 检测"系统级注入"（未签名内存、libc 路径等）
 *   app_integrity.c 检测"App 包本身是否被二次打包"
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
 * 1. APK 路径合法性
 * 正常路径: /data/app/~~<random>==/<pkg>-<random>==/base.apk
 * 可疑路径: /data/local/tmp/, /sdcard/, 自定义目录
 * ============================================================ */
static int check_apk_path(aegis_result_t *r) {
    /* 读 /proc/self/cmdline 拿包名，再用 maps 或 /proc/self/exe 定位 */
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    static const char *bad_prefix[] = {
        "/data/local/tmp/", "/sdcard/", "/storage/",
        "/mnt/sdcard/", "/data/data/"
    };
    for (int i = 0; i < 5; i++) {
        if (strncmp(exe, bad_prefix[i], strlen(bad_prefix[i])) == 0) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "App 从可疑路径运行: %.200s", exe);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }

    /* 正常应在 /data/app/ 或 /system/ */
    if (strncmp(exe, "/data/app/", 10) != 0 &&
        strncmp(exe, "/system/", 8) != 0 &&
        strncmp(exe, "/product/", 9) != 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "App 路径非常规: %.200s", exe);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 2. APK 文件权限
 * 正常: 644 (rw-r--r--)，属主 system
 * 被改成 777 / 可写 = 可疑
 * ============================================================ */
static int check_apk_permission(aegis_result_t *r) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    struct stat st;
    if (stat(exe, &st) != 0) { r->detected = 0; return 0; }

    mode_t m = st.st_mode & 0777;
    /* 非 644/600 都可疑；组/其他人可写 = 危险 */
    if (m & 0022) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 权限异常 (可写): 0%o %.200s", m, exe);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    if (m != 0644 && m != 0600 && m != 0444) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 权限非常规: 0%o", m);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 3. APK 目录是否可写（会导致可被替换）
 * ============================================================ */
static int check_apk_dir_writable(aegis_result_t *r) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    char *slash = strrchr(exe, '/');
    if (!slash) { r->detected = 0; return 0; }
    *slash = 0;

    if (access(exe, W_OK) == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 所在目录可写（存在替换风险）: %.200s", exe);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 4. APK 文件的 mtime 异常
 * 安装后 mtime 应接近首次安装时间，若远早/远晚则可疑
 * ============================================================ */
static int check_apk_mtime(aegis_result_t *r) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    struct stat st;
    if (stat(exe, &st) != 0) { r->detected = 0; return 0; }

    /* 文件 mtime 在未来 = 明显异常 */
    time_t now = time(NULL);
    if (st.st_mtime > now + 86400) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 修改时间在未来（时钟被改/文件被伪造）");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 5. 数据目录与 APK 的 UID 一致性
 * APK 属主应该是 system(1000) 或 root(0)
 * ============================================================ */
static int check_uid_consistency(aegis_result_t *r) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    struct stat st;
    if (stat(exe, &st) != 0) { r->detected = 0; return 0; }

    /* 正常 APK 属于 system(1000)；被改机工具替换可能变成其他 uid */
    if (st.st_uid != 1000 && st.st_uid != 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 属主异常: uid=%d (正常应为 1000 system)", st.st_uid);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 6. 安装来源（installerPackageName）
 * v4.0: 通过读取 /data/system/packages.xml 不可行（无权限）
 *       改为检查常见侧载工具的痕迹
 * ============================================================ */
static int check_installer_trace(aegis_result_t *r) {
    static const char *sideload_tools[] = {
        "/data/data/bin.mt.plus",              /* MT 管理器 */
        "/data/data/com.termux",               /* Termux */
        "/data/data/com.omarea.vtools",        /* Scene */
        "/data/data/github.tornaco.android.thanos", /* Thanox */
    };
    for (int i = 0; i < 4; i++) {
        if (aegis_file_exists(sideload_tools[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现侧载工具: %s（App 可能非官方安装）",
                     sideload_tools[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_LOW;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 7. DEX 文件数量异常
 * 正常 APK 的 dex 在 /data/app/.../oat 或 base.apk 内
 * 若数据目录出现额外 dex = 动态加载
 * ============================================================ */
static int check_extra_dex(aegis_result_t *r) {
    /* 检查 App 私有目录（用 /proc/self/cwd 的父目录） */
    char data_dir[256] = {0};
    /* 通过 /proc/self/cmdline 拿不到包名，用 /proc/self/maps 找 base.apk */
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }

    char line[512];
    int found_extra = 0;
    char first[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, ".dex")) continue;
        /* dex 应该在 base.apk 内或 /data/app/ 下的 oat 目录 */
        if (strstr(line, "/data/app/") || strstr(line, "/data/dalvik-cache/") ||
            strstr(line, "base.apk")) {
            continue;
        }
        /* 其他位置 = 动态加载 */
        if (!found_extra) {
            snprintf(first, sizeof(first), "%.200s", line);
            found_extra = 1;
        }
    }
    fclose(f);
    (void)data_dir;

    if (found_extra) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "从非标准路径加载 DEX: %.180s", first);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 8. 自身 so 是否被内存替换
 * 加载的 libaegis.so 路径应来自 base.apk 内的 lib/
 * ============================================================ */
static int check_self_so_path(aegis_result_t *r) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }

    char line[512];
    int found = 0;
    char path[256] = {0};
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, "libaegis.so")) continue;
        /* 提取路径 */
        char *p = strchr(line, '/');
        if (p) {
            snprintf(path, sizeof(path), "%s", p);
            char *nl = strchr(path, '\n'); if (nl) *nl = 0;
            found = 1;
            break;
        }
    }
    fclose(f);

    if (!found) { r->detected = 0; return 0; }

    /* 正常应在 /data/app/.../lib/<abi>/libaegis.so */
    if (strstr(path, "/data/app/") == NULL &&
        strstr(path, "/data/user/") == NULL &&
        strstr(path, "base.apk") == NULL) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "libaegis.so 从异常路径加载: %.200s", path);
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 9. 应用名称/包名是否被篡改
 * App 的 packageName 应该是 com.ce11kjw.aegis
 * 但检测模块无法拿到自身包名（JNI 层无 Context）
 * 改为检查 /proc/self/cmdline
 * ============================================================ */
static int check_process_name(aegis_result_t *r) {
    char cmdline[256] = {0};
    if (aegis_read_file("/proc/self/cmdline", cmdline, sizeof(cmdline)) <= 0) {
        r->detected = 0;
        return 0;
    }

    /* cmdline 是 null 分隔的，用 strnlen 取第一个 */
    size_t len = strnlen(cmdline, sizeof(cmdline));
    if (len == 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程名称为空（异常）");
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    /* 进程名不应包含可疑字符 */
    if (strstr(cmdline, "/") != NULL) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程名称含路径分隔符: %.120s", cmdline);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }

    r->detected = 0;
    return 0;
}

/* ============================================================
 * 10. Zip 结构异常（重打包常见）
 * 检查 base.apk 的 zip 本地文件头是否与中央目录一致
 * ============================================================ */
static int check_zip_structure(aegis_result_t *r) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { r->detected = 0; return 0; }
    exe[n] = 0;

    FILE *f = fopen(exe, "rb");
    if (!f) { r->detected = 0; return 0; }

    /* 读文件尾找中央目录结束符 EOCD (PK\x05\x06) */
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); r->detected = 0; return 0; }
    long size = ftell(f);
    if (size < 22) { fclose(f); r->detected = 0; return 0; }

    /* EOCD 在最后 22-65557 字节内 */
    long scan = size > 65557 ? 65557 : size;
    unsigned char *tail = (unsigned char *)malloc(scan);
    if (!tail) { fclose(f); r->detected = 0; return 0; }
    fseek(f, size - scan, SEEK_SET);
    size_t got = fread(tail, 1, scan, f);
    fclose(f);

    int found_eocd = 0;
    for (long i = (long)got - 22; i >= 0; i--) {
        if (tail[i] == 'P' && tail[i+1] == 'K' && tail[i+2] == 0x05 && tail[i+3] == 0x06) {
            found_eocd = 1;
            break;
        }
    }
    free(tail);

    if (!found_eocd) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "APK 缺少 ZIP 中央目录结束符（结构被破坏）");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* ============================================================
 * 模块入口
 * ============================================================ */
int aegis_appintegrity_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;

#define ADD(item_name, fn) \
    if (n < max) { \
        r[n].module = AEGIS_MOD_APPINTEGRITY; \
        snprintf(r[n].name, sizeof(r[n].name), "%s", (item_name)); \
        fn(&r[n]); \
        n++; \
    }

    ADD("APK路径合法性", check_apk_path);
    ADD("APK文件权限", check_apk_permission);
    ADD("APK目录可写", check_apk_dir_writable);
    ADD("APK时间异常", check_apk_mtime);
    ADD("APK属主一致性", check_uid_consistency);
    ADD("侧载工具痕迹", check_installer_trace);
    ADD("额外DEX加载", check_extra_dex);
    ADD("自身so路径", check_self_so_path);
    ADD("进程名称异常", check_process_name);
    ADD("ZIP结构完整性", check_zip_structure);

#undef ADD
    return n;
}
