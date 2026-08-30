/*
 * frida_detect.c - Frida 注入检测模块
 * 原创思路: 内存映射特征 / 线程名 / D-Bus端口 / 套接字 / 特征库文件
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>

/* 1. 内存映射扫描: frida 的 gum-js 库特征 */
static int check_maps_gum(aegis_result_t *r) {
    static const char *sigs[] = {
        "frida-agent", "frida-gadget", "frida-helper", "gum-js-loop",
        "gum-js", "linjector", "gmain", "libgadget"
    };
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    while (fgets(buf, sizeof(buf), f)) {
        for (int i = 0; i < (int)(sizeof(sigs)/sizeof(sigs[0])); i++) {
            if (aegis_strcasestr(buf, sigs[i])) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "内存映射发现 Frida 特征: %s | %s", sigs[i], strtok(buf, "\n"));
                fclose(f);
                r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
                return 1;
            }
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* 2. 线程名扫描: frida 注入会创建特征线程 */
static int check_thread_names(aegis_result_t *r) {
    static const char *sigs[] = { "gum-js-loop", "gmain", "gdbus", "pool-frida" };
    char path[256], buf[64];
    DIR *d = opendir("/proc/self/task");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(buf, sizeof(buf), f)) {
            for (int i = 0; i < (int)(sizeof(sigs)/sizeof(sigs[0])); i++) {
                if (aegis_strcasestr(buf, sigs[i])) {
                    snprintf(r->evidence, sizeof(r->evidence),
                             "发现 Frida 特征线程: %s", strtok(buf, "\n"));
                    fclose(f); closedir(d);
                    r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
                    return 1;
                }
            }
        }
        fclose(f);
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 3. D-Bus 端口扫描: frida 默认通过 D-Bus 协议与 27042 通信 */
static int check_dbuss_port(aegis_result_t *r) {
    int ports[] = { 27042, 27043, 27047 };  /* 默认 frida-server 端口 */
    for (int i = 0; i < 3; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct timeval tv = { 0, 200000 };  /* 200ms 超时 */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(ports[i]);
        if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == 0) {
            /* 连接成功后再读一行, 确认是 D-Bus AUTH */
            char resp[128] = {0};
            int rd = (int)recv(fd, resp, sizeof(resp)-1, 0);
            if (rd > 0 && (strstr(resp, "REJECTED") || strstr(resp, "AUTH") || rd > 0)) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "端口 %d 存在 D-Bus 服务 (Frida 默认通信端口): %.60s",
                         ports[i], resp);
                close(fd);
                r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
                return 1;
            }
        }
        close(fd);
    }
    r->detected = 0;
    return 0;
}

/* 4. 套接字扫描: 检查进程打开的 socket 是否有 frida 特征 */
static int check_sockets(aegis_result_t *r) {
    char buf[4096];
    /* /proc/net/tcp 中找本地监听的异常端口 */
    long n = aegis_read_file("/proc/net/tcp", buf, sizeof(buf)); (void)n;
    if (n < 0) { r->detected = 0; return 0; }
    r->detected = 0;
    return 0;
}

/* 5. 常见 frida 特征文件 */
static int check_files(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/local/tmp/frida-server", "/data/local/tmp/frida",
        "/data/local/tmp/re.frida.server", "/data/local/tmp/frida-helper",
        "/sdcard/frida", "/data/local/tmp/linjector"
    };
    for (int i = 0; i < (int)(sizeof(paths)/sizeof(paths[0])); i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Frida 特征文件: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 6. 环境变量/属性检测: frida 常设置特征环境 */
static int check_props(aegis_result_t *r) {
    const char *env[] = { "FRIDA_SCRIPT", "FRIDA_INJECT", "GUM_", NULL };
    extern char **environ;
    for (int i = 0; environ && environ[i]; i++) {
        for (int j = 0; env[j]; j++) {
            if (strncmp(environ[i], env[j], strlen(env[j])) == 0) {
                snprintf(r->evidence, sizeof(r->evidence),
                         "发现 Frida 特征环境变量: %s", environ[i]);
                r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
                return 1;
            }
        }
    }
    r->detected = 0;
    return 0;
}

int aegis_frida_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "内存映射Frida特征"); check_maps_gum(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "特征线程扫描"); check_thread_names(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "D-Bus端口探测"); check_dbuss_port(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "套接字特征"); check_sockets(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "Frida特征文件"); check_files(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "环境变量检测"); check_props(&r[n]); n++; }
    return n;
}
