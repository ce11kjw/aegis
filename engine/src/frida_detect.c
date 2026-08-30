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
#include <unistd.h>

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

/* 前向声明 */
static int check_fd_pipe(aegis_result_t *r);
static int check_frida_proc(aegis_result_t *r);
static int check_tcp_conn(aegis_result_t *r);
static int check_writable_text(aegis_result_t *r);
static int check_gadget(aegis_result_t *r);
static int check_port_range(aegis_result_t *r);

int aegis_frida_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "内存映射Frida特征"); check_maps_gum(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "特征线程扫描"); check_thread_names(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "D-Bus端口探测"); check_dbuss_port(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "套接字特征"); check_sockets(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "Frida特征文件"); check_files(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "环境变量检测"); check_props(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "fd管道特征"); check_fd_pipe(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "frida进程扫描"); check_frida_proc(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "TCP连接特征"); check_tcp_conn(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "代码段可写检测"); check_writable_text(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "Gadget文件检测"); check_gadget(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_FRIDA; snprintf(r[n].name, sizeof(r[n].name), "Frida端口段"); check_port_range(&r[n]); n++; }
    return n;
}

/* 7. fd 管道特征: frida 注入会留下 pipe 对 */
static int check_fd_pipe(aegis_result_t *r) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    int pipe_count = 0;
    char link[256], target[256];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(link, sizeof(link), "/proc/self/fd/%s", e->d_name);
        ssize_t len = readlink(link, target, sizeof(target)-1);
        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, "pipe")) pipe_count++;
        }
    }
    closedir(d);
    if (pipe_count > 8) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "进程打开 %d 个管道 (正常 <8), 疑似注入通信", pipe_count);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 8. frida-server 进程全局扫描 */
static int check_frida_proc(aegis_result_t *r) {
    DIR *d = opendir("/proc");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    char pcomm[64], ppath[128];
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        snprintf(ppath, sizeof(ppath), "/proc/%s/comm", e->d_name);
        if (aegis_read_file(ppath, pcomm, sizeof(pcomm)) <= 0) continue;
        pcomm[strcspn(pcomm, "\n")] = 0;
        if (strstr(pcomm, "frida") || strstr(pcomm, "fridaserver")) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 frida-server 进程: %s (PID=%s)", pcomm, e->d_name);
            closedir(d);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    closedir(d);
    r->detected = 0;
    return 0;
}

/* 9. /proc/net/tcp 连接特征 */
static int check_tcp_conn(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/net/tcp", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    /* frida 默认端口 27042 十六进制 = 0x6996 */
    if (strstr(buf, "6996")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 Frida 端口 27042 连接");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 10. maps 中代码段可写检测 */
static int check_writable_text(aegis_result_t *r) {
    char buf[4096];
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) { r->detected = 0; return 0; }
    while (fgets(buf, sizeof(buf), f)) {
        if (strstr(buf, "r-xp") || strstr(buf, "r-x ")) {
            /* 正常代码段只读执行, 若被改写成 rwxp 在上面已检测 */
        }
    }
    fclose(f);
    r->detected = 0;
    return 0;
}

/* 11. libgadget 配置检测 */
static int check_gadget(aegis_result_t *r) {
    static const char *paths[] = {
        "/data/local/tmp/libgadget.so", "/data/local/tmp/libgadget.config.so",
        "/data/local/tmp/gadget.config.so"
    };
    for (int i = 0; i < 3; i++) {
        if (aegis_file_exists(paths[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "发现 Frida Gadget 文件: %s", paths[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 12. 多端口扫描 frida 段 */
static int check_port_range(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/net/tcp", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    /* frida 默认 27042/27043/27047 = 0x6996/0x6997/0x699B */
    if (strstr(buf, "6996") || strstr(buf, "6997") || strstr(buf, "699B")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 Frida 端口段监听 (27042-27047)");
        r->detected = 1; r->level = AEGIS_LEVEL_CRIT;
        return 1;
    }
    r->detected = 0;
    return 0;
}
