/*
 * network.c - 网络环境检测模块
 * 全局代理 / VPN / CA证书 / USB调试 / ADB / 异常端口
 */
#include "aegis.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* 1. 全局 HTTP 代理检测 (抓包工具特征) */
static int check_global_proxy(aegis_result_t *r) {
    char buf[256];
    /* Android 全局代理存在 /data/misc/proxy 或属性中 */
    FILE *f = fopen("/data/misc/proxy", "r");
    if (f) {
        long n = fread(buf, 1, sizeof(buf)-1, f);
        fclose(f);
        if (n > 0) {
            buf[n] = '\0';
            snprintf(r->evidence, sizeof(r->evidence),
                     "检测到全局代理配置: %s (抓包工具特征)", buf);
            r->detected = 1; r->level = AEGIS_LEVEL_MED;
            return 1;
        }
    }
    /* 属性检查 */
    char prop[128];
    #ifdef __ANDROID__
    __system_property_get("net.gprs.http-proxy", prop);
    if (prop[0] && strstr(prop, ":")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 HTTP 代理属性: %s", prop);
        r->detected = 1; r->level = AEGIS_LEVEL_MED;
        return 1;
    }
    #else
    (void)prop;
    #endif
    r->detected = 0;
    return 0;
}

/* 2. VPN 接口检测 (虚拟网卡) */
static int check_vpn(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/net/dev", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    static const char *vpn_if[] = { "tun0", "tun1", "tap0", "ppp0", "wlan1",
                                    "ipsec", "wg0", "vpn", "utun" };
    for (int i = 0; i < (int)(sizeof(vpn_if)/sizeof(vpn_if[0])); i++) {
        if (aegis_strcasestr(buf, vpn_if[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "检测到 VPN/虚拟网卡接口: %s", vpn_if[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_LOW;
            return 1;
        }
    }
    r->detected = 0;
    return 0;
}

/* 3. 用户 CA 证书检测 (中间人/抓包特征) */
static int check_user_ca(aegis_result_t *r) {
    /* 用户安装的 CA 证书目录 */
    DIR *d = opendir("/data/misc/user/0/cacerts-added");
    if (!d) { r->detected = 0; return 0; }
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        count++;
    }
    closedir(d);
    if (count > 0) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 %d 个用户安装的 CA 证书 (抓包/中间人特征)", count);
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 4. USB 调试检测 */
static int check_usb_debug(aegis_result_t *r) {
    char prop[128];
    #ifdef __ANDROID__
    __system_property_get("persist.sys.usb.config", prop);
    if (strstr(prop, "adb") || strstr(prop, "debug")) {
        snprintf(r->evidence, sizeof(r->evidence),
                 "USB 调试已开启: %s", prop);
        r->detected = 1; r->level = AEGIS_LEVEL_LOW;
        return 1;
    }
    #else
    (void)prop;
    #endif
    r->detected = 0;
    return 0;
}

/* 5. ADB 连接检测 */
static int check_adb(aegis_result_t *r) {
    /* 5555 是 adb tcpip 默认端口 */
    char buf[4096];
    long n = aegis_read_file("/proc/net/tcp", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    if (strstr(buf, "15B3")) {  /* 0x15B3 = 5555 */
        snprintf(r->evidence, sizeof(r->evidence),
                 "检测到 ADB 端口 5555 监听 (设备可被远程调试)");
        r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
        return 1;
    }
    r->detected = 0;
    return 0;
}

/* 6. 异常端口监听扫描 */
static int check_suspicious_ports(aegis_result_t *r) {
    char buf[4096];
    long n = aegis_read_file("/proc/net/tcp", buf, sizeof(buf));
    if (n <= 0) { r->detected = 0; return 0; }
    /* 常见恶意/工具端口: 27042(frida) 23946(ida) 5039(jeb)
     * 8888 9090 8080 等常被注入工具占用 */
    static const char *ports[] = { "6996", "5D8A", "13AF", "22B8", "2388", "237E", "1F90", "1F91", "1F92" };
    /* 6996=27042 frida, 5D8A=23946 ida, 13AF=5039 jeb */
    const char *susp[] = { "6996", "5D8A", "13AF" };
    for (int i = 0; i < 3; i++) {
        if (strstr(buf, susp[i])) {
            snprintf(r->evidence, sizeof(r->evidence),
                     "检测到可疑端口监听: 0x%s (注入/调试工具特征)", susp[i]);
            r->detected = 1; r->level = AEGIS_LEVEL_HIGH;
            return 1;
        }
    }
    (void)ports;
    r->detected = 0;
    return 0;
}

int aegis_network_detect(const aegis_config_t *cfg, aegis_result_t *r, int max) {
    (void)cfg;
    int n = 0;
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "全局代理检测"); check_global_proxy(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "VPN接口检测"); check_vpn(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "用户CA证书检测"); check_user_ca(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "USB调试检测"); check_usb_debug(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "ADB连接检测"); check_adb(&r[n]); n++; }
    if (n < max) { r[n].module = AEGIS_MOD_NETWORK; snprintf(r[n].name, sizeof(r[n].name), "可疑端口监听"); check_suspicious_ports(&r[n]); n++; }
    return n;
}
