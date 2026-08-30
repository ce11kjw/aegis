/*
 * aegis.h - Aegis 安全检测引擎核心头文件
 * 一核三用: EnvGuard v3 (App) / Aegis SDK (加固) / 逆向测试 (C)
 * 架构: 全部检测逻辑下沉 Native 层, Java 仅做展示与调度
 */
#ifndef AEGIS_H
#define AEGIS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 基础常量 ---------- */
#define AEGIS_MODULE_NAME_MAX   32
#define AEGIS_EVIDENCE_MAX      256
#define AEGIS_MAX_RESULTS       256

/* 风险等级 */
typedef enum {
    AEGIS_LEVEL_INFO = 0,   /* 信息, 不构成风险 */
    AEGIS_LEVEL_LOW = 1,    /* 低风险 */
    AEGIS_LEVEL_MED = 2,    /* 中风险 */
    AEGIS_LEVEL_HIGH = 3,   /* 高风险 */
    AEGIS_LEVEL_CRIT = 4    /* 严重 */
} aegis_level_t;

/* 检测模块标识 */
typedef enum {
    AEGIS_MOD_DEBUG = 0,    /* 反调试 */
    AEGIS_MOD_FRIDA = 1,    /* Frida 注入 */
    AEGIS_MOD_XPOSED = 2,   /* Xposed / LSPosed / Zygisk */
    AEGIS_MOD_INTEGRITY = 3,/* 完整性校验 */
    AEGIS_MOD_EMULATOR = 4, /* 模拟器检测 */
    AEGIS_MOD_ROOT = 5,     /* Root / KernelSU / Magisk */
    AEGIS_MOD_SYSTEM = 6,   /* 系统环境 */
    AEGIS_MOD_NETWORK = 7,  /* 网络环境 */
    AEGIS_MOD_COUNT = 8
} aegis_module_t;

/* 单项检测结果 */
typedef struct {
    aegis_module_t module;
    char name[AEGIS_MODULE_NAME_MAX];     /* 检测项名称 */
    int  detected;                        /* 1=检测到风险, 0=未检测到 */
    aegis_level_t level;                  /* 风险等级 */
    char evidence[AEGIS_EVIDENCE_MAX];    /* 证据描述 */
} aegis_result_t;

/* 引擎配置 */
typedef struct {
    int enable_debug;
    int enable_frida;
    int enable_xposed;
    int enable_integrity;
    int enable_emulator;
    int enable_root;
    int enable_system;
    int enable_network;
    int verbose;            /* 详细模式: 返回更多证据 */
} aegis_config_t;

/* ---------- 核心 API ---------- */
/* 初始化引擎 */
void aegis_init(void);

/* 获取默认配置 */
aegis_config_t aegis_default_config(void);

/* 运行全部检测, 结果写入 results, 返回结果数量 */
int aegis_run_all(const aegis_config_t *cfg,
                  aegis_result_t *results, int max_results);

/* 运行单个模块 */
int aegis_run_module(const aegis_config_t *cfg, aegis_module_t mod,
                     aegis_result_t *results, int max_results);

/* 计算整体风险评分 (0-100, 越高越危险) */
int aegis_score(const aegis_result_t *results, int count);

/* 模块名转字符串 */
const char *aegis_module_name(aegis_module_t mod);

/* 等级转字符串 */
const char *aegis_level_str(aegis_level_t level);

/* ---------- 内部工具函数 (供各模块使用) ---------- */
/* 安全读取文件 (截断防溢出), 返回读取字节数 */
long aegis_read_file(const char *path, char *buf, size_t size);

/* 在字符串中搜索子串 (不区分大小写), 返回第一个匹配位置或 NULL */
const char *aegis_strcasestr(const char *haystack, const char *needle);

/* 检查 /proc/self/maps 是否包含特征串, 返回 1=命中 */
int aegis_scan_maps(const char *needle);

/* 检查 /proc/self/task 下线程名是否含特征串 */
int aegis_scan_threads(const char *needle);

/* 检查文件是否存在 */
int aegis_file_exists(const char *path);

/* 计算文件 SHA-256 (十六进制输出, 需要 out 至少 65 字节), 返回 0=成功 */
int aegis_sha256_file(const char *path, char *out_hex);

/* 计算内存缓冲 SHA-256, 返回 0=成功 */
int aegis_sha256_buf(const void *data, size_t len, char *out_hex);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_H */
