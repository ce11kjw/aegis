/*
 * jni_bridge.c - Aegis 引擎 JNI 接口
 * 供 EnvGuard App / Aegis SDK 调用, 返回 JSON 字符串
 */
#include "aegis.h"
#include <jni.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 工具: 结果数组转 JSON 字符串 (调用方负责释放) */
static char *results_to_json(const aegis_result_t *results, int count, int score) {
    size_t cap = 8192 + count * 512;
    char *json = (char *)malloc(cap);
    if (!json) return NULL;
    int off = 0;
    off += snprintf(json + off, cap - off,
        "{\"score\":%d,\"count\":%d,\"items\":[", score, count);
    for (int i = 0; i < count; i++) {
        const aegis_result_t *r = &results[i];
        off += snprintf(json + off, cap - off,
            "%s{\"module\":%d,\"module_name\":\"%s\",\"name\":\"%s\","
            "\"detected\":%d,\"level\":%d,\"level_str\":\"%s\",\"evidence\":\"%s\"}",
            i > 0 ? "," : "",
            (int)r->module, aegis_module_name(r->module),
            r->name, r->detected, (int)r->level,
            aegis_level_str(r->level), r->evidence);
        /* 简单转义 JSON 特殊字符 */
        /* 注: 证据文本来自系统, 极少含引号, 生产应做完整转义 */
    }
    off += snprintf(json + off, cap - off, "]}");
    return json;
}

JNIEXPORT jstring JNICALL
Java_com_ce11kjw_aegis_AegisNative_runAll(JNIEnv *env, jclass clazz) {
    aegis_init();
    aegis_config_t cfg = aegis_default_config();
    aegis_result_t results[AEGIS_MAX_RESULTS];
    int count = aegis_run_all(&cfg, results, AEGIS_MAX_RESULTS);
    int score = aegis_score(results, count);
    char *json = results_to_json(results, count, score);
    jstring out = json ? (*env)->NewStringUTF(env, json) : NULL;
    free(json);
    return out;
}

JNIEXPORT jstring JNICALL
Java_com_ce11kjw_aegis_AegisNative_runModule(JNIEnv *env, jclass clazz, jint module) {
    aegis_init();
    aegis_config_t cfg = aegis_default_config();
    aegis_result_t results[AEGIS_MAX_RESULTS];
    int count = aegis_run_module(&cfg, (aegis_module_t)module,
                                 results, AEGIS_MAX_RESULTS);
    int score = aegis_score(results, count);
    char *json = results_to_json(results, count, score);
    jstring out = json ? (*env)->NewStringUTF(env, json) : NULL;
    free(json);
    return out;
}

/* 静态注册表 */
static const JNINativeMethod methods[] = {
    { "runAll",   "()Ljava/lang/String;", (void *)Java_com_ce11kjw_aegis_AegisNative_runAll },
    { "runModule", "(I)Ljava/lang/String;", (void *)Java_com_ce11kjw_aegis_AegisNative_runModule },
};

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    jclass cls = (*env)->FindClass(env, "com/ce11kjw/aegis/AegisNative");
    if (!cls) return JNI_ERR;
    (*env)->RegisterNatives(env, cls, methods, sizeof(methods)/sizeof(methods[0]));
    return JNI_VERSION_1_6;
}
