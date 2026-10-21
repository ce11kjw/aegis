/*
 * jni_bridge.c - Aegis 引擎 JNI 接口
 * 供 EnvGuard App / Aegis SDK 调用, 返回 JSON 字符串
 */
#include "aegis.h"
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* JSON 转义: 将字符串中特殊字符转义为 \u / \\ / \" 等 */
static void json_escape(const char *in, char *out, size_t out_size) {
    if (!in) { if (out_size > 0) out[0] = '\0'; return; }
    size_t o = 0;
    for (const char *p = in; *p && o + 6 < out_size; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
            case '"':  out[o++]='\\'; out[o++]='"';  break;
            case '\\': out[o++]='\\'; out[o++]='\\'; break;
            case '\n': out[o++]='\\'; out[o++]='n';  break;
            case '\r': out[o++]='\\'; out[o++]='r';  break;
            case '\t': out[o++]='\\'; out[o++]='t';  break;
            case '\b': out[o++]='\\'; out[o++]='b';  break;
            case '\f': out[o++]='\\'; out[o++]='f';  break;
            default:
                if (c < 0x20) {
                    /* 控制字符 -> \u00XX */
                    static const char *hex = "0123456789abcdef";
                    out[o++]='\\'; out[o++]='u'; out[o++]='0'; out[o++]='0';
                    out[o++]=hex[(c>>4)&0xf]; out[o++]=hex[c&0xf];
                } else {
                    out[o++] = *p;
                }
        }
    }
    out[o] = '\0';
}

/* 工具: 结果数组转 JSON 字符串 (调用方负责释放) */
static char *results_to_json(const aegis_result_t *results, int count, int score) {
    size_t cap = 16384 + (size_t)count * 900;   /* 最坏: 每项 evidence 全控制字符 */
    char *json = (char *)malloc(cap);
    if (!json) return NULL;
    int off = 0;
    off += snprintf(json + off, cap - off,
        "{\"score\":%d,\"count\":%d,\"items\":[", score, count);
    for (int i = 0; i < count; i++) {
        const aegis_result_t *r = &results[i];
        char esc_name[160], esc_mod[128], esc_lv[64], esc_ev[AEGIS_EVIDENCE_MAX * 6 + 32];
        json_escape(r->name, esc_name, sizeof(esc_name));
        json_escape(aegis_module_name(r->module), esc_mod, sizeof(esc_mod));
        json_escape(aegis_level_str(r->level), esc_lv, sizeof(esc_lv));
        json_escape(r->evidence, esc_ev, sizeof(esc_ev));
        off += snprintf(json + off, cap - off,
            "%s{\"module\":%d,\"module_name\":\"%s\",\"name\":\"%s\","
            "\"detected\":%d,\"level\":%d,\"level_str\":\"%s\",\"evidence\":\"%s\"}",
            i > 0 ? "," : "",
            (int)r->module, esc_mod,
            esc_name, r->detected, (int)r->level,
            esc_lv, esc_ev);
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



/* ============================================================
 * v4.5: 带进度的全量扫描
 *
 * 逐个模块运行并通过回调通知 Java 层进度。
 * 用于 UI 的扫描过程可视化（模块名 + 进度百分比）。
 * ============================================================ */
JNIEXPORT jstring JNICALL
Java_com_ce11kjw_aegis_AegisNative_runAllWithProgress(
        JNIEnv *env, jclass clazz, jobject callback) {
    aegis_init();
    aegis_config_t cfg = aegis_default_config();
    aegis_result_t results[AEGIS_MAX_RESULTS];
    int total = 0;

    /* 获取回调方法 ID：void onProgress(String module, int index, int total) */
    jmethodID onProgress = NULL;
    if (callback) {
        jclass cbClass = (*env)->GetObjectClass(env, callback);
        if (cbClass) {
            onProgress = (*env)->GetMethodID(env, cbClass, "onProgress",
                                             "(Ljava/lang/String;II)V");
            if (!onProgress) (*env)->ExceptionClear(env);
        }
    }

    /* 模块总数 = 11（含扩展的原创/开源/设备/应用/运行时） */
    int mod_total = AEGIS_MOD_COUNT + 5;   /* 8 基础 + 3 新模块 + 原创 + 开源 */
    int mod_index = 0;

#define NOTIFY(name) do { \
    if (onProgress && callback) { \
        jstring js = (*env)->NewStringUTF(env, (name)); \
        (*env)->CallVoidMethod(env, callback, onProgress, js, mod_index, mod_total); \
        (*env)->DeleteLocalRef(env, js); \
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); \
    } \
    mod_index++; \
} while(0)

    /* 基础 8 模块 */
    for (int m = 0; m < AEGIS_MOD_COUNT && total < AEGIS_MAX_RESULTS; m++) {
        NOTIFY(aegis_module_name((aegis_module_t)m));
        int n = aegis_run_module(&cfg, (aegis_module_t)m,
                                 results + total, AEGIS_MAX_RESULTS - total);
        total += n;
    }

    /* 扩展 5 个（原创/开源 分两批，设备/应用/运行时已在 AEGIS_MOD_COUNT 内） */
    if (total < AEGIS_MAX_RESULTS) {
        NOTIFY("原创检测");
        total += aegis_original_detect(&cfg, results + total, AEGIS_MAX_RESULTS - total);
    }
    if (total < AEGIS_MAX_RESULTS) {
        NOTIFY("开源融合");
        total += aegis_opensource_detect(&cfg, results + total, AEGIS_MAX_RESULTS - total);
    }
#undef NOTIFY

    int score = aegis_score(results, total);
    char *json = results_to_json(results, total, score);
    jstring out = json ? (*env)->NewStringUTF(env, json) : NULL;
    free(json);
    return out;
}

/* v4.2: 检测 su 是否可用（会触发授权弹窗） */
JNIEXPORT jboolean JNICALL
Java_com_ce11kjw_aegis_AegisNative_checkRoot(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    return aegis_check_root_available() ? JNI_TRUE : JNI_FALSE;
}

/* 按模块集合运行（v4.1）：传入 jintArray，只跑指定模块 */
JNIEXPORT jstring JNICALL
Java_com_ce11kjw_aegis_AegisNative_runModules(JNIEnv *env, jclass clazz, jintArray modules) {
    aegis_init();
    aegis_config_t cfg = aegis_default_config();
    aegis_result_t results[AEGIS_MAX_RESULTS];
    int total = 0;

    jsize n = (*env)->GetArrayLength(env, modules);
    if (n <= 0 || total >= AEGIS_MAX_RESULTS) {
        int count = aegis_run_all(&cfg, results, AEGIS_MAX_RESULTS);
        int score = aegis_score(results, count);
        char *json = results_to_json(results, count, score);
        jstring out = json ? (*env)->NewStringUTF(env, json) : NULL;
        free(json);
        return out;
    }

    jint *arr = (*env)->GetIntArrayElements(env, modules, NULL);
    if (!arr) return NULL;

    for (jsize i = 0; i < n && total < AEGIS_MAX_RESULTS; i++) {
        int mod = arr[i];
        if (mod < 0 || mod >= AEGIS_MOD_COUNT) continue;
        int got = aegis_run_module(&cfg, (aegis_module_t)mod,
                                   results + total, AEGIS_MAX_RESULTS - total);
        total += got;
    }
    (*env)->ReleaseIntArrayElements(env, modules, arr, JNI_ABORT);

    int score = aegis_score(results, total);
    char *json = results_to_json(results, total, score);
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

/* ---------- App 用（AegisNative）---------- */
static const JNINativeMethod methods_app[] = {
    { "runAll",     "()Ljava/lang/String;",   (void *)Java_com_ce11kjw_aegis_AegisNative_runAll },
    { "runModule",  "(I)Ljava/lang/String;",  (void *)Java_com_ce11kjw_aegis_AegisNative_runModule },
    { "runModules", "([I)Ljava/lang/String;", (void *)Java_com_ce11kjw_aegis_AegisNative_runModules },
    { "checkRoot",  "()Z",                    (void *)Java_com_ce11kjw_aegis_AegisNative_checkRoot },
    { "runAllWithProgress", "(Lcom/ce11kjw/aegis/data/ScanCallback;)Ljava/lang/String;",
      (void *)Java_com_ce11kjw_aegis_AegisNative_runAllWithProgress },
};

/* ---------- SDK 用（AegisGuard）---------- */
static jstring sdk_runAll(JNIEnv *env, jclass clazz) {
    return Java_com_ce11kjw_aegis_AegisNative_runAll(env, clazz);
}

static jstring sdk_runModuleImpl(JNIEnv *env, jclass clazz, jint module) {
    return Java_com_ce11kjw_aegis_AegisNative_runModule(env, clazz, module);
}

static const JNINativeMethod methods_sdk[] = {
    { "runAll",         "()Ljava/lang/String;",  (void *)sdk_runAll },
    { "runModuleImpl",  "(I)Ljava/lang/String;", (void *)sdk_runModuleImpl },
};

/* 注册一个类的 native 方法（类不存在时静默跳过）
 *
 * ⚠️ 重要：RegisterNatives 失败时**必须清掉待处理异常**，
 * 否则 ART 会在后续 FindClass / 返回时检测到 pending exception
 * 而直接 abort（报 "No pending exception expected"）。
 *
 * 这也是 v4.5.0 首发崩溃的根因之一：
 *   签名写成 (Lcom/ce11kjw/aegis/ScanCallback;) 而非 .../data/ScanCallback;，
 *   RegisterNatives 抛 NoSuchMethodError，
 *   而旧代码只清 FindClass 的异常、没清 RegisterNatives 的，
 *   导致 JNI_OnLoad 返回时 ART abort。
 */
static int register_for_class(JNIEnv *env, const char *class_name,
                              const JNINativeMethod *methods, int count) {
    jclass cls = (*env)->FindClass(env, class_name);
    if (!cls) {
        /* 类未加载：清掉异常，继续尝试下一个 */
        (*env)->ExceptionClear(env);
        return 0;
    }
    int rc = (*env)->RegisterNatives(env, cls, methods, count);
    (*env)->DeleteLocalRef(env, cls);

    if (rc != 0) {
        /* 注册失败：清异常，记录到 logcat，但**不让进程崩溃** */
        (*env)->ExceptionClear(env);
        __android_log_print(ANDROID_LOG_ERROR, "AegisJNI",
                            "RegisterNatives failed for %s (%d methods)",
                            class_name, count);
        return 0;
    }
    return 1;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;

    /* App: com.ce11kjw.aegis.AegisNative */
    int ok_app = register_for_class(env, "com/ce11kjw/aegis/AegisNative",
                                    methods_app,
                                    (int)(sizeof(methods_app)/sizeof(methods_app[0])));

    /* SDK: com.ce11kjw.aegis.sdk.AegisGuard（集成 SDK 时才存在） */
    register_for_class(env, "com/ce11kjw/aegis/sdk/AegisGuard",
                       methods_sdk,
                       (int)(sizeof(methods_sdk)/sizeof(methods_sdk[0])));

    /* 至少注册成功一个才算可用 */
    if (!ok_app) {
        /* App 类没找到时也允许加载（纯 SDK 场景） */
        return JNI_VERSION_1_6;
    }
    return JNI_VERSION_1_6;
}
