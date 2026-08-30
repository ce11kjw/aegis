/*
 * test_engine.c - Aegis 引擎本机测试
 * 编译: gcc -I include -o /tmp/aegis_test test_engine.c 各 src 文件
 * 在 PC 上验证逻辑, 在 Android 上可交叉编译为可执行文件
 */
#include "aegis.h"
#include <stdio.h>

int main(void) {
    aegis_init();
    aegis_config_t cfg = aegis_default_config();
    aegis_result_t results[AEGIS_MAX_RESULTS];
    int count = aegis_run_all(&cfg, results, AEGIS_MAX_RESULTS);
    int score = aegis_score(results, count);

    printf("===== Aegis 引擎检测结果 =====\n");
    printf("总分: %d/100 | 检测项: %d\n\n", score, count);

    for (int i = 0; i < count; i++) {
        const aegis_result_t *r = &results[i];
        printf("[%s] %s | %s | 等级:%s\n",
               r->detected ? "!!" : "--",
               aegis_module_name(r->module), r->name,
               aegis_level_str(r->level));
        if (r->detected)
            printf("    证据: %s\n", r->evidence);
    }
    printf("==============================\n");
    return 0;
}
