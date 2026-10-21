package com.ce11kjw.aegis.data

import android.content.Context

/**
 * 审计桥接（v4.6）
 *
 * 把 Java 侧的 AppAuditor / SystemAuditor 结果
 * 转换成与引擎 JSON 相同的 CheckItem 结构，
 * 便于统一展示。
 *
 * 模块 ID：
 *  11 = 应用审计（AppAuditor）
 *  12 = 系统配置（SystemAuditor）
 */
object AuditBridge {

    /**
     * 运行全部 Java 审计，返回 CheckItem 列表
     */
    fun run(context: Context, enabled: Set<Int>): List<CheckItem> {
        val out = mutableListOf<CheckItem>()

        // 应用审计
        if (11 in enabled) {
            try {
                AppAuditor.audit(context).forEach { r ->
                    out.add(CheckItem(
                        module = 11,
                        moduleName = "应用审计",
                        name = r.name,
                        detected = if (r.detected) 1 else 0,
                        level = r.level,
                        levelStr = levelName(r.level),
                        evidence = r.evidence
                    ))
                }
            } catch (e: Exception) {
                out.add(CheckItem(
                    module = 11, moduleName = "应用审计",
                    name = "应用审计异常",
                    detected = 1, level = 2, levelStr = "中",
                    evidence = "审计失败: ${e.message}"
                ))
            }
        }

        // 系统配置
        if (12 in enabled) {
            try {
                SystemAuditor.audit(context).forEach { r ->
                    out.add(CheckItem(
                        module = 12,
                        moduleName = "系统配置",
                        name = r.name,
                        detected = if (r.detected) 1 else 0,
                        level = r.level,
                        levelStr = levelName(r.level),
                        evidence = r.evidence
                    ))
                }
            } catch (e: Exception) {
                out.add(CheckItem(
                    module = 12, moduleName = "系统配置",
                    name = "系统配置审计异常",
                    detected = 1, level = 2, levelStr = "中",
                    evidence = "审计失败: ${e.message}"
                ))
            }
        }

        return out
    }

    private fun levelName(lv: Int): String = when (lv) {
        0 -> "信息"
        1 -> "低"
        2 -> "中"
        3 -> "高"
        4 -> "严重"
        else -> "未知"
    }
}
