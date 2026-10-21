package com.ce11kjw.aegis.data

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 报告导出（v4.0 新增）
 *
 * 支持三种格式：
 *  - TXT  纯文本，适合阅读/分享
 *  - JSON 结构化，适合程序处理
 *  - HTML 带样式，适合截图分享
 */
object ReportExporter {

    private val ts: String
        get() = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())

    private fun reportDir(context: Context): File {
        val dir = File(context.cacheDir, "reports")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    // ────────────────────────────────────────────────────────
    // TXT
    // ────────────────────────────────────────────────────────
    fun exportTxt(context: Context, report: CheckReport): File {
        val sb = StringBuilder()
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine("  AegisGuard 安全检测报告")
        sb.appendLine("═══════════════════════════════════════")
        sb.appendLine()
        sb.appendLine("生成时间: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA).format(Date())}")
        sb.appendLine("风险评分: ${report.score}/100  (${scoreLevel(report.score)})")
        sb.appendLine("检测项数: ${report.count}")
        sb.appendLine("风险项数: ${report.riskCount}  (严重 ${report.dangerCount} / 警告 ${report.warningCount})")
        sb.appendLine()
        sb.appendLine("───────────────────────────────────────")
        sb.appendLine("  检测详情（按模块）")
        sb.appendLine("───────────────────────────────────────")

        report.grouped().forEach { (moduleName, items) ->
            val riskCount = items.count { it.isRisk }
            sb.appendLine()
            sb.appendLine("【$moduleName】共 ${items.size} 项，命中 $riskCount 项")
            items.forEach { item ->
                val mark = when {
                    !item.isRisk -> "[ OK ]"
                    item.level >= 3 -> "[严重]"
                    item.level >= 2 -> "[警告]"
                    else -> "[提示]"
                }
                sb.appendLine("  $mark ${item.name}")
                if (item.isRisk && item.evidence.isNotBlank()) {
                    sb.appendLine("        证据: ${item.evidence}")
                }
            }
        }

        sb.appendLine()
        sb.appendLine("───────────────────────────────────────")
        sb.appendLine("  声明")
        sb.appendLine("───────────────────────────────────────")
        sb.appendLine("本报告由 AegisGuard 本地生成，未上传任何数据。")
        sb.appendLine("检测结果仅供参考，部分定制 ROM 上可能存在误报。")

        val f = File(reportDir(context), "aegis-report-$ts.txt")
        f.writeText(sb.toString(), Charsets.UTF_8)
        return f
    }

    // ────────────────────────────────────────────────────────
    // JSON
    // ────────────────────────────────────────────────────────
    fun exportJson(context: Context, report: CheckReport): File {
        val sb = StringBuilder()
        sb.appendLine("{")
        sb.appendLine("  \"generator\": \"AegisGuard\",")
        sb.appendLine("  \"timestamp\": \"${SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.US).format(Date())}\",")
        sb.appendLine("  \"score\": ${report.score},")
        sb.appendLine("  \"level\": \"${scoreLevel(report.score)}\",")
        sb.appendLine("  \"count\": ${report.count},")
        sb.appendLine("  \"riskCount\": ${report.riskCount},")
        sb.appendLine("  \"modules\": [")

        val grouped = report.grouped()
        grouped.forEachIndexed { mi, (moduleName, items) ->
            sb.appendLine("    {")
            sb.appendLine("      \"name\": \"${esc(moduleName)}\",")
            sb.appendLine("      \"items\": [")
            items.forEachIndexed { ii, item ->
                sb.append("        {")
                sb.append("\"name\": \"${esc(item.name)}\", ")
                sb.append("\"detected\": ${item.isRisk},")
                sb.append(" \"level\": ${item.level},")
                sb.append(" \"levelStr\": \"${esc(item.levelStr)}\"")
                if (item.evidence.isNotBlank()) {
                    sb.append(", \"evidence\": \"${esc(item.evidence)}\"")
                }
                sb.append("}")
                if (ii < items.size - 1) sb.append(",")
                sb.appendLine()
            }
            sb.appendLine("      ]")
            sb.append("    }")
            if (mi < grouped.size - 1) sb.append(",")
            sb.appendLine()
        }

        sb.appendLine("  ]")
        sb.appendLine("}")

        val f = File(reportDir(context), "aegis-report-$ts.json")
        f.writeText(sb.toString(), Charsets.UTF_8)
        return f
    }

    // ────────────────────────────────────────────────────────
    // HTML（适合截图分享）
    // ────────────────────────────────────────────────────────
    fun exportHtml(context: Context, report: CheckReport): File {
        val levelColor = when {
            report.score >= 70 -> "#EF4444"
            report.score >= 30 -> "#F59E0B"
            report.score >= 10 -> "#3B82F6"
            else -> "#22C55E"
        }

        val sb = StringBuilder()
        sb.appendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
        sb.appendLine("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        sb.appendLine("<title>AegisGuard 检测报告</title>")
        sb.appendLine("<style>")
        sb.appendLine("""
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                   background: #0B0F14; color: #E2E8F0; margin: 0; padding: 20px;
                   line-height: 1.6; }
            .header { text-align: center; padding: 30px 0; }
            .score { font-size: 64px; font-weight: 700; color: $levelColor; }
            .level { font-size: 20px; color: $levelColor; margin-top: 8px; }
            .meta { color: #94A3B8; font-size: 13px; margin-top: 12px; }
            .module { background: #131A22; border-radius: 12px; padding: 16px;
                      margin-bottom: 12px; }
            .module h3 { margin: 0 0 12px; font-size: 14px; color: #94A3B8;
                         font-weight: 600; letter-spacing: 0.5px; }
            .item { display: flex; padding: 8px 0; border-bottom: 1px solid #1E2836;
                    font-size: 13px; }
            .item:last-child { border-bottom: none; }
            .dot { width: 8px; height: 8px; border-radius: 50%; margin-top: 7px;
                   margin-right: 10px; flex-shrink: 0; }
            .ok { background: #22C55E; }
            .med { background: #F59E0B; }
            .high { background: #EF4444; }
            .name { flex: 1; }
            .ev { color: #94A3B8; font-size: 11px; margin-top: 3px; }
            .footer { text-align: center; color: #64748B; font-size: 11px;
                      margin-top: 30px; padding-top: 20px;
                      border-top: 1px solid #1E2836; }
        """.trimIndent())
        sb.appendLine("</style></head><body>")

        sb.appendLine("<div class=\"header\">")
        sb.appendLine("<div class=\"score\">${report.score}</div>")
        sb.appendLine("<div class=\"level\">${scoreLevel(report.score)}</div>")
        sb.appendLine("<div class=\"meta\">${report.count} 项检测 · ${report.riskCount} 项命中</div>")
        sb.appendLine("<div class=\"meta\">${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA).format(Date())}</div>")
        sb.appendLine("</div>")

        report.grouped().forEach { (moduleName, items) ->
            sb.appendLine("<div class=\"module\">")
            sb.appendLine("<h3>${esc(moduleName)} · ${items.size} 项</h3>")
            items.forEach { item ->
                val cls = when {
                    !item.isRisk -> "ok"
                    item.level >= 3 -> "high"
                    else -> "med"
                }
                sb.appendLine("<div class=\"item\">")
                sb.appendLine("<div class=\"dot $cls\"></div>")
                sb.appendLine("<div class=\"name\">${esc(item.name)}")
                if (item.isRisk && item.evidence.isNotBlank()) {
                    sb.appendLine("<div class=\"ev\">${esc(item.evidence)}</div>")
                }
                sb.appendLine("</div></div>")
            }
            sb.appendLine("</div>")
        }

        sb.appendLine("<div class=\"footer\">")
        sb.appendLine("AegisGuard · 本地检测 · 不上传数据")
        sb.appendLine("</div></body></html>")

        val f = File(reportDir(context), "aegis-report-$ts.html")
        f.writeText(sb.toString(), Charsets.UTF_8)
        return f
    }

    // ────────────────────────────────────────────────────────
    // 分享
    // ────────────────────────────────────────────────────────
    fun share(context: Context, file: File) {
        val uri: Uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file
        )
        val mime = when (file.extension) {
            "json" -> "application/json"
            "html" -> "text/html"
            else -> "text/plain"
        }
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, "分享检测报告"))
    }

    // ────────────────────────────────────────────────────────
    private fun esc(s: String): String = s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    fun scoreLevel(score: Int): String = when {
        score >= 90 -> "严重风险"
        score >= 70 -> "危险"
        score >= 50 -> "存在风险"
        score >= 30 -> "可疑"
        score >= 10 -> "轻微异常"
        else -> "环境安全"
    }
}
