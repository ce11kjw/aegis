package com.ce11kjw.aegis.data

import com.google.gson.annotations.SerializedName

/** 单项检测结果 */
data class CheckItem(
    @SerializedName("module") val module: Int = 0,
    @SerializedName("module_name") val moduleName: String = "",
    @SerializedName("name") val name: String = "",
    @SerializedName("detected") val detected: Int = 0,
    @SerializedName("level") val level: Int = 0,
    @SerializedName("level_str") val levelStr: String = "",
    @SerializedName("evidence") val evidence: String = ""
) {
    val isRisk: Boolean get() = detected == 1
    val status: CheckStatus
        get() = when {
            !isRisk -> CheckStatus.CLEAN
            level >= 3 -> CheckStatus.DANGER
            level >= 2 -> CheckStatus.WARNING
            else -> CheckStatus.INFO
        }
}

enum class CheckStatus { CLEAN, INFO, WARNING, DANGER }

/** 检测报告 */
data class CheckReport(
    @SerializedName("score") val score: Int = 0,
    @SerializedName("count") val count: Int = 0,
    @SerializedName("items") val items: List<CheckItem> = emptyList()
) {
    val riskCount: Int get() = items.count { it.isRisk }
    val dangerCount: Int get() = items.count { it.status == CheckStatus.DANGER }
    val warningCount: Int get() = items.count { it.status == CheckStatus.WARNING }

    /** 按模块分组 */
    fun grouped(): List<Pair<String, List<CheckItem>>> =
        items.groupBy { it.moduleName }
            .map { (k, v) -> k to v.sortedByDescending { it.level } }
            .sortedByDescending { (_, v) -> v.maxOfOrNull { it.level } ?: 0 }
}

/** 模块元数据 */
data class ModuleMeta(
    val id: Int,
    val name: String,
    val icon: String,
    val desc: String
)

val MODULES = listOf(
    ModuleMeta(0, "反调试", "bug", "调试器附加与代码注入"),
    ModuleMeta(1, "Frida注入", "syringe", "动态插桩框架痕迹"),
    ModuleMeta(2, "Xposed/Zygisk", "puzzle", "Hook 框架与模块"),
    ModuleMeta(3, "完整性", "fingerprint", "重打包与篡改"),
    ModuleMeta(4, "模拟器", "smartphone", "虚拟化环境识别"),
    ModuleMeta(5, "Root", "crown", "提权与隐藏方案"),
    ModuleMeta(6, "系统环境", "cpu", "内核与安全策略"),
    ModuleMeta(7, "网络环境", "globe", "代理与证书"),
    ModuleMeta(8, "设备伪造", "smartphone", "改机与属性伪装"),
    ModuleMeta(9, "应用完整性", "shield", "包体篡改与侧载"),
    ModuleMeta(10, "运行时行为", "activity", "UID/线程/句柄异常")
)
