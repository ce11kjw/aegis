package com.ce11kjw.aegis.data

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings

/**
 * 已安装应用审计（v4.6，A 模块）
 *
 * ⚠️ 用 Java PackageManager API，不使用任何 shell 命令
 * ⚠️ 不需要 root
 *
 * 检测维度：
 *  1. 侧载应用统计
 *  2. 未知来源安装来源
 *  3. 调试签名应用（debuggable）
 *  4. 双开/分身应用
 *  5. 高危权限组合
 *  6. 设备管理器应用
 *  7. 无障碍服务应用
 *  8. 未知来源安装权限授予情况
 *  9. 包名可疑应用
 * 10. 安装来源统计
 */
object AppAuditor {

    data class AuditResult(
        val name: String,
        val detected: Boolean,
        val level: Int,          // 0=INFO 1=LOW 2=MED 3=HIGH 4=CRIT
        val evidence: String
    )

    /** 已知商店的 installer 包名 */
    private val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",              // Google Play
        "com.xiaomi.market",                // 小米应用商店
        "com.huawei.appmarket",             // 华为应用市场
        "com.oppo.market",                  // OPPO 软件商店
        "com.heytap.market",                // OPPO/一加
        "com.bbk.appstore",                 // vivo 应用商店
        "com.tencent.android.qqdownloader", // 应用宝
        "com.qihoo.appstore",               // 360
        "com.baidu.appsearch",              // 百度
        "com.sec.android.app.samsungapps",  // 三星
    )

    /** 侧载工具（安装 App 的工具，本身也可能是侧载的） */
    private val SIDELOAD_TOOLS = setOf(
        "bin.mt.plus",                      // MT 管理器
        "bin.mt.termex",                    // MT 终端
        "com.termux",                       // Termux
        "com.rosan.installer.x.revived",    // InstallerX
        "com.rosan.installer.x",            // InstallerX
        "np.msdc.bhf",                      // 各种包安装器
        "com.android.packageinstaller",     // 系统包安装器
        "com.google.android.packageinstaller",
        "com.miui.packageinstaller",
    )

    /** 双开/分身 App 包名特征 */
    private val CLONE_PATTERNS = listOf(
        ".clone", ".parallel", ".dual", ".multiapp", ".appclone", ".island"
    )

    /** 高危权限组合（同时持有才算风险） */
    private val HIGH_RISK_PERMS = listOf(
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.PACKAGE_USAGE_STATS",
    )

    /**
     * 执行全部审计
     * @return 每个检测项的结果列表
     */
    fun audit(context: Context): List<AuditResult> {
        val pm = context.packageManager
        val results = mutableListOf<AuditResult>()

        // 获取所有已安装应用（含系统应用，但重点分析第三方）
        val packages = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS or
                    PackageManager.GET_SIGNING_CERTIFICATES)
        } catch (e: Exception) {
            return listOf(AuditResult("应用列表读取", true, 2, "读取失败: ${e.message}"))
        }

        val thirdParty = packages.filter {
            (it.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM == 0
        }

        // ---------- 1. 侧载应用统计 ----------
        val sideloaded = mutableListOf<String>()
        val fromStore = mutableListOf<String>()
        var unknownInstaller = 0

        for (p in thirdParty) {
            val installer = try {
                if (Build.VERSION.SDK_INT >= 30) {
                    pm.getInstallSourceInfo(p.packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    pm.getInstallerPackageName(p.packageName)
                }
            } catch (e: Exception) {
                null
            }

            when {
                installer == null -> {
                    unknownInstaller++
                    sideloaded.add(p.packageName)
                }
                installer in TRUSTED_INSTALLERS -> fromStore.add(p.packageName)
                else -> sideloaded.add(p.packageName)
            }
        }

        results.add(AuditResult(
            "侧载应用统计",
            sideloaded.isNotEmpty(),
            if (sideloaded.size > 20) 2 else 1,
            buildString {
                append("第三方 App ${thirdParty.size} 个：")
                append("商店安装 ${fromStore.size} 个，")
                append("侧载 ${sideloaded.size} 个")
                if (unknownInstaller > 0) append("（其中 ${unknownInstaller} 个 installer 未知）")
                if (sideloaded.isNotEmpty()) {
                    append("\n示例：")
                    append(sideloaded.take(5).joinToString(", "))
                }
            }
        ))

        // ---------- 2. 侧载工具检测 ----------
        val foundTools = mutableListOf<String>()
        for (p in thirdParty) {
            if (p.packageName in SIDELOAD_TOOLS) {
                foundTools.add(p.packageName)
            }
        }
        results.add(AuditResult(
            "侧载工具检测",
            foundTools.isNotEmpty(),
            if (foundTools.isEmpty()) 0 else 1,
            if (foundTools.isEmpty()) "未发现侧载工具"
            else "发现 ${foundTools.size} 个：${foundTools.joinToString(", ")}"
        ))

        // ---------- 3. 调试签名应用 ----------
        val debuggable = thirdParty.filter {
            (it.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_DEBUGGABLE != 0
        }.map { it.packageName }

        results.add(AuditResult(
            "调试签名应用",
            debuggable.isNotEmpty(),
            if (debuggable.isEmpty()) 0 else 2,
            if (debuggable.isEmpty()) "所有第三方 App 均非 debuggable"
            else "发现 ${debuggable.size} 个 debuggable 应用：${debuggable.take(5).joinToString(", ")}"
        ))

        // ---------- 4. 双开/分身应用 ----------
        val clones = thirdParty.filter { p ->
            CLONE_PATTERNS.any { p.packageName.contains(it, true) }
        }.map { it.packageName }

        results.add(AuditResult(
            "双开分身应用",
            clones.isNotEmpty(),
            if (clones.isEmpty()) 0 else 1,
            if (clones.isEmpty()) "未发现双开/分身应用"
            else "发现 ${clones.size} 个：${clones.take(5).joinToString(", ")}"
        ))

        // ---------- 5. 高危权限组合 ----------
        val riskyApps = mutableListOf<String>()
        for (p in thirdParty) {
            val perms = p.requestedPermissions ?: continue
            // 同时持有 SYSTEM_ALERT_WINDOW + 无障碍 才算高危
            val hasOverlay = perms.contains("android.permission.SYSTEM_ALERT_WINDOW")
            val hasA11y = perms.any {
                it.contains("ACCESSIBILITY") || it.contains("BIND_ACCESSIBILITY_SERVICE")
            }
            if (hasOverlay && hasA11y) {
                riskyApps.add(p.packageName)
            }
        }
        results.add(AuditResult(
            "高危权限组合",
            riskyApps.isNotEmpty(),
            if (riskyApps.isEmpty()) 0 else 3,
            if (riskyApps.isEmpty()) "未发现同时持有「悬浮窗 + 无障碍」的应用"
            else "发现 ${riskyApps.size} 个：${riskyApps.joinToString(", ")}"
        ))

        // ---------- 6. 设备管理器应用 ----------
        val admins = try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.activeAdmins?.map { it.packageName } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
        results.add(AuditResult(
            "设备管理器应用",
            admins.isNotEmpty(),
            if (admins.isEmpty()) 0 else 1,
            if (admins.isEmpty()) "无激活的设备管理器"
            else "${admins.size} 个：${admins.joinToString(", ")}"
        ))

        // ---------- 7. 无障碍服务 ----------
        val a11yServices = try {
            val enabled = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: ""
            enabled.split(':').filter { it.isNotBlank() }
        } catch (e: Exception) {
            emptyList()
        }
        results.add(AuditResult(
            "无障碍服务",
            a11yServices.isNotEmpty(),
            if (a11yServices.isEmpty()) 0
            else if (a11yServices.size > 3) 2 else 1,
            if (a11yServices.isEmpty()) "无启用的无障碍服务"
            else "${a11yServices.size} 个：${a11yServices.take(5).joinToString(", ")}"
        ))

        // ---------- 8. 未知来源安装权限 ----------
        val canInstall = thirdParty.count {
            it.requestedPermissions?.contains(
                "android.permission.REQUEST_INSTALL_PACKAGES"
            ) == true
        }
        results.add(AuditResult(
            "未知来源安装权限",
            canInstall > 0,
            if (canInstall == 0) 0 else 1,
            if (canInstall == 0) "无应用申请安装其他应用权限"
            else "$canInstall 个应用申请了「安装未知应用」权限"
        ))

        // ---------- 9. 可疑包名 ----------
        val suspicious = thirdParty.filter { p ->
            val n = p.packageName.lowercase()
            listOf("hack", "crack", "cheat", "mod.", ".mod", "gg.", "gameguardian",
                   "lucky", "patcher", "frida").any { n.contains(it) }
        }.map { it.packageName }
        results.add(AuditResult(
            "可疑包名应用",
            suspicious.isNotEmpty(),
            if (suspicious.isEmpty()) 0 else 3,
            if (suspicious.isEmpty()) "未发现可疑包名"
            else "发现 ${suspicious.size} 个：${suspicious.joinToString(", ")}"
        ))

        // ---------- 10. 安装来源分布 ----------
        val storeRatio = if (thirdParty.isEmpty()) 100
                         else fromStore.size * 100 / thirdParty.size
        results.add(AuditResult(
            "安装来源分布",
            storeRatio < 50,
            if (storeRatio >= 80) 0 else if (storeRatio >= 50) 1 else 2,
            "商店安装占比 $storeRatio%（${fromStore.size}/${thirdParty.size}）"
        ))

        return results
    }
}
