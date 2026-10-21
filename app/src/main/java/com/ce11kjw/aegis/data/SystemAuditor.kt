package com.ce11kjw.aegis.data

import android.content.Context
import android.os.Build
import android.provider.Settings

/**
 * 系统配置审计（v4.6，B 模块）
 *
 * Java 部分（Settings API）：
 *  1. adb_enabled
 *  2. development_settings_enabled
 *  3. mock_location
 *  4. install_non_market_apps
 *
 * C 部分（引擎已有的系统检测模块会补充）：
 *  5. 安全补丁级别
 *  6. 加密状态
 *  7. 系统属性完整性
 *
 * ⚠️ 全部无需 root
 */
object SystemAuditor {

    data class AuditResult(
        val name: String,
        val detected: Boolean,
        val level: Int,
        val evidence: String
    )

    fun audit(context: Context): List<AuditResult> {
        val r = mutableListOf<AuditResult>()
        val cr = context.contentResolver

        fun globalInt(key: String, def: Int = -1): Int = try {
            Settings.Global.getInt(cr, key, def)
        } catch (e: Exception) { def }

        fun secureInt(key: String, def: Int = -1): Int = try {
            Settings.Secure.getInt(cr, key, def)
        } catch (e: Exception) { def }

        fun secureStr(key: String): String = try {
            Settings.Secure.getString(cr, key) ?: ""
        } catch (e: Exception) { "" }

        // ---------- 1. ADB 调试 ----------
        val adb = globalInt("adb_enabled")
        r.add(AuditResult(
            "ADB 调试",
            adb == 1,
            if (adb == 1) 2 else 0,
            if (adb == 1) "ADB 调试已开启（USB 调试）—— 攻击者可完整控制设备"
            else "ADB 调试已关闭 ✓"
        ))

        // ---------- 2. 开发者选项 ----------
        val dev = globalInt("development_settings_enabled")
        r.add(AuditResult(
            "开发者选项",
            dev == 1,
            if (dev == 1) 1 else 0,
            if (dev == 1) "开发者选项已开启（通常与 ADB 一起使用）"
            else "开发者选项已关闭 ✓"
        ))

        // ---------- 3. 模拟定位 ----------
        val mock = secureInt("mock_location")
        val mockApps = globalInt("mock_location_opaque") // Android 12+ 用这个
        val mockDetected = mock == 1 || mockApps > 0
        r.add(AuditResult(
            "模拟定位",
            mockDetected,
            if (mockDetected) 2 else 0,
            when {
                mock == 1 -> "已允许模拟位置（旧版开关）"
                mockApps > 0 -> "$mockApps 个应用被授予模拟位置权限"
                else -> "未启用模拟定位 ✓"
            }
        ))

        // ---------- 4. 未知来源安装 ----------
        val nonMarket = secureInt("install_non_market_apps")
        r.add(AuditResult(
            "未知来源安装",
            nonMarket == 1,
            if (nonMarket == 1) 1 else 0,
            if (nonMarket == 1) "允许安装未知来源应用（侧载风险）"
            else "仅允许商店安装 ✓"
        ))

        // ---------- 5. USB 调试（与 ADB 独立的状态位）----------
        val usbDebug = globalInt("usb_mass_storage_enabled")
        r.add(AuditResult(
            "USB 大容量存储",
            usbDebug == 1,
            if (usbDebug == 1) 1 else 0,
            if (usbDebug == 1) "USB 存储已启用（数据可被读取）"
            else "USB 存储未启用 ✓"
        ))

        // ---------- 6. 通知监听服务 ----------
        val notifListeners = secureStr("enabled_notification_listeners")
        val listenerCount = notifListeners.split(':').count { it.isNotBlank() }
        r.add(AuditResult(
            "通知读取权限",
            listenerCount > 0,
            if (listenerCount > 2) 2 else if (listenerCount > 0) 1 else 0,
            if (listenerCount == 0) "无应用可读取通知 ✓"
            else "$listenerCount 个应用可读取所有通知（含验证码）"
        ))

        // ---------- 7. 输入法 ----------
        val ime = secureStr("default_input_method")
        r.add(AuditResult(
            "当前输入法",
            ime.contains("sogou") || ime.contains("baidu") || ime.contains("iflytek"),
            1,
            if (ime.isBlank()) "未检测到输入法"
            else "默认输入法：${ime.substringAfterLast('/')}"
        ))

        // ---------- 8. 安全补丁级别（C 层也会查，这里用 Build 属性）----------
        val patch = if (Build.VERSION.SDK_INT >= 23) Build.VERSION.SECURITY_PATCH else ""
        val patchOld = isPatchOld(patch)
        r.add(AuditResult(
            "安全补丁级别",
            patchOld,
            if (patchOld) 2 else 0,
            if (patch.isBlank()) "无法读取补丁级别"
            else "补丁日期：$patch" + if (patchOld) "（超过 1 年未更新）" else " ✓"
        ))

        // ---------- 9. 系统版本 ----------
        r.add(AuditResult(
            "系统版本",
            Build.VERSION.SDK_INT < 33,
            if (Build.VERSION.SDK_INT < 30) 2 else if (Build.VERSION.SDK_INT < 33) 1 else 0,
            "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        ))

        // ---------- 10. 屏幕锁定 ----------
        val lockEnabled = try {
            val km = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
            km.isDeviceSecure
        } catch (e: Exception) { null }
        r.add(AuditResult(
            "屏幕锁定",
            lockEnabled == false,
            if (lockEnabled == false) 3 else 0,
            when (lockEnabled) {
                true -> "已设置锁屏密码/PIN/图案 ✓"
                false -> "未设置任何锁屏保护（高风险）"
                null -> "无法检测锁屏状态"
            }
        ))

        return r
    }

    /** 判断安全补丁是否超过 1 年 */
    private fun isPatchOld(patch: String): Boolean {
        if (patch.length < 7) return false
        return try {
            val y = patch.substring(0, 4).toInt()
            val m = patch.substring(5, 7).toInt()
            val nowY = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR)
            val nowM = java.util.Calendar.getInstance().get(java.util.Calendar.MONTH) + 1
            val months = (nowY - y) * 12 + (nowM - m)
            months > 12
        } catch (e: Exception) { false }
    }
}
