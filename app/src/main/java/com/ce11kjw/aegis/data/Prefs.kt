package com.ce11kjw.aegis.data

import android.content.Context
import androidx.core.content.edit

/**
 * 本地设置持久化（v4.2）
 *
 * 用 SharedPreferences 而非 DataStore：
 *  - 依赖少（core-ktx 已含）
 *  - 同步读取，避免首帧闪烁
 *  - 配置项少（只有模块开关集合），无需异步
 */
object Prefs {
    private const val NAME = "aegis_prefs"
    private const val KEY_MODULES = "enabled_modules"

    private fun sp(ctx: Context) = ctx.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    /** 读取已启用的模块 ID 集合；首次返回全开 */
    fun loadModules(ctx: Context): Set<Int> {
        val all = MODULES.map { it.id }.toSet()
        val saved = sp(ctx).getString(KEY_MODULES, null) ?: return all
        if (saved.isBlank()) return emptySet()
        val set = saved.split(",").mapNotNull { it.trim().toIntOrNull() }.toSet()
        // 过滤掉已不存在的模块 ID（版本升级后模块可能变化）
        return set.intersect(all)
    }

    /** 保存模块开关 */
    fun saveModules(ctx: Context, modules: Set<Int>) {
        sp(ctx).edit {
            putString(KEY_MODULES, modules.sorted().joinToString(","))
        }
    }
}
