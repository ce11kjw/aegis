package com.ce11kjw.aegis.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// ---- 状态色（全场景统一） ----
val StatusClean   = Color(0xFF22C55E)   // 绿
val StatusInfo    = Color(0xFF3B82F6)   // 蓝
val StatusWarning = Color(0xFFF59E0B)   // 橙
val StatusDanger  = Color(0xFFEF4444)   // 红

// ---- 品牌色 ----
private val AegisCyan = Color(0xFF22D3EE)
private val AegisCyanDark = Color(0xFF0891B2)

private val DarkScheme = darkColorScheme(
    primary = AegisCyan,
    onPrimary = Color(0xFF001F26),
    primaryContainer = Color(0xFF0E3944),
    onPrimaryContainer = Color(0xFFA5F3FC),
    secondary = Color(0xFF94A3B8),
    background = Color(0xFF0B0F14),
    onBackground = Color(0xFFE2E8F0),
    surface = Color(0xFF131A22),
    onSurface = Color(0xFFE2E8F0),
    surfaceVariant = Color(0xFF1C2632),
    onSurfaceVariant = Color(0xFF94A3B8),
    outline = Color(0xFF2A3646),
    outlineVariant = Color(0xFF1E2836),
    error = StatusDanger
)

private val LightScheme = lightColorScheme(
    primary = AegisCyanDark,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCFFAFE),
    onPrimaryContainer = Color(0xFF155E75),
    secondary = Color(0xFF64748B),
    background = Color(0xFFF8FAFC),
    onBackground = Color(0xFF0F172A),
    surface = Color.White,
    onSurface = Color(0xFF0F172A),
    surfaceVariant = Color(0xFFF1F5F9),
    onSurfaceVariant = Color(0xFF64748B),
    outline = Color(0xFFCBD5E1),
    outlineVariant = Color(0xFFE2E8F0),
    error = StatusDanger
)

@Composable
fun AegisTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val scheme = if (darkTheme) DarkScheme else LightScheme
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = scheme.background.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }
    MaterialTheme(colorScheme = scheme, content = content)
}
