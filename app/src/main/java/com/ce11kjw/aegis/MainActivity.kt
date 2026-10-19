package com.ce11kjw.aegis

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ce11kjw.aegis.data.CheckReport
import com.ce11kjw.aegis.ui.screen.HomeScreen
import com.ce11kjw.aegis.ui.screen.KnowledgeScreen
import com.ce11kjw.aegis.ui.screen.SettingsScreen
import com.ce11kjw.aegis.ui.theme.AegisTheme
import com.ce11kjw.aegis.ui.theme.AegisTypography
import com.google.gson.Gson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            AegisTheme {
                MaterialTheme(typography = AegisTypography) {
                    AegisApp()
                }
            }
        }
    }
}

enum class Tab(val label: String, val icon: ImageVector) {
    HOME("检测", Icons.Filled.Shield),
    KNOWLEDGE("知识库", Icons.Filled.MenuBook),
    SETTINGS("设置", Icons.Filled.Settings)
}

@Composable
fun AegisApp() {
    var tab by remember { mutableStateOf(Tab.HOME) }
    var report by remember { mutableStateOf<CheckReport?>(null) }
    var scanning by remember { mutableStateOf(true) }
    val gson = remember { Gson() }

    fun rescan() {
        scanning = true
    }

    // 首次扫描
    LaunchedEffect(Unit) {
        scanning = true
        val json = withContext(Dispatchers.IO) {
            runCatching { AegisNative.runAll() }.getOrNull()
        }
        delay(400)  // 让骨架屏可见，避免闪烁
        report = runCatching { gson.fromJson(json, CheckReport::class.java) }.getOrNull()
        scanning = false
    }

    // 重新扫描
    LaunchedEffect(scanning) {
        if (scanning && report != null) {
            val json = withContext(Dispatchers.IO) {
                runCatching { AegisNative.runAll() }.getOrNull()
            }
            report = runCatching { gson.fromJson(json, CheckReport::class.java) }.getOrNull()
            scanning = false
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            "Aegis",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 20.sp
                        )
                        if (report != null && !scanning) {
                            Spacer(Modifier.width(8.dp))
                            Box(
                                Modifier
                                    .background(
                                        MaterialTheme.colorScheme.primaryContainer,
                                        RoundedCornerShape(4.dp)
                                    )
                                    .padding(horizontal = 6.dp, vertical = 1.dp)
                            ) {
                                Text(
                                    "${report!!.count} 项",
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.onPrimaryContainer
                                )
                            }
                        }
                    }
                },
                actions = {
                    if (tab == Tab.HOME) {
                        IconButton(onClick = { if (!scanning) rescan() }) {
                            Icon(
                                if (scanning) Icons.Filled.HourglassEmpty else Icons.Filled.Refresh,
                                contentDescription = "重新扫描"
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 0.dp
            ) {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        icon = { Icon(t.icon, contentDescription = t.label) },
                        label = { Text(t.label, fontSize = 11.sp) }
                    )
                }
            }
        }
    ) { padding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            AnimatedContent(
                targetState = tab,
                transitionSpec = {
                    (fadeIn(tween(220)) + slideInHorizontally(tween(280)) { it / 12 })
                        .togetherWith(fadeOut(tween(160)))
                },
                label = "tab"
            ) { current ->
                when (current) {
                    Tab.HOME -> HomeScreen(
                        report = report,
                        scanning = scanning,
                        onRescan = { rescan() }
                    )
                    Tab.KNOWLEDGE -> KnowledgeScreen()
                    Tab.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}
