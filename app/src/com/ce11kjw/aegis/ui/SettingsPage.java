package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * SettingsPage - 设置页
 * 关于引擎 / 检测模块开关说明 / 导出报告入口
 */
public class SettingsPage extends LinearLayout {

    public SettingsPage(Context context) {
        super(context);
        setOrientation(LinearLayout.VERTICAL);
        setPadding(dp(20), dp(16), dp(20), dp(16));

        TextView title = new TextView(context);
        title.setText("设置");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(24);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        addView(title);

        // ===== 引擎信息卡 =====
        GlassCard infoCard = new GlassCard(context);
        addInfoRow(infoCard, "引擎名称", "Aegis 安全检测引擎");
        addInfoRow(infoCard, "版本", "v2.0.0 (versionCode 3)");
        addInfoRow(infoCard, "检测模块", "7 大模块 · 37 项检测");
        addInfoRow(infoCard, "实现层", "Native C (libaegis.so)");
        addInfoRow(infoCard, "架构", "arm64-v8a / armeabi-v7a / x86_64");
        LinearLayout.LayoutParams infoLp = new LinearLayout.LayoutParams(-1, -2);
        infoLp.topMargin = dp(20);
        addView(infoCard, infoLp);

        // ===== 模块说明卡 =====
        GlassCard modCard = new GlassCard(context);
        TextView modTitle = new TextView(context);
        modTitle.setText("检测模块说明");
        modTitle.setTextColor(Color.parseColor("#E2E8F0"));
        modTitle.setTextSize(15);
        modTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        modCard.inner().addView(modTitle);
        addInfoRow(modCard, "反调试", "TracerPid / ptrace / 调试器进程");
        addInfoRow(modCard, "Frida注入", "内存映射 / D-Bus端口 / 特征线程");
        addInfoRow(modCard, "Xposed/Zygisk", "native.bridge / 模块路径");
        addInfoRow(modCard, "完整性", "哈希校验 / W+X权限 / 可执行映射");
        addInfoRow(modCard, "模拟器", "Build / 硬件 / 传感器 / 属性联动");
        addInfoRow(modCard, "Root", "su二进制 / Magisk / KernelSU");
        addInfoRow(modCard, "系统环境", "debuggable / SELinux / CapEff");
        LinearLayout.LayoutParams modLp = new LinearLayout.LayoutParams(-1, -2);
        modLp.topMargin = dp(16);
        addView(modCard, modLp);

        // ===== 关于 =====
        GlassCard aboutCard = new GlassCard(context);
        TextView aboutTitle = new TextView(context);
        aboutTitle.setText("关于");
        aboutTitle.setTextColor(Color.parseColor("#E2E8F0"));
        aboutTitle.setTextSize(15);
        aboutTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        aboutCard.inner().addView(aboutTitle);

        TextView about = new TextView(context);
        about.setText("Aegis Guard 是一套设备安全环境检测工具。\n\n"
            + "所有检测逻辑运行在 Native 层, 覆盖反调试、注入检测、完整性校验、"
            + "模拟器识别、Root 检测与系统环境审计, 用于评估当前设备运行环境的可信度。");
        about.setTextColor(Color.parseColor("#94A3B8"));
        about.setTextSize(13);
        about.setLineSpacing(dp(2), 1.2f);
        LinearLayout.LayoutParams aboutLp = new LinearLayout.LayoutParams(-1, -2);
        aboutLp.topMargin = dp(6);
        aboutCard.inner().addView(about, aboutLp);
        addView(aboutCard, modLp);

        // 页脚
        TextView footer = new TextView(context);
        footer.setText("AegisGuard © 2026 · Powered by Aegis Engine");
        footer.setTextColor(Color.parseColor("#475569"));
        footer.setTextSize(11);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, dp(24), 0, 0);
        addView(footer);
    }

    private void addInfoRow(GlassCard card, String label, String value) {
        LinearLayout row = new LinearLayout(getContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(0, dp(5), 0, dp(5));

        TextView l = new TextView(getContext());
        l.setText(label);
        l.setTextColor(Color.parseColor("#64748B"));
        l.setTextSize(13);
        LinearLayout.LayoutParams lLp = new LinearLayout.LayoutParams(0, -2, 1);
        row.addView(l, lLp);

        TextView v = new TextView(getContext());
        v.setText(value);
        v.setTextColor(Color.parseColor("#CBD5E1"));
        v.setTextSize(13);
        v.setGravity(Gravity.RIGHT);
        row.addView(v, new LinearLayout.LayoutParams(-2, -2));

        card.inner().addView(row);
    }

    private int dp(float v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }
}
