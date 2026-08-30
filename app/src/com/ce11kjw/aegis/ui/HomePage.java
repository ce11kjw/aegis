package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * HomePage - 首页
 * 大标题 + 状态玻璃卡 + 一键检测 + 快捷风险提示
 */
public class HomePage extends LinearLayout {

    private TextView scoreText, statusText, riskText;
    private Runnable onScan;

    public HomePage(Context context, Runnable scanAction) {
        super(context);
        this.onScan = scanAction;
        setOrientation(LinearLayout.VERTICAL);
        setPadding(dp(20), dp(16), dp(20), dp(16));

        // ===== 顶部标题区 =====
        TextView eyebrow = new TextView(context);
        eyebrow.setText("SECURITY ENGINE");
        eyebrow.setTextColor(Color.parseColor("#22D3EE"));
        eyebrow.setTextSize(11);
        eyebrow.setTypeface(Typeface.MONOSPACE);
        eyebrow.setLetterSpacing(0.15f);
        addView(eyebrow);

        TextView title = new TextView(context);
        title.setText("Aegis Guard");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(30);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        addView(title);

        TextView sub = new TextView(context);
        sub.setText("设备安全环境检测 · v2.0.0");
        sub.setTextColor(Color.parseColor("#94A3B8"));
        sub.setTextSize(13);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.bottomMargin = dp(24);
        addView(sub, subLp);

        // ===== 状态玻璃卡 =====
        GlassCard statusCard = new GlassCard(context);
        statusText = new TextView(context);
        statusText.setText("尚未检测");
        statusText.setTextColor(Color.parseColor("#E2E8F0"));
        statusText.setTextSize(18);
        statusText.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        statusCard.inner().addView(statusText);

        scoreText = new TextView(context);
        scoreText.setText("--");
        scoreText.setTextColor(Color.parseColor("#64748B"));
        scoreText.setTextSize(52);
        scoreText.setTypeface(Typeface.MONOSPACE);
        scoreText.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        LinearLayout.LayoutParams scoreLp = new LinearLayout.LayoutParams(-1, -2);
        scoreLp.topMargin = dp(4);
        statusCard.inner().addView(scoreText, scoreLp);

        riskText = new TextView(context);
        riskText.setText("点击下方按钮开始检测");
        riskText.setTextColor(Color.parseColor("#64748B"));
        riskText.setTextSize(13);
        LinearLayout.LayoutParams riskLp = new LinearLayout.LayoutParams(-1, -2);
        riskLp.topMargin = dp(4);
        statusCard.inner().addView(riskText, riskLp);

        LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
        cardLp.bottomMargin = dp(20);
        addView(statusCard, cardLp);

        // ===== 一键检测按钮 (胶囊 + 内嵌箭头圆) =====
        Button scanBtn = new Button(context);
        scanBtn.setText("开始安全检测");
        scanBtn.setTextColor(Color.parseColor("#0A0F1A"));
        scanBtn.setTextSize(16);
        scanBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        scanBtn.setBackground(roundRect(Color.parseColor("#22D3EE"), dp(28)));
        scanBtn.setOnClickListener(new OnClickListener() {
            @Override public void onClick(android.view.View v) {
                if (onScan != null) onScan.run();
            }
        });
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(-1, dp(56));
        btnLp.bottomMargin = dp(20);
        addView(scanBtn, btnLp);

        // ===== 快捷提示 =====
        TextView hint = new TextView(context);
        hint.setText("检测项覆盖: 反调试 · Frida注入 · Xposed · 完整性 · 模拟器 · Root · 系统环境");
        hint.setTextColor(Color.parseColor("#64748B"));
        hint.setTextSize(11);
        hint.setTypeface(Typeface.MONOSPACE);
        addView(hint);
    }

    /** 更新检测结果 */
    public void updateResult(int score, int detectedCount, int totalCount) {
        scoreText.setText(String.valueOf(score));
        // 风险色阶
        String color;
        String risk;
        if (score < 30) {
            color = "#34D399"; risk = "环境安全";
            statusText.setText("检测完成 · 环境安全");
        } else if (score < 60) {
            color = "#F59E0B"; risk = "存在风险";
            statusText.setText("检测完成 · 存在风险");
        } else {
            color = "#EF4444"; risk = "高风险环境";
            statusText.setText("检测完成 · 高风险环境");
        }
        scoreText.setTextColor(Color.parseColor(color));
        riskText.setText(risk + " · 命中 " + detectedCount + "/" + totalCount + " 项风险");
        riskText.setTextColor(Color.parseColor(color));
    }

    private android.graphics.drawable.GradientDrawable roundRect(int color, int radius) {
        android.graphics.drawable.GradientDrawable g =
            new android.graphics.drawable.GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(radius);
        return g;
    }

    private int dp(float v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }
}
