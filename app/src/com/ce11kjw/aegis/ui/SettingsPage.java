package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.ImageView;
import com.ce11kjw.aegis.ui.IconView;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * SettingsPage - 设置页 (第三页)
 * 报告中心 / 外观 / 关于引擎
 */
public class SettingsPage extends LinearLayout {

    private TextView recentScore, recentTime;
    private JSONArray lastItems;
    private int lastScore = 0;
    private Runnable onExport;

    public SettingsPage(Context context, Runnable exportAction) {
        super(context);
        this.onExport = exportAction;
        setOrientation(LinearLayout.VERTICAL);

        ScrollView scroll = new ScrollView(context);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        addView(scroll, new LayoutParams(-1, -1));

        LinearLayout content = new LinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(16), dp(20), dp(16));
        scroll.addView(content);

        // ===== 页头 =====
        TextView eyebrow = new TextView(context);
        eyebrow.setText("SETTINGS");
        eyebrow.setTextColor(Color.parseColor("#22D3EE"));
        eyebrow.setTextSize(11);
        eyebrow.setTypeface(Typeface.MONOSPACE);
        eyebrow.setLetterSpacing(0.15f);
        content.addView(eyebrow);

        TextView title = new TextView(context);
        title.setText("设置");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(26);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        content.addView(title);

        // ===== 📊 报告中心 =====
        LinearLayout sec1row = new LinearLayout(context);
        sec1row.setOrientation(LinearLayout.HORIZONTAL);
        sec1row.setGravity(Gravity.CENTER_VERTICAL);
        ImageView sec1ic = new ImageView(context);
        sec1ic.setImageResource(IconView.ACT_DOWNLOAD);
        int s1sz = dp(14);
        sec1ic.setLayoutParams(new LinearLayout.LayoutParams(s1sz, s1sz));
        sec1ic.setColorFilter(Color.parseColor("#22D3EE"));
        sec1row.addView(sec1ic);
        TextView sec1 = new TextView(context);
        sec1.setText("报告中心");
        sec1.setTextColor(Color.parseColor("#94A3B8"));
        sec1.setTextSize(12);
        sec1.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams s1l = new LinearLayout.LayoutParams(-2, -2);
        s1l.leftMargin = dp(6);
        sec1row.addView(sec1, s1l);
        LinearLayout.LayoutParams s1rowLp = new LinearLayout.LayoutParams(-1, -2);
        s1rowLp.topMargin = dp(20);
        s1rowLp.bottomMargin = dp(8);
        content.addView(sec1row, s1rowLp);
        sec1.setTextColor(Color.parseColor("#94A3B8"));
        sec1.setTextSize(12);
        sec1.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams secLp = new LinearLayout.LayoutParams(-1, -2);
        secLp.topMargin = dp(20);
        secLp.bottomMargin = dp(8);


        GlassCard reportCard = new GlassCard(context);
        // 最近检测状态
        recentScore = new TextView(context);
        recentScore.setText("最近检测: 尚未检测");
        recentScore.setTextColor(Color.parseColor("#CBD5E1"));
        recentScore.setTextSize(15);
        recentScore.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        reportCard.inner().addView(recentScore);

        recentTime = new TextView(context);
        recentTime.setText("点击首页开始检测");
        recentTime.setTextColor(Color.parseColor("#64748B"));
        recentTime.setTextSize(12);
        LinearLayout.LayoutParams rtLp = new LinearLayout.LayoutParams(-1, -2);
        rtLp.topMargin = dp(4);
        reportCard.inner().addView(recentTime, rtLp);

        // 导出按钮
        Button exportBtn = new Button(context);
        exportBtn.setText("导出检测报告");
        exportBtn.setTextColor(Color.parseColor("#0A0F1A"));
        exportBtn.setTextSize(14);
        exportBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        exportBtn.setBackground(roundRect(Color.parseColor("#22D3EE"), dp(24)));
        exportBtn.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                if (onExport != null) onExport.run();
                else Toast.makeText(getContext(), "请先完成一次检测", Toast.LENGTH_SHORT).show();
            }
        });
        LinearLayout.LayoutParams expLp = new LinearLayout.LayoutParams(-1, dp(48));
        expLp.topMargin = dp(12);
        reportCard.inner().addView(exportBtn, expLp);

        content.addView(reportCard, new LinearLayout.LayoutParams(-1, -2));

        // ===== 🎨 外观 =====
        TextView sec2 = new TextView(context);
        sec2.setText("外观");
        sec2.setTextColor(Color.parseColor("#94A3B8"));
        sec2.setTextSize(12);
        sec2.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams sec2Lp = new LinearLayout.LayoutParams(-1, -2);
        sec2Lp.topMargin = dp(20);
        sec2Lp.bottomMargin = dp(8);
        content.addView(sec2, sec2Lp);

        GlassCard lookCard = new GlassCard(context);
        addInfoRow(lookCard, "界面风格", "深色 · 双层玻璃");
        addInfoRow(lookCard, "强调色", "青蓝 #22D3EE");
        addInfoRow(lookCard, "背景", "渐变 #0A0F1A → #131B2E");
        content.addView(lookCard, new LinearLayout.LayoutParams(-1, -2));

        // ===== 📋 关于引擎 =====
        TextView sec3 = new TextView(context);
        sec3.setText("关于引擎");
        sec3.setTextColor(Color.parseColor("#94A3B8"));
        sec3.setTextSize(12);
        sec3.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams sec3Lp = new LinearLayout.LayoutParams(-1, -2);
        sec3Lp.topMargin = dp(20);
        sec3Lp.bottomMargin = dp(8);
        content.addView(sec3, sec3Lp);

        GlassCard aboutCard = new GlassCard(context);
        addInfoRow(aboutCard, "引擎名称", "Aegis 安全检测引擎");
        addInfoRow(aboutCard, "引擎版本", "v3.2.0");
        addInfoRow(aboutCard, "检测模块", "8 大模块 · 105 项");
        addInfoRow(aboutCard, "实现层", "Native C (libaegis.so)");
        addInfoRow(aboutCard, "支持架构", "arm64 / armv7 / x86_64");
        addInfoRow(aboutCard, "APK 版本", "versionCode 7");
        content.addView(aboutCard, new LinearLayout.LayoutParams(-1, -2));

        // 隐私说明卡
        GlassCard privacyCard = new GlassCard(context);
        TextView privTitle = new TextView(context);
        privTitle.setText("隐私说明");
        privTitle.setTextColor(Color.parseColor("#E2E8F0"));
        privTitle.setTextSize(15);
        privTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        privacyCard.inner().addView(privTitle);

        TextView priv = new TextView(context);
        priv.setText("所有检测均在设备本地完成, 不联网、不上传任何数据。\n"
            + "检测结果仅保存在当前会话中, 点击导出才复制到剪贴板。");
        priv.setTextColor(Color.parseColor("#94A3B8"));
        priv.setTextSize(13);
        priv.setLineSpacing(dp(2), 1.2f);
        LinearLayout.LayoutParams privLp = new LinearLayout.LayoutParams(-1, -2);
        privLp.topMargin = dp(6);
        privacyCard.inner().addView(priv, privLp);
        LinearLayout.LayoutParams pcLp = new LinearLayout.LayoutParams(-1, -2);
        pcLp.topMargin = dp(16);
        content.addView(privacyCard, pcLp);

        // ===== 页脚 =====
        TextView footer = new TextView(context);
        footer.setText("AegisGuard © 2026 · Powered by Aegis Engine");
        footer.setTextColor(Color.parseColor("#475569"));
        footer.setTextSize(11);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, dp(24), 0, dp(8));
        content.addView(footer);
    }

    /** 更新最近检测信息 */
    public void updateReport(int score, JSONArray items) {
        lastScore = score;
        lastItems = items;
        recentScore.setText("最近检测: 得分 " + score + "/100");
        recentScore.setTextColor(score < 30 ? Color.parseColor("#34D399")
            : score < 60 ? Color.parseColor("#F59E0B") : Color.parseColor("#EF4444"));
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("MM-dd HH:mm:ss");
        recentTime.setText("检测时间: " + sdf.format(new java.util.Date())
            + " · " + (items != null ? items.length() : 0) + " 项");
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
        v.setTypeface(Typeface.MONOSPACE);
        row.addView(v, new LinearLayout.LayoutParams(-2, -2));

        card.inner().addView(row);
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
