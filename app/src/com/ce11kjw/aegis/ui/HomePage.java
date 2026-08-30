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
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * HomePage - 首页 (检测 + 结果一体, 可滚动)
 * 标题 / 得分卡 / 开始检测按钮 / 检测结果(模块折叠+详情展开)
 */
public class HomePage extends LinearLayout {

    private TextView scoreText, statusText, riskText;
    private LinearLayout resultsContainer;
    private TextView resultTitle;
    private Runnable onScan;

    public HomePage(Context context, Runnable scanAction) {
        super(context);
        this.onScan = scanAction;
        setOrientation(LinearLayout.VERTICAL);

        // ===== 滚动容器 =====
        ScrollView scroll = new ScrollView(context);
        scroll.setFillViewport(true);
        scroll.setVerticalScrollBarEnabled(false);
        addView(scroll, new LayoutParams(-1, -1));

        LinearLayout content = new LinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(20), dp(16), dp(20), dp(16));
        scroll.addView(content);

        // ===== 顶部标题区 =====
        TextView eyebrow = new TextView(context);
        eyebrow.setText("SECURITY ENGINE");
        eyebrow.setTextColor(Color.parseColor("#22D3EE"));
        eyebrow.setTextSize(11);
        eyebrow.setTypeface(Typeface.MONOSPACE);
        eyebrow.setLetterSpacing(0.15f);
        content.addView(eyebrow);

        TextView title = new TextView(context);
        title.setText("Aegis Guard");
        title.setTextColor(Color.parseColor("#F8FAFC"));
        title.setTextSize(30);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        content.addView(title);

        TextView sub = new TextView(context);
        sub.setText("设备安全环境检测 · v3.0.0");
        sub.setTextColor(Color.parseColor("#94A3B8"));
        sub.setTextSize(13);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(-1, -2);
        subLp.bottomMargin = dp(24);
        content.addView(sub, subLp);

        // ===== 得分玻璃卡 =====
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
        content.addView(statusCard, cardLp);

        // ===== 一键检测按钮 =====
        Button scanBtn = new Button(context);
        scanBtn.setText("开始安全检测");
        scanBtn.setTextColor(Color.parseColor("#0A0F1A"));
        scanBtn.setTextSize(16);
        scanBtn.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        scanBtn.setBackground(roundRect(Color.parseColor("#22D3EE"), dp(28)));
        scanBtn.setOnClickListener(new OnClickListener() {
            @Override public void onClick(View v) {
                if (onScan != null) onScan.run();
            }
        });
        LinearLayout.LayoutParams btnLp = new LinearLayout.LayoutParams(-1, dp(56));
        btnLp.bottomMargin = dp(24);
        content.addView(scanBtn, btnLp);

        // ===== 检测结果区 =====
        resultTitle = new TextView(context);
        resultTitle.setText("检测结果");
        resultTitle.setTextColor(Color.parseColor("#F8FAFC"));
        resultTitle.setTextSize(22);
        resultTitle.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        LinearLayout.LayoutParams rtLp = new LinearLayout.LayoutParams(-1, -2);
        rtLp.bottomMargin = dp(4);
        content.addView(resultTitle, rtLp);

        TextView resultHint = new TextView(context);
        resultHint.setText("点击模块展开 · 点击检测项查看详情");
        resultHint.setTextColor(Color.parseColor("#64748B"));
        resultHint.setTextSize(11);
        resultHint.setTypeface(Typeface.MONOSPACE);
        LinearLayout.LayoutParams rhLp = new LinearLayout.LayoutParams(-1, -2);
        rhLp.bottomMargin = dp(8);
        content.addView(resultHint, rhLp);

        resultsContainer = new LinearLayout(context);
        resultsContainer.setOrientation(LinearLayout.VERTICAL);
        content.addView(resultsContainer);
    }

    /** 检测完成后更新: 得分卡 + 结果区 */
    public void showResults(int score, JSONArray items) {
        // 更新得分卡
        int hit = 0, total = 0;
        for (int i = 0; i < items.length(); i++) {
            try {
                total++;
                if (items.getJSONObject(i).optInt("detected") == 1) hit++;
            } catch (Exception e) { }
        }
        scoreText.setText(String.valueOf(score));
        String color, risk;
        if (score < 30) { color = "#34D399"; risk = "环境安全"; statusText.setText("检测完成 · 环境安全"); }
        else if (score < 60) { color = "#F59E0B"; risk = "存在风险"; statusText.setText("检测完成 · 存在风险"); }
        else { color = "#EF4444"; risk = "高风险环境"; statusText.setText("检测完成 · 高风险环境"); }
        scoreText.setTextColor(Color.parseColor(color));
        riskText.setText(risk + " · 命中 " + hit + "/" + total + " 项风险");
        riskText.setTextColor(Color.parseColor(color));

        // 渲染结果区
        renderResults(items);
    }

    /** 渲染 7 大模块折叠列表 */
    private void renderResults(final JSONArray items) {
        resultsContainer.removeAllViews();
        resultTitle.setText("检测结果 · 命中 " + countHit(items) + " 项");

        for (int m = 0; m < 8; m++) {
            final int modIdx = m;
            int hit = 0, total = 0;
            for (int i = 0; i < items.length(); i++) {
                try {
                    if (items.getJSONObject(i).optInt("module") == modIdx) {
                        total++;
                        if (items.getJSONObject(i).optInt("detected") == 1) hit++;
                    }
                } catch (Exception e) { }
            }
            if (total == 0) continue;

            // 模块折叠卡
            final GlassCard moduleCard = new GlassCard(getContext());
            LinearLayout header = new LinearLayout(getContext());
            header.setOrientation(LinearLayout.HORIZONTAL);
            header.setGravity(Gravity.CENTER_VERTICAL);

            TextView dot = new TextView(getContext());
            dot.setText(hit > 0 ? "●" : "○");
            dot.setTextColor(hit > 0 ? Color.parseColor("#EF4444") : Color.parseColor("#34D399"));
            dot.setTextSize(14);
            header.addView(dot);

            TextView name = new TextView(getContext());
            name.setText(KnowledgeData.MODULE_NAMES[m]);
            name.setTextColor(Color.parseColor("#E2E8F0"));
            name.setTextSize(16);
            name.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
            LinearLayout.LayoutParams nameLp = new LinearLayout.LayoutParams(0, -2, 1);
            nameLp.leftMargin = dp(10);
            header.addView(name, nameLp);

            TextView badge = new TextView(getContext());
            badge.setText(hit + "/" + total);
            badge.setTextColor(hit > 0 ? Color.parseColor("#FCA5A5") : Color.parseColor("#6EE7B7"));
            badge.setTextSize(12);
            badge.setTypeface(Typeface.MONOSPACE);
            badge.setGravity(Gravity.CENTER);
            badge.setPadding(dp(8), dp(3), dp(8), dp(3));
            badge.setBackground(roundRect(
                hit > 0 ? Color.parseColor("#331818") : Color.parseColor("#3306420E"), dp(10)));
            header.addView(badge);

            // 展开箭头
            TextView arrow = new TextView(getContext());
            arrow.setText("▾");
            arrow.setTextColor(Color.parseColor("#64748B"));
            arrow.setTextSize(14);
            LinearLayout.LayoutParams arrowLp = new LinearLayout.LayoutParams(-2, -2);
            arrowLp.leftMargin = dp(8);
            header.addView(arrow, arrowLp);

            moduleCard.inner().addView(header);

            final LinearLayout detailContainer = new LinearLayout(getContext());
            detailContainer.setOrientation(LinearLayout.VERTICAL);
            detailContainer.setVisibility(View.GONE);
            LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(-1, -2);
            detailLp.topMargin = dp(10);
            moduleCard.inner().addView(detailContainer, detailLp);

            for (int i = 0; i < items.length(); i++) {
                try {
                    JSONObject it = items.getJSONObject(i);
                    if (it.optInt("module") != modIdx) continue;
                    addItemRow(detailContainer, it);
                } catch (Exception e) { }
            }

            header.setOnClickListener(new OnClickListener() {
                @Override public void onClick(View v) {
                    boolean show = detailContainer.getVisibility() == View.GONE;
                    detailContainer.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });

            LinearLayout.LayoutParams cardLp = new LinearLayout.LayoutParams(-1, -2);
            cardLp.topMargin = dp(14);
            resultsContainer.addView(moduleCard, cardLp);
        }
    }

    /** 单个检测项: 点击展开详情 (原理/攻击场景/证据/防御) */
    private void addItemRow(LinearLayout container, final JSONObject item) {
        try {
            final String name = item.getString("name");
            final int detected = item.getInt("detected");
            final int level = item.getInt("level");
            final String levelStr = item.getString("level_str");
            final String evidence = item.optString("evidence", "");
            final String[] info = KnowledgeData.itemInfo(name);

            LinearLayout row = new LinearLayout(getContext());
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setGravity(Gravity.CENTER_VERTICAL);
            row.setPadding(dp(8), dp(8), dp(8), dp(8));
            row.setBackground(roundRect(Color.parseColor("#1E2433"), dp(12)));

            TextView icon = new TextView(getContext());
            icon.setText(detected == 1 ? "⚠" : "✓");
            icon.setTextColor(detected == 1 ? Color.parseColor("#EF4444") : Color.parseColor("#34D399"));
            icon.setTextSize(14);
            row.addView(icon);

            TextView tv = new TextView(getContext());
            tv.setText(name);
            tv.setTextColor(Color.parseColor("#CBD5E1"));
            tv.setTextSize(14);
            LinearLayout.LayoutParams tvLp = new LinearLayout.LayoutParams(0, -2, 1);
            tvLp.leftMargin = dp(10);
            row.addView(tv, tvLp);

            TextView lv = new TextView(getContext());
            lv.setText(levelStr);
            lv.setTextSize(11);
            lv.setTextColor(Color.parseColor(levelColor(level)));
            lv.setGravity(Gravity.CENTER);
            lv.setPadding(dp(6), dp(2), dp(6), dp(2));
            lv.setBackground(roundRect(Color.parseColor(levelBg(level)), dp(8)));
            row.addView(lv);

            LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(-1, -2);
            rowLp.topMargin = dp(6);
            container.addView(row, rowLp);

            // 详情面板
            final LinearLayout detail = new LinearLayout(getContext());
            detail.setOrientation(LinearLayout.VERTICAL);
            detail.setPadding(dp(10), dp(10), dp(10), dp(10));
            detail.setBackground(roundRect(Color.parseColor("#151A26"), dp(10)));
            detail.setVisibility(View.GONE);

            addDetailLine(detail, "检测原理", info[0], "#94A3B8");
            addDetailLine(detail, "攻击场景", info[1], "#CBD5E1");
            addDetailLine(detail, "证据详情", evidence.length() > 0 ? evidence : "未检测到异常", "#F0883E");
            addDetailLine(detail, "风险等级", levelStr + " (Level " + level + ")", levelColor(level));
            addDetailLine(detail, "防御建议", info[3], "#6EE7B7");

            LinearLayout.LayoutParams detailLp = new LinearLayout.LayoutParams(-1, -2);
            detailLp.leftMargin = dp(8);
            detailLp.rightMargin = dp(8);
            detailLp.topMargin = dp(4);
            container.addView(detail, detailLp);

            row.setOnClickListener(new OnClickListener() {
                @Override public void onClick(View v) {
                    boolean show = detail.getVisibility() == View.GONE;
                    detail.setVisibility(show ? View.VISIBLE : View.GONE);
                }
            });
        } catch (Exception e) { }
    }

    private void addDetailLine(LinearLayout parent, String label, String content, String color) {
        TextView l = new TextView(getContext());
        l.setText(label);
        l.setTextColor(Color.parseColor("#64748B"));
        l.setTextSize(10);
        l.setTypeface(Typeface.MONOSPACE);
        parent.addView(l);

        TextView c = new TextView(getContext());
        c.setText(content);
        c.setTextColor(Color.parseColor(color));
        c.setTextSize(13);
        c.setLineSpacing(dp(2), 1.1f);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(2);
        lp.bottomMargin = dp(8);
        parent.addView(c, lp);
    }

    private int countHit(JSONArray items) {
        int hit = 0;
        for (int i = 0; i < items.length(); i++) {
            try {
                if (items.getJSONObject(i).optInt("detected") == 1) hit++;
            } catch (Exception e) { }
        }
        return hit;
    }

    private String levelColor(int level) {
        switch (level) {
            case 0: return "#64748B";
            case 1: return "#34D399";
            case 2: return "#F59E0B";
            case 3: return "#F97316";
            default: return "#EF4444";
        }
    }

    private String levelBg(int level) {
        switch (level) {
            case 0: return "#22334455";
            case 1: return "#3306420E";
            case 2: return "#33B45309";
            case 3: return "#33C2410C";
            default: return "#337F1D1D";
        }
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
