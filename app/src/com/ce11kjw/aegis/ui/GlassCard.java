package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.widget.LinearLayout;

/**
 * GlassCard - 双层嵌套玻璃卡片
 * 外层: 深色实底 #111827 + 大圆角 24 + 极细青蓝描边
 * 内层: 半透明 #1A1F2E + 圆角 20 + 内发光
 */
public class GlassCard extends LinearLayout {

    private LinearLayout inner;

    public GlassCard(Context context) {
        super(context);
        setOrientation(LinearLayout.VERTICAL);
        setPadding(dp(6), dp(6), dp(6), dp(6));

        // 外层托盘: 深色实底 + 圆角24 + 发光描边
        GradientDrawable outer = new GradientDrawable();
        outer.setColor(Color.parseColor("#111827"));
        outer.setCornerRadius(dp(24));
        outer.setStroke(dp(1), Color.parseColor("#3322D3EE"));
        setBackground(outer);

        // 内层玻璃: 半透明 + 圆角20 + 内发光
        inner = new LinearLayout(context);
        inner.setOrientation(LinearLayout.VERTICAL);
        inner.setPadding(dp(16), dp(14), dp(16), dp(14));
        GradientDrawable innerBg = new GradientDrawable();
        innerBg.setColor(Color.parseColor("#E61A1F2E"));
        innerBg.setCornerRadius(dp(20));
        // 内发光: 顶部细白线模拟高光
        innerBg.setStroke(dp(1), Color.parseColor("#1AFFFFFF"));
        inner.setBackground(innerBg);

        addView(inner, new LayoutParams(-1, -2));
    }

    /** 获取内层容器, 往里塞内容 */
    public LinearLayout inner() {
        return inner;
    }

    private int dp(float v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }
}
