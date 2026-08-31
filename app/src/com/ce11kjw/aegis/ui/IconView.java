package com.ce11kjw.aegis.ui;

import android.content.Context;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.ce11kjw.aegis.R;

/**
 * IconView - Lucide 矢量图标封装
 * 通过 R.drawable 引用 VectorDrawable, 用 tint 着色
 */
public class IconView {

    public static ImageView make(Context ctx, int drawableRes, int sizeDp, String colorHex) {
        ImageView iv = new ImageView(ctx);
        iv.setImageResource(drawableRes);
        int px = (int) (sizeDp * ctx.getResources().getDisplayMetrics().density + 0.5f);
        iv.setLayoutParams(new LinearLayout.LayoutParams(px, px));
        setColor(iv, colorHex);
        return iv;
    }

    public static void setColor(ImageView iv, String colorHex) {
        iv.setColorFilter(Color.parseColor(colorHex), PorterDuff.Mode.SRC_IN);
    }

    /* ===== 图标资源 (Lucide, 已转 VectorDrawable) ===== */
    public static final int NAV_SHIELD = R.drawable.ic_shield;
    public static final int NAV_BOOK   = R.drawable.ic_book_open;
    public static final int NAV_SETTINGS = R.drawable.ic_settings;
    public static final int MOD_BUG    = R.drawable.ic_bug;
    public static final int MOD_SYRINGE = R.drawable.ic_syringe;
    public static final int MOD_PUZZLE = R.drawable.ic_puzzle;
    public static final int MOD_FINGERPRINT = R.drawable.ic_fingerprint;
    public static final int MOD_SMARTPHONE = R.drawable.ic_smartphone;
    public static final int MOD_CROWN  = R.drawable.ic_crown;
    public static final int MOD_CPU    = R.drawable.ic_cpu;
    public static final int MOD_GLOBE  = R.drawable.ic_globe;
    public static final int ST_SHIELD_CHECK = R.drawable.ic_shield_check;
    public static final int ST_SHIELD_ALERT = R.drawable.ic_shield_alert;
    public static final int ST_SHIELD_X = R.drawable.ic_shield_x;
    public static final int ACT_PLAY    = R.drawable.ic_play;
    public static final int ACT_DOWNLOAD = R.drawable.ic_download;
    public static final int ACT_CHEVRON = R.drawable.ic_chevron_down;
    public static final int ACT_LOADER  = R.drawable.ic_loader;
    public static final int ACT_RADAR   = R.drawable.ic_radar;

    /** 模块图标映射: 0-7 → drawable */
    public static int moduleIcon(int moduleIdx) {
        switch (moduleIdx) {
            case 0: return MOD_BUG;
            case 1: return MOD_SYRINGE;
            case 2: return MOD_PUZZLE;
            case 3: return MOD_FINGERPRINT;
            case 4: return MOD_SMARTPHONE;
            case 5: return MOD_CROWN;
            case 6: return MOD_CPU;
            default: return MOD_GLOBE;
        }
    }
}
