package com.ce11kjw.aegis.sdk;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * AegisGuard SDK - 安全检测/加固 SDK
 * 一核三用中的"加固 SDK"产品, 供第三方 App 集成
 *
 * 快速开始:
 *   AegisGuard.init(context);
 *   int score = AegisGuard.detect();           // 获取风险分 (0-100)
 *   JSONArray items = AegisGuard.getResults();  // 获取全部检测项
 *   boolean rooted = AegisGuard.isRooted();      // 快速判断是否 root
 *   boolean hooked = AegisGuard.isHooked();      // 快速判断是否被注入
 *
 * 集成说明:
 *   1. 将 libaegis.so 放入 app/src/main/jniLibs/{abi}/
 *   2. 调用 AegisGuard.init(context) 初始化
 *   3. 在敏感操作前调用 AegisGuard.assertSecure() 进行阻断
 */
public class AegisGuard {
    private static AegisGuard sInstance;
    private Context mContext;
    private JSONArray mItems;
    private int mScore;
    private boolean mInitialized;

    static {
        System.loadLibrary("aegis");
    }

    private AegisGuard(Context context) {
        mContext = context.getApplicationContext();
    }

    /** 初始化 SDK (建议在 Application.onCreate 调用) */
    public static synchronized void init(Context context) {
        if (sInstance == null) {
            sInstance = new AegisGuard(context);
        }
        sInstance.runAllChecks();
    }

    public static synchronized AegisGuard get() {
        if (sInstance == null) {
            throw new IllegalStateException("AegisGuard 未初始化, 请先调用 init()");
        }
        return sInstance;
    }

    /** 运行全部检测 */
    public synchronized void runAllChecks() {
        try {
            String json = runAll();
            JSONObject obj = new JSONObject(json);
            mScore = obj.getInt("score");
            mItems = obj.getJSONArray("items");
            mInitialized = true;
        } catch (Exception e) {
            mInitialized = false;
        }
    }

    /** 获取整体风险分 0-100 */
    public static int detect() {
        return get().mScore;
    }

    /** 获取全部检测结果 */
    public static JSONArray getResults() {
        return get().mItems;
    }

    /** 是否已初始化 */
    public static boolean isReady() {
        return sInstance != null && sInstance.mInitialized;
    }

    /** 是否被 root */
    public static boolean isRooted() {
        return containsModule(5, "Root");
    }

    /** 是否被注入 (Frida/Xposed/调试) */
    public static boolean isHooked() {
        return containsModule(1, "Frida") || containsModule(2, "Xposed") || containsModule(0, "反调试");
    }

    /** 是否在模拟器中 */
    public static boolean isEmulator() {
        return containsModule(4, "模拟器");
    }

    /** 安全断言: 高风险环境直接抛出异常, 用于阻断敏感操作 */
    public static void assertSecure() throws SecurityException {
        if (!isReady()) return;
        int score = detect();
        if (score >= 60) {
            throw new SecurityException("检测到高风险环境 (score=" + score + "), 已阻断敏感操作");
        }
    }

    /** 检查指定模块是否有风险项 */
    private static boolean containsModule(int moduleIdx, String moduleName) {
        try {
            JSONArray items = getResults();
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.getJSONObject(i);
                int mod = item.optInt("module", -1);
                int detected = item.optInt("detected", 0);
                int level = item.optInt("level", 0);
                if (mod == moduleIdx && detected == 1 && level >= 2) {
                    return true;
                }
            }
        } catch (Exception e) { }
        return false;
    }

    private static native String runAll();
}
