package com.ce11kjw.aegis.sdk;

import android.content.Context;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * AegisGuard SDK v4.0 - 安全检测/加固 SDK
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

    /** [v4.0] 设备是否被伪造（改机/属性伪装） */
    public static boolean isDeviceSpoofed() {
        return containsModule(8, "设备伪造");
    }

    /** [v4.0] App 自身是否被篡改（重打包/侧载/so 替换） */
    public static boolean isAppTampered() {
        return containsModule(9, "应用完整性");
    }

    /** [v4.0] 运行时是否有异常行为（UID 提权/线程突变/句柄泄漏） */
    public static boolean hasRuntimeAnomaly() {
        return containsModule(10, "运行时行为");
    }

    /** [v4.0] 综合风险等级: 0=安全 1=轻微 2=可疑 3=风险 4=危险 5=严重 */
    public static int getRiskLevel() {
        int score = detect();
        if (score >= 90) return 5;
        if (score >= 70) return 4;
        if (score >= 50) return 3;
        if (score >= 30) return 2;
        if (score >= 10) return 1;
        return 0;
    }

    /** 安全断言: 高风险环境直接抛出异常, 用于阻断敏感操作（默认阈值 60） */
    public static void assertSecure() throws SecurityException {
        assertSecure(60);
    }

    /** [v4.0] 安全断言（自定义阈值 0-100） */
    public static void assertSecure(int threshold) throws SecurityException {
        if (!isReady()) return;
        int score = detect();
        if (score >= threshold) {
            throw new SecurityException("检测到高风险环境 (score=" + score
                + ", threshold=" + threshold + "), 已阻断敏感操作");
        }
    }

    /** [v4.0] 按模块运行检测 */
    public static JSONArray runModule(int moduleIdx) {
        try {
            String json = runModuleImpl(moduleIdx);
            JSONObject obj = new JSONObject(json);
            return obj.getJSONArray("items");
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    private static native String runModuleImpl(int moduleIdx);

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
