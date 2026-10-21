package com.ce11kjw.aegis.data

/**
 * 扫描进度回调（v4.5）
 *
 * JNI 侧通过 CallVoidMethod 调用 onProgress(String, int, int)，
 * 方法名和签名必须完全匹配（见 jni_bridge.c 的 GetMethodID）。
 *
 * ⚠️ 不能是 Kotlin 的 fun interface：
 *    Kotlin 会把 SAM 接口编译成带 invoke() 的类，
 *    GetMethodID("onProgress") 找不到方法。
 *    必须用普通 interface。
 */
interface ScanCallback {
    /**
     * @param module 刚完成的模块名
     * @param index  已完成数（从 0 开始）
     * @param total  总模块数
     */
    fun onProgress(module: String, index: Int, total: Int)
}
