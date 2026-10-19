# 保留 JNI 接口
-keep class com.ce11kjw.aegis.AegisNative { *; }
-keepclasseswithmembernames class * { native <methods>; }
# Gson 数据类
-keep class com.ce11kjw.aegis.data.** { *; }
-keepattributes Signature
-keepattributes *Annotation*
