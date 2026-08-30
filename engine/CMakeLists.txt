cmake_minimum_required(VERSION 3.22)
project(aegis C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(aegis SHARED
    src/aegis.c
    src/sha256.c
    src/debug_detect.c
    src/frida_detect.c
    src/xposed_detect.c
    src/integrity.c
    src/emulator.c
    src/root_detect.c
    src/system_detect.c
    src/network.c
    src/jni_bridge.c
)

target_include_directories(aegis PRIVATE include)
target_link_libraries(aegis log)

# 同时构建原生可执行测试程序 (可选, 在 Android 上以可执行方式运行)
add_executable(aegis_test
    test/test_engine.c
    src/aegis.c
    src/sha256.c
    src/debug_detect.c
    src/frida_detect.c
    src/xposed_detect.c
    src/integrity.c
    src/emulator.c
    src/root_detect.c
    src/system_detect.c
    src/network.c
)
target_include_directories(aegis_test PRIVATE include)
