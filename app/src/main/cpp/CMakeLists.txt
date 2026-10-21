cmake_minimum_required(VERSION 3.22.1)
project(aegis LANGUAGES C)

# 优先使用 Gradle 传入的绝对路径（-DAEGIS_ENGINE_DIR=...）
# 回退到相对路径（本地直接 cmake 时）
if(DEFINED AEGIS_ENGINE_DIR)
    set(ENGINE_DIR ${AEGIS_ENGINE_DIR})
else()
    set(ENGINE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../engine)
endif()

message(STATUS "AEGIS_ENGINE_DIR = ${ENGINE_DIR}")
if(NOT EXISTS "${ENGINE_DIR}/src/aegis.c")
    message(FATAL_ERROR "engine sources not found at ${ENGINE_DIR}/src/aegis.c")
endif()

add_library(aegis SHARED
    ${ENGINE_DIR}/src/aegis.c
    ${ENGINE_DIR}/src/sha256.c
    ${ENGINE_DIR}/src/debug_detect.c
    ${ENGINE_DIR}/src/frida_detect.c
    ${ENGINE_DIR}/src/xposed_detect.c
    ${ENGINE_DIR}/src/integrity.c
    ${ENGINE_DIR}/src/emulator.c
    ${ENGINE_DIR}/src/root_detect.c
    ${ENGINE_DIR}/src/system_detect.c
    ${ENGINE_DIR}/src/network.c
    ${ENGINE_DIR}/src/original_detect.c
    ${ENGINE_DIR}/src/opensource_detect.c
    ${ENGINE_DIR}/src/device_detect.c
    ${ENGINE_DIR}/src/app_integrity.c
    ${ENGINE_DIR}/src/runtime_detect.c
    ${ENGINE_DIR}/src/jni_bridge.c
)

target_include_directories(aegis PRIVATE ${ENGINE_DIR}/include)

find_library(log-lib log)
target_link_libraries(aegis ${log-lib})

set_target_properties(aegis PROPERTIES OUTPUT_NAME "aegis")
