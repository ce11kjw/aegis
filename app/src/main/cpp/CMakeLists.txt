cmake_minimum_required(VERSION 3.22.1)
project(aegis LANGUAGES C)

set(ENGINE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../engine)

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
    ${ENGINE_DIR}/src/jni_bridge.c
)

target_include_directories(aegis PRIVATE ${ENGINE_DIR}/include)

find_library(log-lib log)
target_link_libraries(aegis ${log-lib})

set_target_properties(aegis PROPERTIES OUTPUT_NAME "aegis")
