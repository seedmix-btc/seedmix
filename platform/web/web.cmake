# -- Web (Emscripten) Platform Build ----------------------------------------
# SDL2 is provided by Emscripten's bundled SDL2 port (-sUSE_SDL=2).

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# Build libwally from external/libwally-core (cross-compiled via emconfigure)
include(BuildLibWally)

# Build libqrencode (QR encoder) + quirc (QR decoder)
include(BuildQrLibs)

# -- LVGL Library -----------------------------------------------------------
set(LVGL_DIR ${CMAKE_SOURCE_DIR}/external/lvgl CACHE PATH "Path to LVGL source")

if(NOT EXISTS ${LVGL_DIR}/lvgl.h)
    message(FATAL_ERROR
        "LVGL not found at ${LVGL_DIR}\n"
        "Run:  scripts/ensure_deps.sh")
endif()

if(NOT LV_BUILD_CONF_PATH)
    set(LV_BUILD_CONF_PATH "${CMAKE_SOURCE_DIR}/main/lv_conf.h" CACHE PATH
        "lv_conf.h used by the vendored LVGL" FORCE)
endif()

set(CONFIG_LV_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CONFIG_LV_BUILD_DEMOS    OFF CACHE BOOL "" FORCE)

# SDL2 headers come from Emscripten's bundled SDL2 port, so -sUSE_SDL=2 must
# be on BOTH the compile line (LVGL's SDL driver includes <SDL2/SDL.h>) and
# the link line.  These flags are directory-scoped, so set them before
# add_subdirectory(lvgl) so the driver sources compile too.
add_compile_options(-sUSE_SDL=2)
add_link_options(-sUSE_SDL=2 -sALLOW_MEMORY_GROWTH=1 -sSTACK_SIZE=1048576 -sASYNCIFY -sEXIT_RUNTIME=0)

add_subdirectory(${LVGL_DIR} ${CMAKE_BINARY_DIR}/lvgl)

# -- Application Executable ------------------------------------------------
add_executable(${PROJECT_NAME}
    ${COMMON_SOURCES}
    platform/web/main_web.c
    platform/web/hal_web.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/main
    ${CMAKE_SOURCE_DIR}/main/ui
    ${CMAKE_SOURCE_DIR}/main/crypto
    ${CMAKE_SOURCE_DIR}/main/qr
    ${CMAKE_SOURCE_DIR}/main/util
    ${CMAKE_SOURCE_DIR}/platform/web
    ${LVGL_DIR}
    ${LVGL_DIR}/src/drivers/sdl
)

target_link_libraries(${PROJECT_NAME} PRIVATE lvgl libwally qrencode quirc)

# Emit an HTML shell (emcc -o seedmix.html) so the page is directly openable.
set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ".html")

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
