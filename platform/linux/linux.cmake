# -- Linux Platform Build ---------------------------------------------------
# Requires: SDL2; libwally-core is built automatically from the submodule.

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

# -- Find Dependencies --------------------------------------------------
find_package(SDL2 REQUIRED)

# Build libwally from external/libwally-core (submodule)
include(BuildLibWally)

# Build libqrencode (QR encoder) + quirc (QR decoder)
include(BuildQrLibs)

# -- LVGL Library -------------------------------------------------------
# Points to your local LVGL clone - adjust or use FetchContent
set(LVGL_DIR ${CMAKE_SOURCE_DIR}/external/lvgl CACHE PATH "Path to LVGL source")

if(NOT EXISTS ${LVGL_DIR}/lvgl.h)
    message(FATAL_ERROR
        "LVGL not found at ${LVGL_DIR}\n"
        "Run:  git submodule update --init  or  clone into external/lvgl")
endif()

# Tell LVGL (v9.2.0) where lv_conf.h lives
set(LV_CONF_PATH ${CMAKE_SOURCE_DIR}/main/lv_conf.h)

# Don't build examples/demos (they reference widgets we havve disabled)
set(LV_CONF_BUILD_DISABLE_EXAMPLES ON CACHE BOOL "" FORCE)
set(LV_CONF_BUILD_DISABLE_DEMOS    ON CACHE BOOL "" FORCE)

# Include LVGL (it provides its own CMakeLists.txt)
add_subdirectory(${LVGL_DIR} ${CMAKE_BINARY_DIR}/lvgl)

# LVGL's SDL driver sources need SDL2 headers
target_include_directories(lvgl PUBLIC ${SDL2_INCLUDE_DIRS})

# -- Application Executable ---------------------------------------------
add_executable(${PROJECT_NAME}
    ${COMMON_SOURCES}
    platform/linux/main_linux.c
    platform/linux/hal_linux.c
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/main
    ${CMAKE_SOURCE_DIR}/main/ui
    ${CMAKE_SOURCE_DIR}/main/crypto
    ${CMAKE_SOURCE_DIR}/main/qr
    ${CMAKE_SOURCE_DIR}/main/util
    ${CMAKE_SOURCE_DIR}/platform/linux
    ${LVGL_DIR}
    ${LVGL_DIR}/src/drivers/sdl
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    lvgl
    SDL2::SDL2
    m
    pthread
)

# libwally is always built from the submodule on Linux
target_link_libraries(${PROJECT_NAME} PRIVATE libwally qrencode quirc)

# -- Compiler Flags -----------------------------------------------------
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Debug>:-g -O0>
    $<$<CONFIG:Release>:-O2>
)

if(ENABLE_ASAN)
    target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
endif()

# -- Button input emulation ---------------------------------------------
if(ENABLE_BUTTONS)
    target_sources(${PROJECT_NAME} PRIVATE platform/linux/buttons_linux.c)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_BUTTONS)
    message(STATUS "Button input emulation enabled (LEFT/RIGHT/ENTER)")
endif()

# -- T-Display screen size ----------------------------------------------
if(ENABLE_TDISPLAY)
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_TDISPLAY)
    message(STATUS "T-Display screen size enabled (240x135)")
endif()
