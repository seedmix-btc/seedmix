# ESP-IDF project for seedmix.
#
# This is built with idf.py.  Example:
#
#     . ~/.espressif/tools/activate_idf_v5.5.5.sh
#     cd platform/esp32
#     idf.py set-target esp32
#     idf.py build
#
# The vendored LVGL (external/lvgl, populated by scripts/ensure_deps.sh) is
# added as an ESP-IDF component

cmake_minimum_required(VERSION 3.16)

set(LVGL_DIR "${CMAKE_CURRENT_LIST_DIR}/../../external/lvgl")
if(NOT EXISTS "${LVGL_DIR}/lvgl.h")
    message(FATAL_ERROR
        "LVGL not found at ${LVGL_DIR}\n"
        "Run scripts/ensure_deps.sh first")
endif()
list(APPEND EXTRA_COMPONENT_DIRS "${LVGL_DIR}")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Keep one dependency lock per target
idf_build_set_property(DEPENDENCIES_LOCK dependencies.lock.${IDF_TARGET})

project(seedmix)
