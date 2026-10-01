/**
 * @file lv_conf.h
 * @brief LVGL configuration for the Linux (SDL2) and Web (Emscripten) builds.
 */

#ifndef LV_CONF_H
#define LV_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------
 * General
 *----------------------------------------------------------------------*/
#define LV_COLOR_DEPTH          16
#define LV_COLOR_16_SWAP        0

/*----------------------------------------------------------------------
 * Memory
 *----------------------------------------------------------------------*/
#define LV_MEM_SIZE             (128U * 1024U)   /* 128 kB */
#define LV_MEM_ADR              0

/*----------------------------------------------------------------------
 * Display
 *----------------------------------------------------------------------*/
#define LV_DPI                  130

/*----------------------------------------------------------------------
 * SDL (Linux desktop driver)
 *----------------------------------------------------------------------*/
#define LV_USE_SDL              1

/*----------------------------------------------------------------------
 * Logging
 *----------------------------------------------------------------------*/
#define LV_USE_LOG              1
#if LV_USE_LOG
    #define LV_LOG_LEVEL         LV_LOG_LEVEL_WARN
    #define LV_LOG_PRINTF        1
#endif

/*----------------------------------------------------------------------
 * Assets / Fonts
 *----------------------------------------------------------------------*/
#define LV_FONT_MONTSERRAT_10   1
#define LV_FONT_MONTSERRAT_12   1
#define LV_FONT_MONTSERRAT_14   1
#define LV_FONT_MONTSERRAT_18   1
#define LV_FONT_MONTSERRAT_20   1
#define LV_FONT_MONTSERRAT_24   1
#define LV_FONT_MONTSERRAT_28   1
#define LV_FONT_MONTSERRAT_48   1
#define LV_USE_FONT_COMPRESSED  1

/*----------------------------------------------------------------------
 * Image decoders
 *----------------------------------------------------------------------*/
/* The Linux HAL decodes the image file the user picked with LVGL's bundled
 * JPEG and BMP decoders, which also need the POSIX file system driver to open
 * it by path. */
#if !defined(__EMSCRIPTEN__)
    #define LV_USE_TJPGD        1   /* JPEG */
    #define LV_USE_BMP          1   /* BMP */

    #define LV_USE_FS_POSIX     1
    #if LV_USE_FS_POSIX
        #define LV_FS_POSIX_LETTER      'A' /* paths are passed as "A:/path/to/image.png" */
        #define LV_FS_POSIX_PATH        ""
        #define LV_FS_POSIX_CACHE_SIZE  0
    #endif
#endif

/*----------------------------------------------------------------------
 * Features - enable what you need
 *----------------------------------------------------------------------*/
#define LV_USE_SYSMON           0
#define LV_USE_PERF_MONITOR     0

#define LV_USE_SNAPSHOT         0
#define LV_USE_MONKEY           0
#define LV_USE_GRIDNAV          0

/*----------------------------------------------------------------------
 * Widgets
 *----------------------------------------------------------------------*/
#define LV_USE_ARC              1
#define LV_USE_BAR              1
#define LV_USE_BUTTON           1
#define LV_USE_BUTTONMATRIX     1
#define LV_USE_CANVAS           0
#define LV_USE_CHECKBOX         0
#define LV_USE_DROPDOWN         0
#define LV_USE_IMAGE            1
#define LV_USE_LABEL            1
#define LV_USE_LINE             1
#define LV_USE_ROLLER           0
#define LV_USE_SLIDER           0
#define LV_USE_SWITCH           0
#define LV_USE_TEXTAREA         1
#define LV_USE_TABLE            0
#define LV_USE_TABVIEW          0
#define LV_USE_TILEVIEW         0
#define LV_USE_WIN              0

#define LV_USE_SPINNER          1
#define LV_USE_CALENDAR         0
#define LV_USE_CHART            0
#define LV_USE_IMAGEBUTTON      0
#define LV_USE_KEYBOARD         1
#define LV_USE_LED              0
#define LV_USE_LIST             0
#define LV_USE_MENU             0
#define LV_USE_MSGBOX           1
#define LV_USE_SPAN             0
#define LV_USE_SPINBOX          0

/*----------------------------------------------------------------------
 * Themes
 *----------------------------------------------------------------------*/
#define LV_USE_THEME_DEFAULT    1
#define LV_USE_THEME_MONO       0

#ifdef __cplusplus
}
#endif

#endif /* LV_CONF_H */
