/**
 * @file main/build_info.h
 * @brief The commit and date a binary was built from.
 *
 * The values arrive as compile definitions from cmake/BuildInfo.cmake.  A tree
 * without git, or a target that was never given the stamp, reports "unknown".
 */

#ifndef SEEDMIX_BUILD_INFO_H
#define SEEDMIX_BUILD_INFO_H

#ifndef SEEDMIX_GIT_HASH
#define SEEDMIX_GIT_HASH "unknown"
#endif

#ifndef SEEDMIX_BUILD_DATE
#define SEEDMIX_BUILD_DATE "unknown"
#endif

/** Two lines for the corner of the main screen: hash, then date. */
#define SEEDMIX_BUILD_STAMP SEEDMIX_GIT_HASH "\n" SEEDMIX_BUILD_DATE

#endif
