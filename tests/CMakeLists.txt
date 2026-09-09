# -- Unit tests (Linux only) -------------------------------------------------
# Uses Unity (ThrowTheSwitch), vendored by scripts/ensure_deps.sh (pinned to
# a commit SHA), so no network access is needed at configure time.

set(UNITY_DIR ${CMAKE_SOURCE_DIR}/external/unity)
if(NOT EXISTS ${UNITY_DIR}/CMakeLists.txt)
    message(FATAL_ERROR
        "Unity not found at ${UNITY_DIR}\n"
        "Run:  bash scripts/ensure_deps.sh")
endif()

# Build just the unity library (Unity ships no test subdirectory of its own).
add_subdirectory(${UNITY_DIR} ${CMAKE_BINARY_DIR}/unity)

# -- Coverage instrumentation -----------------------------------------------
# Instrument only the code under test (targets in this directory), not Unity
# (vendored above) or libwally (built separately with autotools).
if(ENABLE_COVERAGE)
    add_compile_options(-g -O0 --coverage)
    add_link_options(--coverage)
endif()

# Sanitizers for the test targets
if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=${ENABLE_SANITIZERS} -fno-omit-frame-pointer)
    add_link_options(-fsanitize=${ENABLE_SANITIZERS})
endif()

# -- Library under test ------------------------------------------------------
# Standalone units only (no LVGL/UI/platform).  error.c is excluded because it
# depends on LVGL; minimal stubs are provided in support/:
#   fatal_stub.c  - fatal_handler replacement
#   hal_stub.c    - deterministic hal_get_random* replacement
add_library(seedmix_test_util STATIC
    ${CMAKE_SOURCE_DIR}/main/util/utils.c
    ${CMAKE_SOURCE_DIR}/main/util/log.c
    ${CMAKE_SOURCE_DIR}/main/crypto/secure_stack.c
    ${CMAKE_SOURCE_DIR}/main/crypto/mnemonic.c
    ${CMAKE_SOURCE_DIR}/main/crypto/bip39_wordlist.c
    ${CMAKE_SOURCE_DIR}/main/crypto/seedqr.c
    ${CMAKE_SOURCE_DIR}/main/qr/qr.c
    ${CMAKE_SOURCE_DIR}/main/crypto/touch.c
    ${CMAKE_SOURCE_DIR}/main/crypto/dice.c
    ${CMAKE_SOURCE_DIR}/main/crypto/coin.c
    support/fatal_stub.c
    support/hal_stub.c
)

target_include_directories(seedmix_test_util PUBLIC
    ${CMAKE_SOURCE_DIR}/main
    ${CMAKE_SOURCE_DIR}/main/util
    ${CMAKE_SOURCE_DIR}/main/crypto
    ${CMAKE_SOURCE_DIR}/main/qr
)

# libwally (IMPORTED, GLOBAL) is defined by platform/linux/linux.cmake
# qrencode/quirc are defined by cmake/BuildQrLibs.cmake
target_link_libraries(seedmix_test_util PUBLIC libwally qrencode quirc)

target_compile_options(seedmix_test_util PRIVATE
    -Wall -Wextra -Wpedantic
)

# -- Test executables (one per suite; each defines its own main()) -----------
function(seedmix_add_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE seedmix_test_util unity)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/support)
    target_compile_options(${name} PRIVATE
        -Wall -Wextra -Wpedantic
        $<$<CONFIG:Debug>:-g -O0>
        $<$<CONFIG:Release>:-O2>
    )
    add_test(NAME ${name} COMMAND ${name})
    set_property(GLOBAL APPEND PROPERTY SEEDMIX_TEST_EXECUTABLES ${name})
endfunction()

seedmix_add_test(seedmix_utils_tests          test_utils.c)
seedmix_add_test(seedmix_mnemonic_tests       test_mnemonic.c)
seedmix_add_test(seedmix_dice_tests           test_dice.c)
seedmix_add_test(seedmix_coin_tests           test_coin.c)
seedmix_add_test(seedmix_secure_stack_tests   test_secure_stack.c)
seedmix_add_test(seedmix_bip39_wordlist_tests test_bip39_wordlist.c)
seedmix_add_test(seedmix_kat_tests            test_kat.c)
seedmix_add_test(seedmix_fatal_tests          test_fatal.c)
# The "death" tests intentionally longjmp out of FATAL paths, abandoning heap
# allocations made before the fault (on a real device fatal() aborts the
# device).  Leak detection therefore does not apply to this suite
set_tests_properties(seedmix_fatal_tests PROPERTIES
    ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0"
)
seedmix_add_test(seedmix_touch_tests          test_touch.c)
seedmix_add_test(seedmix_seedqr_tests         test_seedqr.c)
seedmix_add_test(seedmix_qr_tests             test_qr.c)

# Convenience target built by scripts/test.sh
get_property(_test_exes GLOBAL PROPERTY SEEDMIX_TEST_EXECUTABLES)
add_custom_target(seedmix_tests DEPENDS ${_test_exes})
