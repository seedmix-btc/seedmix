# libwally-core as an ESP-IDF component.
#
# Builds the bundled libsecp256k1 (standard modules only - the zkp extension
# modules are unused by seedmix) followed by the wallycore sources from
# external/libwally-core.  The upstream build is driven by its CMake files,
# but those ship with underscore-prefixed names (_CMakeLists.txt/_cmake) to
# keep the autotools build primary, so we replicate the equivalent
# configuration here instead.

set(WALLY_DIR "${COMPONENT_DIR}/../../../..//external/libwally-core")

# mbedtls is required for the hardware SHA-512 engine: config.h defines
# HAVE_MBEDTLS_SHA512_H so ccan's SHA-512 calls
# mbedtls_sha512_* instead of the portable C round loop.
idf_component_register(SRCS "" REQUIRES mbedtls)

# -- Bundled secp256k1 ------------------------------------------------
# Standard module set: ecdh/recovery/extrakeys/schnorrsig are the only ones
# libwally's non-elements code references.  The zkp-only modules
# (generator/rangeproof/surjectionproof/whitelist/ecdsa-s2c) are for Elements
# confidential-transaction support, which seedmix does not use.
set(SECP256K1_ENABLE_MODULE_ECDH ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ELLSWIFT OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_GENERATOR OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_RANGEPROOF OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SURJECTIONPROOF OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_WHITELIST OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_MUSIG OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDSA_ADAPTOR OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_ECDSA_S2C OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_BPPP OFF CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG_HALFAGG OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_CTIME_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SECP256K1_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory("${WALLY_DIR}/src/secp256k1" "${CMAKE_CURRENT_BINARY_DIR}/secp256k1")

# -- wallycore sources ---------------------------------------------------
# Same source globs as upstream src/_CMakeLists.txt (sha256_sse4.c is x86-only).
file(GLOB ccan_srcs
    "${WALLY_DIR}/src/ccan/ccan/base64/*.[ch]"
    "${WALLY_DIR}/src/ccan/ccan/build_assert/*.h"
    "${WALLY_DIR}/src/ccan/ccan/compiler/*.h"
    "${WALLY_DIR}/src/ccan/ccan/crypto/sha256/*.[ch]"
    "${WALLY_DIR}/src/ccan/ccan/crypto/sha512/*.[ch]"
    "${WALLY_DIR}/src/ccan/ccan/crypto/ripemd160/*.[ch]"
    "${WALLY_DIR}/src/ccan/ccan/endian/*.h"
    "${WALLY_DIR}/src/ccan/ccan/str/hex/*.[ch]"
    "${WALLY_DIR}/src/ccan/ccan/tap/*.[ch]"
)
list(REMOVE_ITEM ccan_srcs "${WALLY_DIR}/src/ccan/ccan/crypto/sha256/sha256_sse4.c")

file(GLOB wally_srcs "${WALLY_DIR}/src/*.[ch]")

add_library(wallycore STATIC ${ccan_srcs} ${wally_srcs})

target_compile_definitions(wallycore PRIVATE BUILD_STANDARD_SECP)
# The component's own config.h/ccan_config.h shadow the autotools-generated
# src/config.h, so list the component dir before the vendored src dir.  The
# bundled secp256k1 headers are also added directly because its CMake only
# exports them INTERFACE-side when it is a sub-project of a regular top-level
# project() (see secp256k1/src/CMakeLists.txt), which is not how ESP-IDF
# processes components.
target_include_directories(wallycore
    PUBLIC "${WALLY_DIR}" "${WALLY_DIR}/include"
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${WALLY_DIR}/src"
        "${WALLY_DIR}/src/ccan"
        "${WALLY_DIR}/src/secp256k1/include"
)
# PRIVATE: only wallycore's own sources need the mbedtls headers, and the
# engine's symbols come along when the component is linked.  The include dirs
# are taken from the component property because IDF only feeds them to its own
# component targets, not to a plain library like wallycore.
target_link_libraries(wallycore PUBLIC secp256k1 PRIVATE mbedtls)
# The component's public include dirs are relative paths, so anchor them on the
# component itself: port/include holds esp_config.h and sha512_alt.h.
idf_component_get_property(mbedtls_dir mbedtls COMPONENT_DIR)
target_include_directories(wallycore PRIVATE
    "${mbedtls_dir}/port/include"
    "${mbedtls_dir}/mbedtls/include"
    "${mbedtls_dir}/mbedtls/library")

# Expose wallycore (and transitively secp256k1) to components that require
# this component.
target_link_libraries(${COMPONENT_LIB} INTERFACE wallycore)
