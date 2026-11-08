#[=======================================================================[
Build libwally-core from the external/libwally-core submodule.

Uses ExternalProject to run autogen/configure/make and install into the
build tree.  After inclusion, the following are available:

  LIBWALLY_INCLUDE_DIR    - path to wally_core.h etc.
  LIBWALLY_LIBRARY        - path to libwallycore.a (static)
  libwally                - CMake IMPORTED target
#]=======================================================================]

include(ExternalProject)

set(LIBWALLY_SOURCE_DIR  ${CMAKE_SOURCE_DIR}/external/libwally-core)
set(LIBWALLY_INSTALL_DIR ${CMAKE_BINARY_DIR}/libwally-install)
set(LIBWALLY_INCLUDE_DIR ${LIBWALLY_INSTALL_DIR}/include)
set(LIBWALLY_LIBRARY     ${LIBWALLY_INSTALL_DIR}/lib/libwallycore.a)
set(LIBSECP256K1_LIBRARY ${LIBWALLY_INSTALL_DIR}/lib/libsecp256k1.a)

if(NOT EXISTS ${LIBWALLY_SOURCE_DIR}/tools/autogen.sh)
    message(FATAL_ERROR
        "libwally-core submodule not found at ${LIBWALLY_SOURCE_DIR}\n"
        "Run:  git submodule update --init")
endif()

# Emscripten: build libwally with emcc in a pristine COPY of the source tree
# (under the CMake binary dir).  Both platforms build in-source, so the WASM
# objects never collide with the native Linux in-source build.  A VPATH build
# is not viable because the Linux build leaves in-source artifacts
# (config.status, *.la) in the shared source tree, which confuse make's VPATH
# search.  `git archive` produces a clean tree with no build artifacts.
# Both platforms configure through scripts/configure_libwally.sh, which only
# redoes the destructive part (wipe + `git archive` extract + autogen +
# configure) when the revision or install prefix actually changed.  An
# ExternalProject's configure step re-runs whenever CMake regenerates its build
# files - i.e. on every reconfigure - and doing the wipe there threw away all of
# libwally's and secp256k1's objects each time.
if(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    set(LIBWALLY_MAKE_WRAPPER emmake)
    set(LIBWALLY_BUILD_DIR ${CMAKE_BINARY_DIR}/libwally-src)
    set(LIBWALLY_EXTRA_ARGS BINARY_DIR ${LIBWALLY_BUILD_DIR})
    set(LIBWALLY_BUILD_IN_SOURCE 0)
    # A pristine tree in the build dir via git archive avoids both the shared
    # in-source artifacts and make's VPATH search seeing stale *.la files.
    set(LIBWALLY_MODE emscripten)
else()
    set(LIBWALLY_MAKE_WRAPPER "")
    set(LIBWALLY_EXTRA_ARGS)
    set(LIBWALLY_BUILD_IN_SOURCE 1)
    set(LIBWALLY_BUILD_DIR ${LIBWALLY_SOURCE_DIR})
    set(LIBWALLY_MODE native)
endif()

set(LIBWALLY_CONFIGURE_COMMAND
    ${CMAKE_SOURCE_DIR}/scripts/configure_libwally.sh
        ${LIBWALLY_SOURCE_DIR}
        ${LIBWALLY_BUILD_DIR}
        ${LIBWALLY_INSTALL_DIR}
        ${LIBWALLY_MODE}
        ${CMAKE_BINARY_DIR}/libwally-configured.stamp)

ExternalProject_Add(libwally_ext
    ${LIBWALLY_EXTRA_ARGS}
    SOURCE_DIR        ${LIBWALLY_SOURCE_DIR}
    CONFIGURE_COMMAND ${LIBWALLY_CONFIGURE_COMMAND}
    BUILD_COMMAND     ${LIBWALLY_MAKE_WRAPPER} $(MAKE) -j
    INSTALL_COMMAND   ${LIBWALLY_MAKE_WRAPPER} $(MAKE) install
    BUILD_IN_SOURCE   ${LIBWALLY_BUILD_IN_SOURCE}
    BUILD_BYPRODUCTS  ${LIBWALLY_LIBRARY}
    USES_TERMINAL_CONFIGURE OFF
    USES_TERMINAL_BUILD     OFF
    USES_TERMINAL_INSTALL   OFF
)

# Ensure the install directories exist at configure time so the
# IMPORTED target's properties resolve
file(MAKE_DIRECTORY ${LIBWALLY_INCLUDE_DIR})
file(MAKE_DIRECTORY ${LIBWALLY_INSTALL_DIR}/lib)

# Create an IMPORTED target so we can link with `libwally` + `libsecp256k1`
add_library(libwally STATIC IMPORTED GLOBAL)
add_dependencies(libwally libwally_ext)
set_target_properties(libwally PROPERTIES
    IMPORTED_LOCATION ${LIBWALLY_LIBRARY}
    INTERFACE_INCLUDE_DIRECTORIES ${LIBWALLY_INCLUDE_DIR}
    INTERFACE_LINK_LIBRARIES ${LIBSECP256K1_LIBRARY}
)

message(STATUS "libwally will be built from submodule -> ${LIBWALLY_INSTALL_DIR}")
