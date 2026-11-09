# -- Build stamp -------------------------------------------------------------
# Stamps a target with the commit it was built from, so a device or a page can
# be identified without guessing from a build directory:
#
#   SEEDMIX_GIT_HASH    short commit hash, "-dirty" when tracked files differ
#   SEEDMIX_BUILD_DATE  configure-time date, YYYY-MM-DD
#
# Both are read once, when the build is configured.  A source tarball (no .git)
# leaves them "unknown" rather than failing the build.

function(seedmix_build_info target)
    set(git_hash "unknown")
    set(build_date "unknown")

    # CMAKE_CURRENT_SOURCE_DIR is the caller's, and both callers (the root list
    # file and platform/esp32/main) sit inside the repository.
    find_package(Git QUIET)
    if(GIT_FOUND)
        # Make the stamp self-refreshing: a commit or an index change re-runs
        # configure, so an incremental build cannot keep reporting the previous
        # commit.
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --absolute-git-dir
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE git_dir
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE git_dir_result)
        if(git_dir_result EQUAL 0 AND IS_DIRECTORY "${git_dir}")
            set(configure_depends "${git_dir}/HEAD" "${git_dir}/index")
            file(READ "${git_dir}/HEAD" head_ref LIMIT 200)
            string(REGEX MATCH "^ref: (.*)" ref_match "${head_ref}")
            if(ref_match AND CMAKE_MATCH_1)
                list(APPEND configure_depends "${git_dir}/${CMAKE_MATCH_1}")
            endif()
            set_property(DIRECTORY "${CMAKE_SOURCE_DIR}" APPEND PROPERTY
                         CMAKE_CONFIGURE_DEPENDS ${configure_depends})
        endif()

        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE hash
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            RESULT_VARIABLE rev_parse_result)
        if(rev_parse_result EQUAL 0 AND hash)
            set(git_hash "${hash}")

            # Tracked changes only: a build directory or an untracked scratch
            # file does not make the commit itself misleading.
            execute_process(
                COMMAND "${GIT_EXECUTABLE}" diff-index --quiet --no-ext-diff HEAD --
                WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                RESULT_VARIABLE diff_result)
            if(NOT diff_result EQUAL 0)
                set(git_hash "${git_hash}-dirty")
            endif()
        endif()
    endif()

    string(TIMESTAMP build_date "%Y-%m-%d")

    target_compile_definitions(${target} PRIVATE
        "SEEDMIX_GIT_HASH=\"${git_hash}\""
        "SEEDMIX_BUILD_DATE=\"${build_date}\"")
    message(STATUS "Build stamp: ${git_hash} ${build_date}")
endfunction()
