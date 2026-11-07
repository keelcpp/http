# Verifies that all public keel_http headers:
# 1. Only contain `#include <cstddef>`, `#include <cstdint>`, or `#include <new>` as angle-bracket includes.
# 2. When compiled standalone with `/showIncludes` (MSVC) or `-H` (Clang/GCC), do not transitively include
#    any system header outside the exact baseline of `<cstddef> + <cstdint> + <new>`.

if(NOT DEFINED KEEL_HTTP_INCLUDE_DIR)
    message(FATAL_ERROR "KEEL_HTTP_INCLUDE_DIR must be passed to CheckHeaderPurity.cmake")
endif()

file(GLOB KEEL_HTTP_PUBLIC_HEADERS "${KEEL_HTTP_INCLUDE_DIR}/keel/*.h" "${KEEL_HTTP_INCLUDE_DIR}/keel/*.hpp")

set(ALLOWED_STD_HEADERS "cstddef" "cstdint" "new")

foreach(HDR IN LISTS KEEL_HTTP_PUBLIC_HEADERS)
    get_filename_component(HDR_NAME "${HDR}" NAME)
    file(STRINGS "${HDR}" INCLUDE_LINES REGEX "^[ \t]*#[ \t]*include[ \t]*<[^>]+>")
    foreach(LINE IN LISTS INCLUDE_LINES)
        string(REGEX REPLACE "^[ \t]*#[ \t]*include[ \t]*<([^>]+)>.*$" "\\1" INC_NAME "${LINE}")
        if(NOT INC_NAME IN_LIST ALLOWED_STD_HEADERS)
            message(FATAL_ERROR "Header purity violation in ${HDR_NAME}: forbidden '#include <${INC_NAME}>'. Only <cstddef>, <cstdint>, <new> are allowed.")
        endif()
    endforeach()
endforeach()

if(DEFINED COMPILER_PATH AND EXISTS "${COMPILER_PATH}")
    set(SCRATCH_DIR "${CMAKE_BINARY_DIR}/header_purity_check")
    file(MAKE_DIRECTORY "${SCRATCH_DIR}")

    set(SYS_INC_FLAGS "")
    if(DEFINED STD_INC_DIRS AND NOT STD_INC_DIRS STREQUAL "")
        string(REPLACE "|" ";" STD_INC_LIST "${STD_INC_DIRS}")
        foreach(SDIR IN LISTS STD_INC_LIST)
            if(COMPILER_ID MATCHES "MSVC")
                list(APPEND SYS_INC_FLAGS "/I${SDIR}")
            else()
                list(APPEND SYS_INC_FLAGS "-isystem" "${SDIR}")
            endif()
        endforeach()
    endif()

    if(COMPILER_ID MATCHES "MSVC" AND "$ENV{INCLUDE}" STREQUAL "" AND SYS_INC_FLAGS STREQUAL "")
        get_filename_component(CL_DIR1 "${COMPILER_PATH}" DIRECTORY)
        get_filename_component(CL_DIR2 "${CL_DIR1}" DIRECTORY)
        get_filename_component(CL_DIR3 "${CL_DIR2}" DIRECTORY)
        get_filename_component(MSVC_ROOT "${CL_DIR3}" DIRECTORY)
        if(EXISTS "${MSVC_ROOT}/include")
            list(APPEND SYS_INC_FLAGS "/I${MSVC_ROOT}/include")
        endif()
        file(GLOB WIN_SDK_VERSIONS "C:/Program Files (x86)/Windows Kits/10/Include/10.*")
        if(WIN_SDK_VERSIONS)
            list(SORT WIN_SDK_VERSIONS ORDER DESCENDING)
            list(GET WIN_SDK_VERSIONS 0 LATEST_SDK)
            if(EXISTS "${LATEST_SDK}/ucrt")
                list(APPEND SYS_INC_FLAGS "/I${LATEST_SDK}/ucrt")
            endif()
            if(EXISTS "${LATEST_SDK}/shared")
                list(APPEND SYS_INC_FLAGS "/I${LATEST_SDK}/shared")
            endif()
        endif()
    endif()

    set(BASELINE_SRC "${SCRATCH_DIR}/baseline.cpp")
    file(WRITE "${BASELINE_SRC}" "#include <cstddef>\n#include <cstdint>\n#include <new>\nint main() { return 0; }\n")

    if(COMPILER_ID MATCHES "MSVC")
        execute_process(
            COMMAND "${COMPILER_PATH}" /nologo /std:c++20 /Zs /showIncludes ${SYS_INC_FLAGS} "${BASELINE_SRC}"
            OUTPUT_VARIABLE BASELINE_OUT
            ERROR_VARIABLE BASELINE_ERR
            RESULT_VARIABLE BASELINE_RES
        )
        set(COMBINED_BASELINE "${BASELINE_OUT}\n${BASELINE_ERR}")
    else()
        execute_process(
            COMMAND "${COMPILER_PATH}" -std=c++20 -fsyntax-only -H ${SYS_INC_FLAGS} "${BASELINE_SRC}"
            OUTPUT_VARIABLE BASELINE_OUT
            ERROR_VARIABLE BASELINE_ERR
            RESULT_VARIABLE BASELINE_RES
        )
        set(COMBINED_BASELINE "${BASELINE_OUT}\n${BASELINE_ERR}")
    endif()

    if(NOT BASELINE_RES EQUAL 0)
        message(FATAL_ERROR "Failed to compile baseline for header purity check:\n${COMBINED_BASELINE}")
    endif()

    set(ALLOWED_PATHS "")
    string(REPLACE "\r\n" "\n" COMBINED_BASELINE "${COMBINED_BASELINE}")
    string(REPLACE "\n" ";" BASELINE_LINES "${COMBINED_BASELINE}")
    foreach(BLINE IN LISTS BASELINE_LINES)
        if(COMPILER_ID MATCHES "MSVC")
            if(BLINE MATCHES "Note: including file:[ \t]*(.+)$")
                string(STRIP "${CMAKE_MATCH_1}" INC_PATH)
                file(TO_CMAKE_PATH "${INC_PATH}" INC_PATH_NORM)
                string(TOLOWER "${INC_PATH_NORM}" INC_PATH_NORM)
                list(APPEND ALLOWED_PATHS "${INC_PATH_NORM}")
            endif()
        else()
            if(BLINE MATCHES "^\\.+ ([^ ]+)$")
                string(STRIP "${CMAKE_MATCH_1}" INC_PATH)
                file(TO_CMAKE_PATH "${INC_PATH}" INC_PATH_NORM)
                list(APPEND ALLOWED_PATHS "${INC_PATH_NORM}")
            endif()
        endif()
    endforeach()

    file(TO_CMAKE_PATH "${KEEL_HTTP_INCLUDE_DIR}" KEEL_HTTP_DIR_NORM)
    file(TO_CMAKE_PATH "${KEEL_CORE_INCLUDE_DIR}" KEEL_CORE_DIR_NORM)
    if(COMPILER_ID MATCHES "MSVC")
        string(TOLOWER "${KEEL_HTTP_DIR_NORM}" KEEL_HTTP_DIR_NORM)
        string(TOLOWER "${KEEL_CORE_DIR_NORM}" KEEL_CORE_DIR_NORM)
    endif()

    foreach(HDR IN LISTS KEEL_HTTP_PUBLIC_HEADERS)
        get_filename_component(HDR_NAME "${HDR}" NAME)
        set(TEST_SRC "${SCRATCH_DIR}/test_${HDR_NAME}.cpp")
        file(WRITE "${TEST_SRC}" "#include \"keel/${HDR_NAME}\"\nint main() { return 0; }\n")

        if(COMPILER_ID MATCHES "MSVC")
            execute_process(
                COMMAND "${COMPILER_PATH}" /nologo /std:c++20 /Zs /showIncludes "/I${KEEL_HTTP_INCLUDE_DIR}" "/I${KEEL_CORE_INCLUDE_DIR}" ${SYS_INC_FLAGS} "${TEST_SRC}"
                OUTPUT_VARIABLE HDR_OUT
                ERROR_VARIABLE HDR_ERR
                RESULT_VARIABLE HDR_RES
            )
            set(COMBINED_HDR "${HDR_OUT}\n${HDR_ERR}")
        else()
            execute_process(
                COMMAND "${COMPILER_PATH}" -std=c++20 -fsyntax-only -H "-I${KEEL_HTTP_INCLUDE_DIR}" "-I${KEEL_CORE_INCLUDE_DIR}" ${SYS_INC_FLAGS} "${TEST_SRC}"
                OUTPUT_VARIABLE HDR_OUT
                ERROR_VARIABLE HDR_ERR
                RESULT_VARIABLE HDR_RES
            )
            set(COMBINED_HDR "${HDR_OUT}\n${HDR_ERR}")
        endif()

        if(NOT HDR_RES EQUAL 0)
            message(FATAL_ERROR "Standalone compilation failed for ${HDR_NAME}:\n${COMBINED_HDR}")
        endif()

        string(REPLACE "\r\n" "\n" COMBINED_HDR "${COMBINED_HDR}")
        string(REPLACE "\n" ";" HDR_LINES "${COMBINED_HDR}")
        foreach(HLINE IN LISTS HDR_LINES)
            set(FOUND_INC "")
            if(COMPILER_ID MATCHES "MSVC")
                if(HLINE MATCHES "Note: including file:[ \t]*(.+)$")
                    string(STRIP "${CMAKE_MATCH_1}" FOUND_INC)
                    file(TO_CMAKE_PATH "${FOUND_INC}" FOUND_INC)
                    string(TOLOWER "${FOUND_INC}" FOUND_INC)
                endif()
            else()
                if(HLINE MATCHES "^\\.+ ([^ ]+)$")
                    string(STRIP "${CMAKE_MATCH_1}" FOUND_INC)
                    file(TO_CMAKE_PATH "${FOUND_INC}" FOUND_INC)
                endif()
            endif()

            if(NOT FOUND_INC STREQUAL "")
                string(FIND "${FOUND_INC}" "${KEEL_HTTP_DIR_NORM}" IS_KEEL_HTTP_HDR)
                string(FIND "${FOUND_INC}" "${KEEL_CORE_DIR_NORM}" IS_KEEL_CORE_HDR)
                if(NOT IS_KEEL_HTTP_HDR EQUAL 0 AND NOT IS_KEEL_CORE_HDR EQUAL 0)
                    if(NOT FOUND_INC IN_LIST ALLOWED_PATHS)
                        message(FATAL_ERROR "Transitive header purity violation in ${HDR_NAME}: pulled in external system header '${FOUND_INC}'")
                    endif()
                endif()
            endif()
        endforeach()
    endforeach()
endif()

message(STATUS "Header purity check passed for all keel_http headers.")
