cmake_minimum_required(VERSION 3.20)
project(keel_http VERSION 0.1.0 LANGUAGES CXX)

option(KEEL_HTTP_NO_EXCEPTIONS_RTTI "Compile keel_http without C++ exceptions and RTTI" OFF)
option(KEEL_HTTP_BUILD_TESTS "Build keel_http unit tests and header purity checks" ${PROJECT_IS_TOP_LEVEL})

if( NOT TARGET keel::keel )
    if( EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/keel/CMakeLists.txt" )
        add_subdirectory(third_party/keel EXCLUDE_FROM_ALL)
    elseif( EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../keel/CMakeLists.txt" )
        add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../keel" "${CMAKE_CURRENT_BINARY_DIR}/keel" EXCLUDE_FROM_ALL)
    else()
        find_package(keel REQUIRED)
    endif()
endif()

add_library(keel_http STATIC
    src/http.cpp
)
add_library(keel::http ALIAS keel_http)

target_compile_features(keel_http PUBLIC cxx_std_20)
set_target_properties(keel_http PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_include_directories(keel_http PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(keel_http PUBLIC keel::keel)

if( WIN32 )
    target_link_libraries(keel_http PUBLIC winhttp)
elseif( EMSCRIPTEN )
    target_link_options(keel_http PUBLIC "SHELL:-s FETCH=1" "-lwebsocket.js")
else()
    find_package(Threads REQUIRED)
    target_link_libraries(keel_http PUBLIC Threads::Threads)
    find_package(CURL QUIET)
    if( CURL_FOUND )
        target_link_libraries(keel_http PRIVATE CURL::libcurl)
        target_compile_definitions(keel_http PRIVATE KEEL_HTTP_HAS_CURL=1)
    endif()
endif()

if( MSVC )
    target_compile_options(keel_http PRIVATE /W4 /utf-8)
    if( KEEL_HTTP_NO_EXCEPTIONS_RTTI )
        string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        string(REGEX REPLACE "/GR" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        target_compile_options(keel_http PUBLIC /EHs-c- /GR-)
        target_compile_definitions(keel_http PUBLIC _HAS_EXCEPTIONS=0)
    endif()
else()
    target_compile_options(keel_http PRIVATE -Wall -Wextra -Wpedantic)
    if( KEEL_HTTP_NO_EXCEPTIONS_RTTI )
        target_compile_options(keel_http PUBLIC -fno-exceptions -fno-rtti)
    endif()
endif()

# Install & package support (`find_package(keel_http)`)
include(CMakePackageConfigHelpers)
install(TARGETS keel_http EXPORT keel_httpTargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/keel DESTINATION include)
install(EXPORT keel_httpTargets
    FILE keel_httpTargets.cmake
    NAMESPACE keel::
    DESTINATION lib/cmake/keel_http
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/keel_httpConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_httpConfig.cmake"
    INSTALL_DESTINATION lib/cmake/keel_http
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/keel_httpConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/keel_httpConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/keel_httpConfigVersion.cmake"
    DESTINATION lib/cmake/keel_http
)

if( KEEL_HTTP_BUILD_TESTS )
    enable_testing()

    add_executable(test_http tests/test_http.cpp)
    target_link_libraries(test_http PRIVATE keel::http)
    if( MSVC )
        target_compile_options(test_http PRIVATE /W4 /utf-8)
    else()
        target_compile_options(test_http PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME test_http COMMAND test_http)

    get_target_property(KEEL_CORE_INC_DIRS keel::keel INTERFACE_INCLUDE_DIRECTORIES)
    list(GET KEEL_CORE_INC_DIRS 0 KEEL_CORE_INC_DIR)
    string(REGEX REPLACE "^\\$<BUILD_INTERFACE:([^>]+)>$" "\\1" KEEL_CORE_INC_DIR "${KEEL_CORE_INC_DIR}")

    string(REPLACE ";" "|" KEEL_STD_INC_JOINED "${CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES}")
    add_test(
        NAME test_header_purity
        COMMAND ${CMAKE_COMMAND}
            "-DKEEL_HTTP_INCLUDE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/include"
            "-DKEEL_CORE_INCLUDE_DIR=${KEEL_CORE_INC_DIR}"
            "-DCOMPILER_PATH=${CMAKE_CXX_COMPILER}"
            "-DCOMPILER_ID=${CMAKE_CXX_COMPILER_ID}"
            "-DSTD_INC_DIRS=${KEEL_STD_INC_JOINED}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckHeaderPurity.cmake"
    )
endif()
