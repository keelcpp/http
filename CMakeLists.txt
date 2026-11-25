cmake_minimum_required(VERSION 3.20)
project(keel_http VERSION 0.2.0 LANGUAGES CXX)

option(KEEL_HTTP_NO_EXCEPTIONS_RTTI "Compile keel_http without C++ exceptions and RTTI" OFF)
option(KEEL_HTTP_BUILD_TESTS "Build keel_http unit tests and header purity checks" ${PROJECT_IS_TOP_LEVEL})

if(NOT TARGET keel::keel)
    find_package(keel QUIET CONFIG)
endif()
if(NOT TARGET keel::keel)
    include(FetchContent)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/keel/CMakeLists.txt" AND NOT DEFINED FETCHCONTENT_SOURCE_DIR_KEEL)
        set(FETCHCONTENT_SOURCE_DIR_KEEL "${CMAKE_CURRENT_SOURCE_DIR}/third_party/keel" CACHE PATH "Local keel checkout")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../keel/CMakeLists.txt" AND NOT DEFINED FETCHCONTENT_SOURCE_DIR_KEEL)
        set(FETCHCONTENT_SOURCE_DIR_KEEL "${CMAKE_CURRENT_SOURCE_DIR}/../keel" CACHE PATH "Local keel checkout")
    endif()
    if(KEEL_HTTP_NO_EXCEPTIONS_RTTI)
        set(KEEL_NO_EXCEPTIONS_RTTI ON CACHE BOOL "" FORCE)
    endif()
    FetchContent_Declare(
        keel
        GIT_REPOSITORY https://github.com/keelcpp/keel.git
        GIT_TAG        4b37783925fe7af7a64daaff90f268df267fbbf3
    )
    FetchContent_MakeAvailable(keel)
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
    POSITION_INDEPENDENT_CODE ON
)

target_include_directories(keel_http PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(keel_http PUBLIC keel::keel)

if(WIN32)
    target_link_libraries(keel_http PUBLIC winhttp)
elseif(EMSCRIPTEN)
    target_link_options(keel_http PUBLIC "SHELL:-s FETCH=1" "-lwebsocket.js")
else()
    find_package(Threads REQUIRED)
    target_link_libraries(keel_http PUBLIC Threads::Threads)
    find_package(CURL QUIET)
    if(CURL_FOUND)
        target_link_libraries(keel_http PRIVATE CURL::libcurl)
        target_compile_definitions(keel_http PRIVATE KEEL_HTTP_HAS_CURL=1)
    endif()
endif()

if(MSVC)
    target_compile_options(keel_http PRIVATE /W4 /utf-8)
    if(KEEL_HTTP_NO_EXCEPTIONS_RTTI)
        string(REGEX REPLACE "/EH[a-z]+" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        string(REGEX REPLACE "/GR" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        target_compile_options(keel_http PUBLIC /EHs-c- /GR-)
        target_compile_definitions(keel_http PUBLIC _HAS_EXCEPTIONS=0)
    endif()
else()
    target_compile_options(keel_http PRIVATE -Wall -Wextra -Wpedantic)
    if(KEEL_HTTP_NO_EXCEPTIONS_RTTI)
        target_compile_options(keel_http PUBLIC -fno-exceptions -fno-rtti)
    endif()
endif()

if(COMMAND keel_enforce_guidelines)
    keel_enforce_guidelines(keel_http
        SCOPE ALL
        BAN_RAW_INTS ALL
        BAN_RAW_FLOATS ALL
        HEADERS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
        STANDALONE_HEADERS ${KEEL_HTTP_BUILD_TESTS}
        TEST_NAME test_guidelines_headers
        WARNINGS OFF
    )
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

if(KEEL_HTTP_BUILD_TESTS)
    enable_testing()

    add_executable(test_http tests/test_http.cpp)
    target_link_libraries(test_http PRIVATE keel::http)
    if(MSVC)
        target_compile_options(test_http PRIVATE /W4 /utf-8)
    else()
        target_compile_options(test_http PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    if(COMMAND keel_enforce_guidelines)
        keel_enforce_guidelines(test_http
            SCOPE ALL
            BAN_RAW_INTS ALL
            BAN_RAW_FLOATS ALL
            WARNINGS OFF
        )
    endif()

    add_test(NAME test_http COMMAND test_http)
endif()
