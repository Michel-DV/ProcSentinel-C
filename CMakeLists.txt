cmake_minimum_required(VERSION 3.23)
project(ProcSentinelC VERSION 1.0.0 LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "ProcSentinel-C targets Windows and requires the Win32 API")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(procsentinel_core STATIC
    src/network.c
    src/pe.c
    src/process.c
    src/report.c
    src/scoring.c
    src/sha256.c
    src/signature.c
    src/util.c
)

target_include_directories(procsentinel_core PUBLIC include)
target_compile_definitions(procsentinel_core PUBLIC
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)
target_link_libraries(procsentinel_core PUBLIC
    advapi32
    bcrypt
    crypt32
    iphlpapi
    wintrust
    ws2_32
)

if(MSVC)
    target_compile_options(procsentinel_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(procsentinel_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(procsentinel src/main.c)
target_link_libraries(procsentinel PRIVATE procsentinel_core)
set_target_properties(procsentinel PROPERTIES OUTPUT_NAME "procsentinel")

include(CTest)
if(BUILD_TESTING)
    add_executable(procsentinel_tests tests/test_core.c)
    target_link_libraries(procsentinel_tests PRIVATE procsentinel_core)
    add_test(NAME procsentinel_core_tests COMMAND procsentinel_tests)
endif()
