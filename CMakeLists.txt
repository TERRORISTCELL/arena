cmake_minimum_required(VERSION 3.16)

# Default to the MinGW cross toolchain only when cross-compiling from a non-Windows host.
# On native Windows, use MSVC (or whatever generator/compiler the user selects).
if(NOT WIN32 AND NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/mingw-w64.cmake" CACHE FILEPATH "" FORCE)
endif()

project(arena C CXX ASM_NASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(arena STATIC
    src/error.cpp
    src/memory.cpp
    src/scan.cpp
    src/spoof.cpp
    asm/ret.nasm
)

target_include_directories(arena
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(MSVC)
    target_compile_definitions(arena PRIVATE NOMINMAX)
endif()

if(WIN32 OR CMAKE_CROSSCOMPILING)
    target_link_libraries(arena PUBLIC kernel32)
endif()

set_target_properties(arena PROPERTIES
    OUTPUT_NAME arena
)

add_executable(arena_link_test tests/link_test.cpp)
target_link_libraries(arena_link_test PRIVATE arena)

if(MSVC)
    target_compile_definitions(arena_link_test PRIVATE NOMINMAX)
endif()

add_executable(arena_lib_verify tests/lib_verify/verify.cpp)
target_link_libraries(arena_lib_verify PRIVATE arena)

if(MSVC)
    target_compile_definitions(arena_lib_verify PRIVATE NOMINMAX)
    target_compile_options(arena_lib_verify PRIVATE /EHa)
endif()

install(TARGETS arena ARCHIVE DESTINATION lib)
install(FILES include/arena.h DESTINATION include)
