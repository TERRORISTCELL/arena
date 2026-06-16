# Cross-compile MSVC ABI static libs from Linux (clang-cl + xwin sysroot).
cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

if(NOT XWIN_SYSROOT)
    if(DEFINED ENV{XWIN_SYSROOT})
        set(XWIN_SYSROOT "$ENV{XWIN_SYSROOT}")
    elseif(EXISTS "$ENV{HOME}/.cache/cargo-xwin/xwin/sysroot")
        set(XWIN_SYSROOT "$ENV{HOME}/.cache/cargo-xwin/xwin/sysroot")
    elseif(EXISTS "$ENV{HOME}/.xwin/sysroot")
        set(XWIN_SYSROOT "$ENV{HOME}/.xwin/sysroot")
    else()
        message(FATAL_ERROR "XWIN_SYSROOT not found. Install cargo-xwin and run: cargo xwin cache xwin --accept-license")
    endif()
endif()

find_program(CLANG_CL NAMES clang-cl clang REQUIRED)
find_program(LLVM_AR NAMES llvm-ar lib REQUIRED)

set(CMAKE_C_COMPILER "${CLANG_CL}")
set(CMAKE_CXX_COMPILER "${CLANG_CL}")
set(CMAKE_AR "${LLVM_AR}")

if(CMAKE_C_COMPILER MATCHES "clang$")
    set(_TARGET_FLAG "--target=x86_64-pc-windows-msvc")
else()
    set(_TARGET_FLAG "")
endif()

set(CMAKE_C_FLAGS_INIT "${_TARGET_FLAG} /MD /W3 /DNOMINMAX /D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")
set(CMAKE_CXX_FLAGS_INIT "${_TARGET_FLAG} /MD /W3 /EHsc /std:c++20 /DNOMINMAX /D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")

set(CMAKE_SYSROOT "${XWIN_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH "${XWIN_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

set(CMAKE_ASM_NASM_COMPILER nasm)
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)
