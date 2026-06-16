# Native MSVC toolchain marker (windows-latest). Relies on cl.exe from the VS dev environment.
cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    add_compile_definitions(NOMINMAX _ALLOW_COMPILER_AND_STL_VERSION_MISMATCH)
endif()
