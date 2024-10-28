# Uncomment the following to use cross-compiling
#set (CMAKE_SYSTEM_NAME Linux)

set (CMAKE_COMPILER_VENDOR "clang")

if(WIN32)
    set (CMAKE_C_COMPILER clang-cl)
    set (CMAKE_CXX_COMPILER clang-cl)
    set (CMAKE_Fortran_COMPILER flang-new)
    set (CMAKE_Fortran_FLAGS "-cpp -D_CRT_SECURE_NO_WARNINGS -D_MT -D_DLL --target=x86_64-pc-windows-msvc -w")
    set (CMAKE_C_FLAGS "-w")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# the following is used if cross-compiling
#set (CMAKE_CROSSCOMPILING_EMULATOR "")
