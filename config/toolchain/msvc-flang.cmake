# Uncomment the following to use cross-compiling
#set (CMAKE_SYSTEM_NAME Linux)

set (CMAKE_COMPILER_VENDOR "clang")

if(WIN32)
    set (CMAKE_C_COMPILER clang-cl)
    set (CMAKE_CXX_COMPILER clang-cl)
    set (CMAKE_Fortran_COMPILER flang-new)
    # Set fortran flags to fix intrinsics SIZEOF and STORAGE_SIZE
    set (CMAKE_Fortran_FLAGS "--driver-mode=cl")
    # Add verbose flag to see the commands
    set (CMAKE_VERBOSE_MAKEFILE ON)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# the following is used if cross-compiling
set (CMAKE_CROSSCOMPILING_EMULATOR "")
