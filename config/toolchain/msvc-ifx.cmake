# Uncomment the following to use cross-compiling
#set (CMAKE_SYSTEM_NAME Linux)

set (CMAKE_COMPILER_VENDOR "MSVC")

if(WIN32)
    set (CMAKE_C_COMPILER cl)
    set (CMAKE_CXX_COMPILER cl)
    set (CMAKE_Fortran_COMPILER ifx)
    set (CMAKE_Fortran_FLAGS "/fpp /MD /assume:underscore")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)

# the following is used if cross-compiling
set (CMAKE_CROSSCOMPILING_EMULATOR "")
