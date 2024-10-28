@echo off
setlocal

:: Set this dir as the current dir
cd %~dp0

:: Define paths
set FC=%CONDA_PREFIX%/Library/bin/flang-new.exe
set FLANG_COMPILER=%FC%

:: set the source file as the input argument
set SOURCE_FILE=%1
:: set the output executable name as the same as the source file name, but with .exe extension
set OUTPUT_EXECUTABLE=%SOURCE_FILE:.f90=.exe%

:: extra arguments can be passed to the script (multiple arguments after the source file %1)
set EXTRA_ARGS=%2 %3 %4 %5 %6 %7 %8 %9

echo "FC=%FC%"
echo "FLANG_COMPILER=%FLANG_COMPILER%"

:: Check if flang compiler exists
if not exist %FLANG_COMPILER% (
    echo ERROR: flang-new compiler not found at %FLANG_COMPILER%.
    exit /b 1
)

:: Compile the Fortran program
echo Compiling %SOURCE_FILE% with flang-new...
%FLANG_COMPILER% %SOURCE_FILE% -o %OUTPUT_EXECUTABLE% %EXTRA_ARGS%
if %errorlevel% neq 0 (
    echo Compilation failed.
    exit /b 1
)

:: Run the executable
echo Running %OUTPUT_EXECUTABLE%...
%OUTPUT_EXECUTABLE%
if %errorlevel% neq 0 (
    echo Execution failed.
    exit /b 1
)

:: Clean up (optional)
echo Cleaning up generated executable...
del %OUTPUT_EXECUTABLE%

echo Done.
endlocal
