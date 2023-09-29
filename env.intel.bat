@echo off

:: This is a batch file to set the environment variables for the project
:: It is not strictly necessary, but it provides you with type hints when working with the OpenCascade c++ library
:: distributed using conda-forge
::
:: mamba env update -f environment.build.yml --prune
:: mamba activate ada-cpp
::
:: Note!
:: You have to add a .env file to the root of the project where you set PREFIX=<path to your ada-cpp conda env>

set MY_PY_VER=311

:: set this file's parent directory as a variable
set THIS_DIR=%~dp0

:: read the .env file located in THIS_DIR and set the environment variables.
:: the .env file should contain a line like this:
:: PREFIX=C:\Users\your_user_name\mambaforge3\envs\ada-cpp
for /f "tokens=*" %%i in (%THIS_DIR%.env) do set %%i

call "%ONEAPI_ROOT%\setvars.bat"
echo %PATH%
echo %FC%

set "LONG_PATH=%IFORT_COMPILER23%"

for %%A in ("%LONG_PATH%") do set "SHORT_PATH=%%~sA"

echo Long Path:  %LONG_PATH%
echo Short Path: %SHORT_PATH%

::set FC=%SHORT_PATH%bin\ifx.exe
set FC=%SHORT_PATH%bin\intel64\ifort.exe

set LIBRARY_PREFIX=%PREFIX%/Library
set CMAKE_PREFIX_PATH=%PREFIX%;%LIBRARY_PREFIX%/include;%LIBRARY_PREFIX%/lib;%LIBRARY_PREFIX%/bin;

::set CMAKE_FORTRAN_COMPILER=%PREFIX%/Library/bin/flang.exe
::set CMAKE_Fortran_COMPILER=gfortran.exe
::set CMAKE_Fortran_PREPROCESS_SOURCE=ON
::set FC=%CMAKE_FORTRAN_COMPILER%
set HDF5_BUILD_FORTRAN=ON

set PYTHON_EXECUTABLE=%PREFIX%/python.exe
set PYTHON_LIBRARY=%PREFIX%/libs/python%MY_PY_VER%.lib