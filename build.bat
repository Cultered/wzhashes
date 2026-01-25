@echo off
REM Build script for hashes_fast.cpp using MinGW-w64 (MSYS2)

echo ============================================================
echo Building hashes_fast.cpp with MinGW-w64 GCC...
echo ============================================================

set "GCC=C:\msys64\ucrt64\bin\g++.exe"

if not exist "%GCC%" (
    echo ERROR: GCC not found at %GCC%
    echo Please install MSYS2 and run: pacman -S mingw-w64-ucrt-x86_64-gcc
    exit /b 1
)

echo Using: %GCC%
echo.
echo Compiling with maximum optimizations...

"%GCC%" -O3 -march=native -mtune=native -std=c++17 -pthread ^
    -ffast-math -funroll-loops -flto ^
    -o hashes_fast.exe hashes_fast.cpp

if errorlevel 1 (
    echo.
    echo ERROR: Compilation failed!
    exit /b 1
)

echo.
echo ============================================================
echo Build successful! Run with: hashes_fast.exe
echo ============================================================
echo.
echo Usage:
echo   hashes_fast.exe                    - Interactive mode
echo   hashes_fast.exe "^bfc0"            - Pattern as argument
echo   hashes_fast.exe "^bfc0" 16         - Pattern and worker count
echo.
