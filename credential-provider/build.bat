@echo off
rem ============================================================================
rem  PawLockerProvider.dll build script
rem
rem  Requires the "Desktop development with C++" workload of Visual Studio.
rem  No CMake / MSBuild on purpose: calling vcvars64 + the compiler directly
rem  leaves fewer moving parts that can differ between machines.
rem
rem  Usage:   credential-provider\build.bat
rem  Output:  credential-provider\build\PawLockerProvider.dll
rem
rem  NOTE: keep this file ASCII-only. cmd.exe parses it in the OEM codepage,
rem  so non-ASCII comments turn into mojibake that can break parsing.
rem ============================================================================

setlocal
cd /d "%~dp0"

rem -- 1. locate Visual Studio ------------------------------------------------
rem Use the official vswhere rather than a hard-coded path: the VS major
rem version (17/18/...) changes over time and the install root is movable.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [x] vswhere.exe not found - Visual Studio is not installed
    exit /b 1
)

set "VSROOT="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%i"

if "%VSROOT%"=="" (
    echo [x] No Visual Studio installation with the C++ toolchain was found
    echo     Enable "Desktop development with C++" in the Visual Studio Installer
    exit /b 1
)
echo [*] Visual Studio: %VSROOT%

rem -- 2. initialise the x64 toolchain ----------------------------------------
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [x] vcvars64.bat failed
    exit /b 1
)

where cl.exe >nul 2>nul
if errorlevel 1 (
    echo [x] Compiler still not on PATH after vcvars64
    exit /b 1
)

rem -- 3. build ---------------------------------------------------------------
if not exist build mkdir build

echo [*] Compiling...

rem /LD          build a DLL
rem /std:c++17   language level
rem /utf-8       sources are UTF-8 (comments are Chinese). Without this MSVC
rem               assumes the OEM codepage and emits C4819.
rem /EHsc        C++ exception model (the code avoids throwing, the CRT needs it)
rem /W4 /WX      warnings are errors. This component runs inside LogonUI; a
rem               warning we ignore today can be why a user cannot log in later.
rem /O2          release optimisation
rem /guard:cf    Control Flow Guard - worth having for a logon component
rem /D_WIN32_WINNT=0x0A00   target Windows 10+
cl.exe /nologo /LD /std:c++17 /utf-8 /EHsc /W4 /WX /O2 /guard:cf ^
    /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 ^
    /I include /I src ^
    /Fo:build\ /Fd:build\PawLockerProvider.pdb ^
    src\Trace.cpp src\CredentialChannel.cpp src\Provider.cpp src\dllmain.cpp ^
    /link /DEF:PawLockerProvider.def /OUT:build\PawLockerProvider.dll ^
    /IMPLIB:build\PawLockerProvider.lib ^
    ole32.lib advapi32.lib secur32.lib wtsapi32.lib shlwapi.lib user32.lib kernel32.lib

if errorlevel 1 (
    echo.
    echo [x] Build failed
    exit /b 1
)

echo.
echo [+] Built: build\PawLockerProvider.dll
echo.
echo Next: pick "Credential provider" as the unlock method in PawLocker settings
echo       and register the DLL, or let the first-run wizard do it.
endlocal
