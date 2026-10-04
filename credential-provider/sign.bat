@echo off
rem ============================================================================
rem  PawLockerProvider.dll - code signing helper
rem
rem  Commands:
rem    sign.bat                  sign the built DLL with the development cert
rem    sign.bat devcert          create/refresh the development cert only
rem    sign.bat trust            trust that cert machine-wide (needs admin)
rem    sign.bat untrust          undo "trust"
rem    sign.bat verify           verify the DLL signature
rem    sign.bat cert <thumb>     sign with an existing certificate thumbprint
rem
rem  Why sign at all?
rem    Windows does not *require* a credential provider to be Authenticode
rem    signed, but an unsigned DLL loaded into LogonUI is refused by:
rem      - WDAC / AppLocker / Device Guard policies (any managed machine)
rem      - Smart App Control (Windows 11 22H2 and later)
rem      - most EDR products
rem    Signing is also the only way to detect that the DLL in Program Files was
rem    swapped. That directory is ACL-protected, but ACLs are not integrity.
rem
rem  A self-signed development certificate proves nothing to anyone else and
rem  will never satisfy SmartScreen or a customer's policy. For a release, use
rem  a real code-signing (EV) certificate or Azure Trusted Signing and run:
rem      sign.bat cert <thumbprint>
rem
rem  Keep this file ASCII-only - cmd.exe parses batch files in the OEM code
rem  page. Keep it CRLF-terminated - see .gitattributes.
rem ============================================================================

setlocal EnableExtensions
cd /d "%~dp0"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=sign"

set "DLL=build\PawLockerProvider.dll"
set "BUILD=build"
set "CER=%BUILD%\pawlocker-dev.cer"
set "THUMBFILE=%BUILD%\devcert.thumbprint"
set "PSCERT=%~dp0dev-cert.ps1"
set "SELF=%~f0"
set "TIMESTAMP_URL=http://timestamp.digicert.com"

rem -- locate signtool ---------------------------------------------------------
rem Order of preference: explicit override, then the newest SDK, then PATH.
set "SIGNTOOL="
if defined SIGNTOOL_EXE if exist "%SIGNTOOL_EXE%" set "SIGNTOOL=%SIGNTOOL_EXE%"

set "KITS=%ProgramFiles(x86)%\Windows Kits\10\bin"
if not defined SIGNTOOL if exist "%KITS%" for /f "delims=" %%d in ('dir /b /ad /o-n "%KITS%" 2^>nul') do if not defined SIGNTOOL if exist "%KITS%\%%d\x64\signtool.exe" set "SIGNTOOL=%KITS%\%%d\x64\signtool.exe"
if not defined SIGNTOOL for /f "delims=" %%s in ('where signtool.exe 2^>nul') do if not defined SIGNTOOL set "SIGNTOOL=%%s"

if /i "%ACTION%"=="devcert" goto :action_devcert
if /i "%ACTION%"=="trust"   goto :action_trust
if /i "%ACTION%"=="untrust" goto :action_untrust
if /i "%ACTION%"=="verify"  goto :action_verify
if /i "%ACTION%"=="cert"    goto :action_cert
if /i "%ACTION%"=="sign"    goto :action_sign

echo [x] Unknown command: %ACTION%
goto :usage


rem ============================================================================
:action_devcert
call :ensure_devcert
exit /b %errorlevel%


rem ============================================================================
:action_sign
call :ensure_dll
if errorlevel 1 exit /b 1
call :ensure_signtool
if errorlevel 1 exit /b 1
call :ensure_devcert
if errorlevel 1 exit /b 1

set "THUMB="
set /p THUMB=<"%THUMBFILE%"
if "%THUMB%"=="" (
    echo [x] Could not read the certificate thumbprint from %THUMBFILE%
    exit /b 1
)
call :do_sign "%THUMB%"
exit /b %errorlevel%


rem ============================================================================
:action_cert
if "%~2"=="" (
    echo [x] Usage: sign.bat cert ^<thumbprint^>
    echo     Find one with: certutil -user -store My
    exit /b 1
)
call :ensure_dll
if errorlevel 1 exit /b 1
call :ensure_signtool
if errorlevel 1 exit /b 1
call :do_sign "%~2"
exit /b %errorlevel%


rem ============================================================================
:action_trust
call :ensure_devcert
if errorlevel 1 exit /b 1

net session >nul 2>&1
if errorlevel 1 (
    echo [*] Administrator rights are required - requesting elevation...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath $env:SELF -ArgumentList 'trust'"
    if errorlevel 1 (
        echo [x] Elevation was declined.
        echo     Run this from an elevated prompt instead:  %SELF% trust
        exit /b 1
    )
    echo [*] Continue in the elevated window that just opened.
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSCERT%" trust
if errorlevel 1 (
    echo [x] Trusting the certificate failed.
    exit /b 1
)
exit /b 0


rem ============================================================================
:action_untrust
net session >nul 2>&1
if errorlevel 1 (
    echo [*] Administrator rights are required - requesting elevation...
    powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath $env:SELF -ArgumentList 'untrust'"
    if errorlevel 1 (
        echo [x] Elevation was declined.
        exit /b 1
    )
    exit /b 0
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%PSCERT%" untrust
exit /b %errorlevel%


rem ============================================================================
:action_verify
call :ensure_dll
if errorlevel 1 exit /b 1
call :ensure_signtool
if errorlevel 1 exit /b 1

echo [*] Verifying %DLL% with %SIGNTOOL%
"%SIGNTOOL%" verify /pa /v "%DLL%"
if errorlevel 1 (
    echo.
    echo [!] Verification failed. The usual reasons, in order of likelihood:
    echo     1. the certificate is not trusted on this machine yet
    echo           sign.bat trust        ^(accept the elevation prompt^)
    echo     2. the DLL has not been signed at all
    echo           sign.bat
    echo     3. the file was modified after signing
    echo           rebuild, then sign again
    exit /b 1
)
echo [+] Signature verified: %DLL%
exit /b 0


rem ============================================================================
rem  Subroutines
rem ============================================================================

:ensure_dll
if not exist "%DLL%" (
    echo [x] %DLL% not found - run build.bat first.
    exit /b 1
)
exit /b 0

:ensure_signtool
if not defined SIGNTOOL (
    echo [x] signtool.exe was not found.
    echo     Install the Windows SDK, or point SIGNTOOL_EXE at an existing copy.
    exit /b 1
)
exit /b 0

:ensure_devcert
if not exist "%BUILD%" mkdir "%BUILD%"
if exist "%THUMBFILE%" exit /b 0
echo [*] No development certificate yet - creating one.
powershell -NoProfile -ExecutionPolicy Bypass -File "%PSCERT%" ensure
if errorlevel 1 (
    echo [x] Could not create the development certificate.
    exit /b 1
)
exit /b 0

:do_sign
set "THUMB=%~1"
echo [*] Signing with certificate %THUMB%
"%SIGNTOOL%" sign /sha1 %THUMB% /fd SHA256 /tr "%TIMESTAMP_URL%" /td SHA256 /v "%DLL%"
if errorlevel 1 (
    echo.
    echo [!] Signing with a timestamp failed - retrying without one.
    echo     Offline? Then this is expected. An untimestamped signature simply
    echo     stops being trusted once the certificate expires.
    echo.
    "%SIGNTOOL%" sign /sha1 %THUMB% /fd SHA256 /v "%DLL%"
)
if errorlevel 1 (
    echo [x] Signing failed.
    exit /b 1
)
echo [+] Signed: %DLL%
echo.
echo Next: sign.bat verify   then   sign.bat trust ^(as administrator^)
exit /b 0

:usage
echo.
echo Usage: sign.bat [devcert ^| sign ^| trust ^| untrust ^| verify ^| cert ^<thumbprint^>]
echo.
echo   devcert   create/refresh the development certificate
echo   sign      sign the built DLL with the development certificate (default)
echo   trust     trust the development certificate machine-wide (needs admin)
echo   untrust   undo "trust"
echo   verify    verify the DLL signature
echo   cert      sign with an existing certificate thumbprint
echo.
exit /b 1
