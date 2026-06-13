@echo off
:: WifiCat - BW16 firmware flasher (self-contained)
:: Usage:  flash_bw16.bat COM5
setlocal
set PORT=%1
if "%PORT%"=="" (
    echo Usage: flash_bw16.bat ^<COM_PORT^>
    echo Example: flash_bw16.bat COM5
    exit /b 1
)
if not exist "upload_image.exe" (
    echo [ERR] run this from the flasher folder ^(upload_image.exe missing^)
    exit /b 1
)
echo Put the BW16 in download mode: hold BURN, tap RESET, release BURN.
echo Then press any key to flash on %PORT% ...
pause >nul
echo [*] Flashing WifiCat firmware...
upload_image.exe .\bins %PORT%
if %ERRORLEVEL%==0 (
    echo [OK] Done. Press RESET on the BW16 to boot WifiCat.
) else (
    echo [ERR] Flash failed ^(code %ERRORLEVEL%^). Wrong COM port or not in download mode?
)
endlocal
