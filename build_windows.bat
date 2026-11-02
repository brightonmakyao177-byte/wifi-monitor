@echo off
rem Builds dist\WiFiMonitor-Setup.exe. Needs Python 3 and Inno Setup 6 on this PC.
setlocal
cd /d "%~dp0"

py -3 -m venv .build-venv || goto :failed
call .build-venv\Scripts\activate.bat || goto :failed
python -m pip install --quiet pyinstaller || goto :failed
python -m unittest test_wifimon || goto :failed
pyinstaller --noconfirm --clean --windowed --name WiFiMonitor ^
    --add-data "dashboard.html;." --add-data "oui.csv;." wifimon.py || goto :failed

set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
"%ISCC%" installer.iss || goto :failed

echo.
echo Done: %CD%\dist\WiFiMonitor-Setup.exe
exit /b 0

:failed
echo.
echo The build failed. See the messages above.
exit /b 1
