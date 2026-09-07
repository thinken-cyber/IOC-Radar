@echo off
setlocal EnableExtensions

set "PACKAGE=%~dp0IOC-Radar-final.zip"
set "TARGET=%LOCALAPPDATA%\IOC-Radar"
set "BACKEND=https://ioc-radar.onrender.com/health"

if not exist "%PACKAGE%" (
  echo [ERROR] Khong tim thay IOC-Radar-final.zip.
  echo Dat file install-ioc-radar.bat cung thu muc voi file ZIP extension.
  pause
  exit /b 1
)

echo [1/5] Kiem tra Chrome...
set "CHROME="
for %%P in ("%ProgramFiles%\Google\Chrome\Application\chrome.exe" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe") do (
  if not defined CHROME if exist "%%~P" set "CHROME=%%~P"
)
if not defined CHROME echo [WARN] Khong tim thay Chrome, se mo bang trinh duyet mac dinh.

echo [2/5] Kiem tra backend Render...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r=Invoke-RestMethod -Uri '%BACKEND%' -TimeoutSec 20; if ($r.ok -eq $true) { exit 0 } else { exit 2 } } catch { exit 3 }"
if errorlevel 1 (
  echo [WARN] Khong ket noi duoc backend. Extension van duoc cai, nhung co the chua quet duoc IOC.
) else (
  echo [OK] Backend Render dang san sang.
)

echo [3/5] Giai nen extension vao:
echo        %TARGET%
if exist "%TARGET%" rmdir /s /q "%TARGET%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%PACKAGE%' -DestinationPath '%TARGET%' -Force"
if errorlevel 1 (
  echo [ERROR] Giai nen that bai.
  pause
  exit /b 1
)

if not exist "%TARGET%\manifest.json" (
  echo [ERROR] Khong tim thay manifest.json trong ban extension.
  pause
  exit /b 1
)

for /f "usebackq delims=" %%V in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-Content -Raw '%TARGET%\manifest.json' | ConvertFrom-Json).version"`) do set "VERSION=%%V"
if not defined VERSION set "VERSION=unknown"
echo [OK] IOC Radar version %VERSION% da san sang.

echo [4/5] Mo trang quan ly extension...
if defined CHROME (
  start "" "%CHROME%" "chrome://extensions"
) else (
  start "" "chrome://extensions"
)

echo [5/5] Huong dan cuoi cung
 echo.
echo 1. Bat Developer mode.
echo 2. Chon Load unpacked.
echo 3. Chon thu muc:
echo    %TARGET%
echo 4. Neu da cai ban cu, bam Reload tren extension.
echo.
echo Cai dat da hoan tat phan tu dong. Chrome yeu cau ban xac nhan Load unpacked mot lan.
pause
endlocal
