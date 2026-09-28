@echo off
setlocal
cd /d "%~dp0"
title Kestrel PortHunter

REM Ventana de escritorio: sin navegador y sin abrir ningun puerto.
REM Npcap suele estar en modo "solo administradores": arrancando elevados se pide
REM permiso (UAC) una sola vez aqui en vez de en cada escaneo o captura.
net session >nul 2>&1
if errorlevel 1 (
    echo Solicitando permisos de administrador...
    powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { Write-Host 'Permiso denegado.'; Start-Sleep -Seconds 3 }"
    exit /b
)

if not exist ".venv\Scripts\python.exe" (
    echo Creando entorno virtual...
    py -3 -m venv .venv 2>nul || python -m venv .venv
    if errorlevel 1 (
        echo No se encuentra Python. Instalalo desde https://www.python.org/downloads/
        pause
        exit /b 1
    )
)

".venv\Scripts\python.exe" -c "import flask, scapy, webview" >nul 2>&1
if errorlevel 1 (
    echo Instalando dependencias...
    ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        pause
        exit /b 1
    )
)

REM pythonw: sin ventana de consola. Los errores van a data\porthunter.log.
start "" ".venv\Scripts\pythonw.exe" run.py --desktop
