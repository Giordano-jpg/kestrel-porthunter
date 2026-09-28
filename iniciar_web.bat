@echo off
setlocal
cd /d "%~dp0"
title Kestrel PortHunter (navegador)

REM Modo navegador: servidor en 127.0.0.1:8765 (solo accesible desde este equipo).
REM La app corre elevada, pero el navegador se abre desde esta ventana sin privilegios.
net session >nul 2>&1
if errorlevel 1 (
    echo Solicitando permisos de administrador...
    powershell -NoProfile -Command ^
      "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop } catch { Write-Host 'Permiso denegado.'; exit 1 };" ^
      "for ($i = 0; $i -lt 300; $i++) { $c = New-Object Net.Sockets.TcpClient;" ^
      "  try { $c.Connect('127.0.0.1', 8765); $c.Close(); Start-Process 'http://127.0.0.1:8765'; exit 0 } catch { Start-Sleep -Seconds 1 } }"
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

".venv\Scripts\python.exe" -c "import flask, scapy" >nul 2>&1
if errorlevel 1 ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt

".venv\Scripts\python.exe" run.py --web --no-browser
pause
