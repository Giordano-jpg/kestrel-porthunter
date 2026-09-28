#!/usr/bin/env bash
# Arranque en Linux. Para escaneo SYN/ARP, -O y el monitor hace falta root: sudo ./iniciar.sh
set -e
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "Creando entorno virtual e instalando dependencias..."
    python3 -m venv .venv
    .venv/bin/pip install --disable-pip-version-check -r requirements.txt
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Aviso: sin root nmap usa connect scan (-sT), no ve MACs ni puede usar -O, y el monitor no captura."
    echo "       Para todo: sudo ./iniciar.sh"
fi

exec .venv/bin/python run.py "$@"
