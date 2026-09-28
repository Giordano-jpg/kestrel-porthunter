"""Diagnóstico del entorno: nmap, privilegios, Npcap, WSL y redes locales."""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import socket
import sys

from . import __version__, nmap_cmd
from .monitor import scapy_status


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def is_wsl() -> bool:
    return "microsoft" in platform.release().lower() or "WSL_DISTRO_NAME" in os.environ


def npcap_admin_only() -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
            return bool(winreg.QueryValueEx(k, "AdminOnly")[0])
    except OSError:
        return None


def _run(cmd: list[str]) -> str:
    import subprocess

    try:
        out = subprocess.run(cmd, capture_output=True, timeout=10,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return out.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return ""


def _system_addresses() -> tuple[list[tuple[str, str, int]], str | None]:
    """[(interfaz, ip, prefijo)] y la interfaz de la ruta por defecto, sin cargar Npcap."""
    rows: list[tuple[str, str, int]] = []
    default = None
    if sys.platform == "win32":
        script = (
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; "
            "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object { "
            "'A|' + $_.InterfaceAlias + '|' + $_.IPAddress + '|' + $_.PrefixLength }; "
            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
            "Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1 | "
            "ForEach-Object { 'D|' + $_.InterfaceAlias }"
        )
        for line in _run(["powershell", "-NoProfile", "-Command", script]).splitlines():
            parts = line.strip().split("|")
            if parts[0] == "A" and len(parts) == 4 and parts[3].isdigit():
                rows.append((parts[1], parts[2], int(parts[3])))
            elif parts[0] == "D" and len(parts) == 2:
                default = parts[1]
    else:
        for line in _run(["ip", "-o", "-4", "addr", "show"]).splitlines():
            m = re.search(r"^\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
            if m:
                rows.append((m.group(1), m.group(2), int(m.group(3))))
        m = re.search(r"\bdev\s+(\S+)", _run(["ip", "route", "show", "default"]))
        default = m.group(1) if m else None
    return rows, default


def local_networks() -> list[dict]:
    """Redes IPv4 de este equipo (para sugerir objetivos), sin APIPA ni loopback."""
    rows, default = _system_addresses()
    nets = []
    for iface, ip, plen in rows:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_link_local:
            continue
        nets.append({"iface": iface, "ip": ip, "default": iface == default,
                     "cidr": str(ipaddress.ip_network(f"{ip}/{plen}", strict=False))})
    nets.sort(key=lambda n: not n["default"])
    return nets


def diagnostics(settings: dict) -> dict:
    nmap = nmap_cmd.find_nmap(settings.get("nmap_path", ""))
    version = nmap_cmd.nmap_version(nmap) if nmap else None
    scapy_ok, scapy_msg = scapy_status(load=False)
    admin = is_admin()
    admin_only = npcap_admin_only()
    wsl = is_wsl()

    tips = []
    if not nmap:
        tips.append("No se encuentra nmap. Instálalo desde https://nmap.org/download o indica la ruta en Ajustes.")
    if sys.platform == "win32" and admin_only and not admin and not settings.get("unprivileged"):
        tips.append("Npcap está en modo 'sólo administradores': cada escaneo y el monitor pedirán "
                    "permiso (UAC). Arranca con iniciar.bat (pide permiso una sola vez), activa "
                    "'Modo sin privilegios' en Ajustes o reinstala Npcap sin la casilla "
                    "'Restrict Npcap driver's access to Administrators only'.")
    if sys.platform != "win32" and not admin:
        tips.append("Sin root nmap usa connect scan (-sT), no ve MACs y no puede usar -O; el monitor "
                    "tampoco puede capturar. Arranca con: sudo ./iniciar.sh")
    if wsl:
        tips.append("Estás en WSL: con la red NAT por defecto de WSL2 no se ve la LAN real (ni ARP ni MACs). "
                    "Ejecuta la app en Windows directamente, o activa networkingMode=mirrored en .wslconfig.")
    if not scapy_ok:
        tips.append("Monitor desactivado: " + scapy_msg)

    return {
        "app_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": socket.gethostname(),
        "admin": admin,
        "wsl": wsl,
        "nmap_path": nmap,
        "nmap_version": version,
        "npcap_admin_only": admin_only,
        "scapy": scapy_msg,
        "scapy_ok": scapy_ok,
        "networks": local_networks(),
        "tips": tips,
    }
