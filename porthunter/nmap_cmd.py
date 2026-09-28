"""Localización de nmap, perfiles de escaneo y construcción de comandos."""

from __future__ import annotations

import functools
import os
import re
import shlex
import shutil
import subprocess
import sys

COMMON_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
    "/snap/bin/nmap",
]

# Perfiles de escaneo de puertos. "raw" = necesita paquetes en bruto (Npcap/root).
PORT_PROFILES: dict[str, dict] = {
    "rapido": {
        "label": "Rápido: 100 puertos más comunes (-F)",
        "args": ["-F"],
    },
    "estandar": {
        "label": "Estándar: 1000 puertos más comunes",
        "args": [],
    },
    "servicios": {
        "label": "Servicios y versiones: 1000 puertos (-sV)",
        "args": ["-sV", "--version-light"],
    },
    "windows": {
        "label": "Equipos Windows: SMB/RDP/WinRM + nombre NetBIOS",
        "args": ["-sS", "-sU", "-p", "U:137,T:135,139,445,3389,5985,5986", "--script", "nbstat"],
        "raw": True,
    },
    "completo": {
        "label": "Completo: los 65535 puertos TCP (-p-)",
        "args": ["-p-"],
    },
    "completo_sv": {
        "label": "Completo + versiones (-p- -sV), lento",
        "args": ["-p-", "-sV", "--version-light"],
    },
    "so": {
        "label": "Sistema operativo (-O) + 1000 puertos",
        "args": ["-O", "--osscan-guess"],
        "raw": True,
    },
    "udp": {
        "label": "UDP: 50 puertos más comunes (-sU), lento",
        "args": ["-sU", "--top-ports", "50"],
        "raw": True,
    },
}

# Sondas extra para -sn: detectan equipos Windows con el firewall que ignora el ping.
REINFORCED_PING = ["-PE", "-PP", "-PS21,22,23,80,135,139,443,445,3389,8080", "-PA80,443"]

TIMINGS = {"T2": "-T2", "T3": "-T3", "T4": "-T4", "T5": "-T5"}

# Opciones que no se permiten en los argumentos libres: la app gestiona ella misma
# la salida (-oX) y la entrada (-iL), y no queremos escritura/lectura de ficheros arbitrarios.
_FORBIDDEN = (
    "-o", "-iL", "-iR", "--resume", "--datadir", "--servicedb", "--versiondb",
    "--stylesheet", "--script-args-file", "--excludefile", "--append-output",
    "--log-errors", "--script-updatedb", "--stats-every", "--interactive",
)
_FORBIDDEN_EXACT = {"-oX", "-oN", "-oG", "-oA", "-oS", "-oM"}
_PATHLIKE_RE = re.compile(r"[\\/]|\.\.|^[A-Za-z]:")


class ArgsError(ValueError):
    pass


def find_nmap(configured: str = "") -> str | None:
    if configured and os.path.isfile(configured):
        return configured
    found = shutil.which("nmap")
    if found:
        return found
    for path in COMMON_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _popen_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0


@functools.lru_cache(maxsize=8)
def nmap_version(path: str) -> str | None:
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, timeout=15, creationflags=_popen_flags()
        ).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"Nmap version ([\w.]+)", out)
    return m.group(1) if m else None


def split_extra_args(text: str) -> list[str]:
    """Parte los argumentos libres y rechaza las opciones de ficheros de entrada/salida."""
    if not text or not text.strip():
        return []
    try:
        args = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ArgsError(f"Argumentos mal formados: {exc}") from exc
    for i, arg in enumerate(args):
        if arg in _FORBIDDEN_EXACT or any(arg.startswith(p) for p in _FORBIDDEN):
            raise ArgsError(f"La opción {arg!r} no está permitida (la app gestiona la entrada/salida).")
        if arg == "--script" or arg.startswith("--script="):
            value = arg.split("=", 1)[1] if "=" in arg else (args[i + 1] if i + 1 < len(args) else "")
            if _PATHLIKE_RE.search(value):
                raise ArgsError("En --script usa nombres o categorías de scripts, no rutas.")
    return args


def dns_args(settings: dict) -> list[str]:
    servers = (settings.get("dns_servers") or "").replace(" ", "")
    if servers:
        if not re.fullmatch(r"[0-9A-Fa-f.:,]+", servers):
            raise ArgsError("Servidores DNS no válidos.")
        return ["--dns-servers", servers]
    if settings.get("system_dns"):
        return ["--system-dns"]
    return []


def discovery_args(mode: str, options: dict) -> list[str]:
    """Argumentos para las fases de descubrimiento: 'list' (-sL) o 'ping' (-sn)."""
    if mode == "list":
        return ["-sL"]
    args = ["-sn"]
    if options.get("reinforced"):
        args += REINFORCED_PING
    if options.get("traceroute"):
        args.append("--traceroute")
    return args


def port_args(options: dict) -> list[str]:
    profile = PORT_PROFILES.get(options.get("profile") or "estandar", PORT_PROFILES["estandar"])
    args = list(profile["args"])
    if options.get("no_ping"):
        args.append("-Pn")
    if options.get("traceroute"):
        args.append("--traceroute")
    return args


def common_args(options: dict, settings: dict) -> list[str]:
    args = [TIMINGS.get(options.get("timing") or "T4", "-T4")]
    if options.get("unprivileged"):
        args.append("--unprivileged")
    return args + dns_args(settings)


def monitoring_args(xml_path: str) -> list[str]:
    """Opciones que la app añade siempre para seguir el progreso y leer el resultado."""
    return ["-v", "--reason", "--stats-every", "5s", "-oX", xml_path]


def format_command(cmd: list[str]) -> str:
    if sys.platform == "win32":
        return subprocess.list2cmdline(cmd)
    return shlex.join(cmd)
