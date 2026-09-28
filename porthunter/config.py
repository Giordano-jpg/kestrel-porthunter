"""Rutas de datos y ajustes persistentes (data/settings.json)."""

from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PORTHUNTER_DATA", BASE_DIR / "data"))

DEFAULTS: dict = {
    # Vacío = autodetectar (PATH y rutas típicas de instalación).
    "nmap_path": "",
    "max_parallel_jobs": 2,
    # Servidores DNS para la resolución inversa, p. ej. "10.10.0.10,10.10.0.11".
    "dns_servers": "",
    # Usar el resolvedor del sistema en vez del resolvedor paralelo de nmap.
    "system_dns": False,
    # --unprivileged: sin paquetes en bruto (connect scan). Evita el aviso de UAC de Npcap
    # si no ejecutas la app como administrador, a costa de menos información (sin MAC ni -O).
    "unprivileged": False,
    "detector": {
        "iface": "",
        "watch_all": False,
        "window_seconds": 10,
        "tcp_ports_threshold": 15,
        "udp_ports_threshold": 15,
        "stealth_threshold": 3,
        "sweep_hosts_threshold": 25,
        "alert_cooldown_seconds": 60,
        "whitelist": [],
        "save_pcap": True,
    },
}


def ensure_dirs(data_dir: Path = DATA_DIR) -> None:
    for sub in ("", "scans", "captures"):
        (data_dir / sub).mkdir(parents=True, exist_ok=True)


def _merge(base: dict, patch: dict) -> dict:
    """Mezcla `patch` sobre `base` sólo en las claves que ya existen en `base`."""
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if key not in out:
            continue
        if isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = _coerce(out[key], value)
    return out


def _coerce(default, value):
    """Convierte `value` al tipo del valor por defecto (los formularios envían strings)."""
    if isinstance(default, bool):
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "si", "sí", "on")
        return bool(value)
    if isinstance(default, int):
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return default
    if isinstance(default, list):
        if isinstance(value, str):
            return [v.strip() for v in value.replace(",", "\n").splitlines() if v.strip()]
        return [str(v).strip() for v in value if str(v).strip()]
    return "" if value is None else str(value).strip()


class Settings:
    def __init__(self, data_dir: Path = DATA_DIR):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "settings.json"
        self._lock = threading.Lock()
        self._data = copy.deepcopy(DEFAULTS)
        if self.path.exists():
            try:
                self._data = _merge(DEFAULTS, json.loads(self.path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "porthunter.db"

    def get(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._data)

    def update(self, patch: dict) -> dict:
        with self._lock:
            self._data = _merge(self._data, patch or {})
            self._data["max_parallel_jobs"] = min(max(1, self._data["max_parallel_jobs"]), 8)
            self.data_dir.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
            return copy.deepcopy(self._data)
