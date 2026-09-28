"""Servicio de monitorización: captura con Scapy/Npcap, pasa los paquetes al detector,
guarda las alertas en la base de datos y escribe un .pcap por incidente para Wireshark.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import sys
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

from .config import Settings
from .db import Database, now_iso, to_iso
from .detector import KIND_LABELS, Alert, Packet, ScanDetector
from .inventory import display_name
from .targets import ip_sort_key

log = logging.getLogger(__name__)

PREROLL_PACKETS = 64
PREROLL_SOURCES = 200
MAX_PCAP_PACKETS = 20_000
FLUSH_SECONDS = 2.0


NPCAP_DLL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll"


def scapy_status(load: bool = True) -> tuple[bool, str]:
    """¿Se puede capturar? Con load=False sólo mira si está instalado, sin cargar Npcap:
    con Npcap en modo "sólo administradores", cargarlo sin permisos lanza el aviso de UAC."""
    if not load:
        if importlib.util.find_spec("scapy") is None:
            return False, "Scapy no está instalado. Ejecuta: pip install scapy"
        if sys.platform == "win32" and not NPCAP_DLL.exists():
            return False, "No se encuentra Npcap. Instálalo (viene con Wireshark y con Nmap)."
        return True, "Scapy y Npcap instalados"
    try:
        import scapy
        # scapy.config por sí solo no carga nada: es scapy.arch (vía scapy.all) quien abre
        # Npcap, pone conf.use_pcap y rellena conf.ifaces.
        import scapy.all  # noqa: F401
        from scapy.config import conf
    except Exception as exc:  # noqa: BLE001
        return False, f"Scapy no está instalado o no se pudo cargar ({exc}). Ejecuta: pip install scapy"
    if sys.platform == "win32" and not conf.use_pcap:
        from .system import is_admin

        if not NPCAP_DLL.exists():
            return False, "No se encuentra Npcap. Instálalo (viene con Wireshark y con Nmap)."
        if not is_admin():
            return False, ("Npcap está instalado pero no se pudo abrir: está en modo 'sólo administradores' y "
                           "no se concedió el permiso (aviso de UAC). Cierra la app y ábrela con iniciar.bat, "
                           "que pide el permiso una sola vez al arrancar.")
        return False, ("Npcap está instalado pero no se pudo cargar ni siquiera como administrador. "
                       "Comprueba que el servicio 'npcap' está en marcha o reinstala Npcap.")
    return True, f"Scapy {scapy.VERSION}"


class MonitorService:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self.detector: ScanDetector | None = None
        self.sniffer = None
        self.iface_label = ""
        self.started: str | None = None
        self.error: str | None = None
        self._writers: dict[str, dict] = {}
        self._preroll: OrderedDict[str, deque] = OrderedDict()
        self._save_pcap = True

    # -- interfaces ---------------------------------------------------------

    @staticmethod
    def interfaces() -> list[dict]:
        ok, _ = scapy_status()
        if not ok:
            return []
        from scapy.config import conf

        default = conf.iface
        out = []
        for i in conf.ifaces.data.values():
            ips = [i.ip] if i.ip else []
            ips += [ip for ip in getattr(i, "ips", {}).get(4, []) if ip not in ips]
            out.append({
                "id": i.network_name or i.name,
                "name": i.name,
                "description": i.description,
                "ips": ips,
                "default": i == default,
            })
        out.sort(key=lambda x: (not x["default"], not x["ips"], x["name"].lower()))
        return out

    @staticmethod
    def _local_ips() -> set[str]:
        ips = {"127.0.0.1"}
        for iface in MonitorService.interfaces():
            ips.update(iface["ips"])
        return ips

    # -- control --------------------------------------------------------------

    def start(self, iface_id: str | None = None, overrides: dict | None = None) -> dict:
        ok, reason = scapy_status()
        if not ok:
            raise RuntimeError(reason)
        from scapy.config import conf
        from scapy.interfaces import resolve_iface
        from scapy.sendrecv import AsyncSniffer

        with self._lock:
            if self.running:
                return self.status()
            patch = dict(overrides or {})
            if iface_id is not None:
                patch["iface"] = iface_id
            cfg = self.settings.update({"detector": patch})["detector"] if patch else self.settings.get()["detector"]

            iface = resolve_iface(cfg["iface"]) if cfg["iface"] else conf.iface
            self.detector = ScanDetector(self._local_ips(), **cfg)
            self._save_pcap = cfg["save_pcap"]
            self.error = None
            self._stop.clear()
            sniffer = AsyncSniffer(iface=iface, prn=self._on_packet, store=False, filter="ip or arp",
                                   promisc=bool(cfg["watch_all"]))
            sniffer.start()
        time.sleep(1.0)
        if sniffer.exception is not None or not sniffer.running:
            exc = sniffer.exception
            self.error = f"No se pudo capturar en {iface.name}: {exc or 'la captura se detuvo'}"
            if exc and "promisc" in str(exc).lower():
                self.error += " (tu tarjeta no admite modo promiscuo: desactiva 'toda la red')."
            raise RuntimeError(self.error)
        with self._lock:
            self.sniffer = sniffer
            self.iface_label = f"{iface.name} ({iface.description})"
            self.started = now_iso()
        threading.Thread(target=self._flusher, name="monitor-flush", daemon=True).start()
        log.info("Monitor iniciado en %s", self.iface_label)
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            sniffer, self.sniffer = self.sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:  # noqa: BLE001
                log.warning("Error al parar la captura: %s", exc)
        self._stop.set()
        self._flush(final=True)
        return self.status()

    @property
    def running(self) -> bool:
        return self.sniffer is not None and bool(getattr(self.sniffer, "running", False))

    # -- captura --------------------------------------------------------------

    @staticmethod
    def normalize(pkt) -> Packet | None:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP

        ts = float(pkt.time)
        if ARP in pkt:
            a = pkt[ARP]
            return Packet(ts, "arp", a.psrc, a.pdst, arp_op=int(a.op))
        if IP not in pkt:
            return None
        ip = pkt[IP]
        if TCP in pkt:
            t = pkt[TCP]
            opts = tuple(o[0] for o in t.options if isinstance(o, tuple) and o and o[0] not in ("NOP", "EOL"))
            return Packet(ts, "tcp", ip.src, ip.dst, int(t.sport), int(t.dport), int(t.flags), int(t.window), opts)
        if UDP in pkt:
            u = pkt[UDP]
            return Packet(ts, "udp", ip.src, ip.dst, int(u.sport), int(u.dport))
        if ICMP in pkt:
            return Packet(ts, "icmp", ip.src, ip.dst, icmp_type=int(pkt[ICMP].type))
        return None

    def _on_packet(self, pkt) -> None:
        try:
            p = self.normalize(pkt)
            if p is None:
                return
            with self._lock:
                det = self.detector
                if det is None:
                    return
                alert = det.process(p)
                local = p.src in det.local_ips
            if self._save_pcap and not local:
                self._capture(p.src, pkt)
            if alert is not None and alert.db_id is None:
                self._insert_alert(alert)
        except Exception:  # noqa: BLE001 - un paquete raro no debe tumbar la captura
            log.exception("Error procesando paquete")

    def _capture(self, src: str, pkt) -> None:
        with self._lock:
            writer = self._writers.get(src)
            if writer is not None:
                if writer["count"] < MAX_PCAP_PACKETS:
                    writer["writer"].write(pkt)
                    writer["count"] += 1
                return
            buf = self._preroll.get(src)
            if buf is None:
                buf = self._preroll[src] = deque(maxlen=PREROLL_PACKETS)
                while len(self._preroll) > PREROLL_SOURCES:
                    self._preroll.popitem(last=False)
            self._preroll.move_to_end(src)
            buf.append(pkt)

    def _open_writer(self, alert: Alert) -> str | None:
        if not self._save_pcap:
            return None
        from scapy.utils import PcapWriter

        with self._lock:
            if alert.src in self._writers:
                return self._writers[alert.src]["name"]
            self.settings.captures_dir.mkdir(parents=True, exist_ok=True)
            safe_src = re.sub(r"[^0-9A-Za-z.]", "_", alert.src)
            name = f"alerta_{alert.db_id}_{alert.kind}_{safe_src}.pcap"
            writer = PcapWriter(str(self.settings.captures_dir / name), append=False, sync=False)
            count = 0
            for old in self._preroll.pop(alert.src, ()):
                writer.write(old)
                count += 1
            self._writers[alert.src] = {"writer": writer, "name": name, "count": count}
            return name

    def _device_names(self, ips) -> dict[str, dict]:
        ips = list(set(ips))
        if not ips:
            return {}
        out = {}
        for i in range(0, len(ips), 500):
            chunk = ips[i:i + 500]
            rows = self.db.query(
                f"SELECT * FROM devices WHERE current_ip IN ({','.join('?' * len(chunk))}) "
                "ORDER BY last_seen", chunk)
            for r in rows:
                out[r["current_ip"]] = {"id": r["id"], "name": display_name(r), "watched": r["watched"]}
        return out

    def _insert_alert(self, alert: Alert) -> None:
        named = self._device_names([alert.src]).get(alert.src)
        with self._lock:
            if alert.db_id is not None:
                return
            fields = self._alert_fields(alert)
            alert.db_id = self.db.execute(
                "INSERT INTO alerts(first_seen, last_seen, kind, severity, src, src_name, dst, count, ports, "
                "hosts, note) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (to_iso(alert.first), fields["last_seen"], alert.kind, fields["severity"], alert.src,
                 named["name"] if named else None, alert.dst, fields["count"], fields["ports"],
                 fields["hosts"], fields["note"]),
            )
            alert.dirty = False
        pcap = self._open_writer(alert)
        if pcap:
            self.db.execute("UPDATE alerts SET pcap = ? WHERE id = ?", (pcap, alert.db_id))
        log.warning("ALERTA %s desde %s", KIND_LABELS.get(alert.kind, alert.kind), alert.src)

    @staticmethod
    def _alert_fields(a: Alert) -> dict:
        return {
            "last_seen": to_iso(a.last),
            "severity": a.severity,
            "count": a.count,
            "ports": ",".join(str(p) for p in sorted(a.ports)[:500]),
            "hosts": ",".join(sorted(a.hosts, key=ip_sort_key)[:500]),
            "note": a.note,
        }

    def _flusher(self) -> None:
        while not self._stop.wait(FLUSH_SECONDS):
            try:
                self._flush()
            except Exception:  # noqa: BLE001
                log.exception("Error guardando alertas")

    def _flush(self, final: bool = False) -> None:
        with self._lock:
            det = self.detector
            if det is None:
                return
            ended = det.expire() if not final else list(det.active.values())
            if final:
                det.active.clear()
            pending = [a for a in det.active.values() if a.dirty and a.db_id is not None]
            pending += [a for a in ended if a.db_id is not None]
            updates = []
            for a in pending:
                a.dirty = False
                f = self._alert_fields(a)
                updates.append((f["last_seen"], f["severity"], f["count"], f["ports"], f["hosts"], f["note"],
                                a.db_id))
            active_srcs = {a.src for a in det.active.values()}
            closing = [s for s in self._writers if final or s not in active_srcs]
            writers = [self._writers.pop(s) for s in closing]
        if updates:
            with self.db.connect() as conn:
                conn.executemany(
                    "UPDATE alerts SET last_seen = ?, severity = ?, count = ?, ports = ?, hosts = ?, note = ? "
                    "WHERE id = ?", updates)
        for w in writers:
            try:
                w["writer"].close()
            except Exception:  # noqa: BLE001
                pass
        # Vacía a disco los pcaps abiertos para que se puedan descargar mientras siguen activos.
        with self._lock:
            for w in self._writers.values():
                try:
                    w["writer"].flush()
                except Exception:  # noqa: BLE001
                    pass

    # -- estado ---------------------------------------------------------------

    def status(self) -> dict:
        ok, reason = scapy_status()
        with self._lock:
            det = self.detector
            inbound = det.inbound_snapshot() if det else []
            stats = dict(det.stats) if det else {}
            active = len(det.active) if det else 0
        names = self._device_names(e["src"] for e in inbound)
        for e in inbound:
            e["device"] = names.get(e["src"])
            e["first"], e["last"] = to_iso(e["first"]), to_iso(e["last"])
        return {
            "available": ok,
            "reason": reason,
            "running": self.running,
            "iface": self.iface_label if self.running else "",
            "started": self.started if self.running else None,
            "error": self.error,
            "stats": stats,
            "active_alerts": active,
            "inbound": inbound,
            "config": self.settings.get()["detector"],
        }
