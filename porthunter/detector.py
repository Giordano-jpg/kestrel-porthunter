"""Motor de detección de escaneos (independiente de Scapy, recibe paquetes normalizados).

Patrones que detecta:
- tcp_scan:     un origen envía SYN (sin ACK) a muchos puertos distintos de un equipo.
- stealth_scan: paquetes TCP que el tráfico normal nunca genera (NULL, FIN sin ACK, XMAS).
- udp_scan:     un origen envía UDP a muchos puertos distintos (descontando respuestas).
- ping_sweep:   un origen hace ping (ICMP echo) a muchos equipos distintos.
- arp_sweep:    un origen pregunta por ARP por muchas IPs (así descubre nmap -sn en la LAN).
                Las peticiones ARP son broadcast, así que se ven aunque el switch no te
                reenvíe el resto del tráfico de otros equipos.

Además marca la firma típica de nmap: SYN con ventana 1024/2048/3072/4096 y como única
opción TCP el MSS.
"""

from __future__ import annotations

import time
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

NMAP_WINDOWS = {1024, 2048, 3072, 4096}
KIND_LABELS = {
    "tcp_scan": "Escaneo de puertos TCP",
    "stealth_scan": "Escaneo sigiloso (NULL/FIN/XMAS)",
    "udp_scan": "Escaneo de puertos UDP",
    "ping_sweep": "Barrido de ping (ICMP)",
    "arp_sweep": "Barrido ARP de la red local",
}
MAX_OUTBOUND_FLOWS = 50_000
MAX_INBOUND_SOURCES = 500


@dataclass
class Packet:
    ts: float
    kind: str  # tcp | udp | icmp | arp
    src: str
    dst: str
    sport: int = 0
    dport: int = 0
    flags: int = 0
    window: int = 0
    tcp_opts: tuple[str, ...] = ()
    icmp_type: int = -1
    arp_op: int = 0


@dataclass
class Alert:
    kind: str
    src: str
    dst: str | None
    first: float
    last: float
    ports: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    count: int = 0
    tool: str | None = None
    flags_seen: set = field(default_factory=set)
    db_id: int | None = None
    dirty: bool = True

    @property
    def key(self) -> tuple:
        return (self.kind, self.src, self.dst)

    @property
    def severity(self) -> str:
        if self.kind == "stealth_scan" or self.tool:
            return "alta"
        if self.kind in ("tcp_scan", "udp_scan"):
            return "media"
        return "baja"

    @property
    def note(self) -> str:
        parts = []
        if self.tool:
            parts.append(f"Firma de {self.tool}")
        if self.flags_seen:
            parts.append("Flags: " + ", ".join(sorted(self.flags_seen)))
        return " · ".join(parts)


class _Window:
    """Valores distintos vistos en los últimos `seconds` segundos."""

    __slots__ = ("seconds", "items", "counter", "last")

    def __init__(self, seconds: float):
        self.seconds = seconds
        self.items: deque = deque()
        self.counter: Counter = Counter()
        self.last = 0.0

    def add(self, ts: float, value) -> int:
        self.items.append((ts, value))
        self.counter[value] += 1
        self.last = ts
        limit = ts - self.seconds
        while self.items and self.items[0][0] < limit:
            _, old = self.items.popleft()
            self.counter[old] -= 1
            if self.counter[old] <= 0:
                del self.counter[old]
        return len(self.counter)


def stealth_type(flags: int) -> str | None:
    f = flags & 0x3F
    if f == 0:
        return "NULL"
    if f == FIN:
        return "FIN"
    if f == FIN | PSH | URG:
        return "XMAS"
    return None


class ScanDetector:
    def __init__(self, local_ips=(), *, window_seconds=10, tcp_ports_threshold=15, udp_ports_threshold=15,
                 stealth_threshold=3, sweep_hosts_threshold=25, alert_cooldown_seconds=60, whitelist=(),
                 watch_all=False, **_ignored):
        self.local_ips = set(local_ips)
        self.window = float(window_seconds)
        self.tcp_threshold = int(tcp_ports_threshold)
        self.udp_threshold = int(udp_ports_threshold)
        self.stealth_threshold = int(stealth_threshold)
        self.sweep_threshold = int(sweep_hosts_threshold)
        self.cooldown = float(alert_cooldown_seconds)
        self.whitelist = set(whitelist)
        self.watch_all = bool(watch_all)

        self.active: dict[tuple, Alert] = {}
        self._windows: dict[tuple, _Window] = {}
        self._stealth_flags: dict[tuple, set] = {}
        self._outbound: OrderedDict = OrderedDict()
        self.inbound: OrderedDict = OrderedDict()
        self.stats = Counter()

    # -- entrada ------------------------------------------------------------

    def process(self, p: Packet) -> Alert | None:
        """Procesa un paquete. Devuelve la alerta creada/actualizada, si la hay."""
        self.stats["packets"] += 1
        self.stats[p.kind] += 1

        if p.kind == "arp":
            return self._arp(p)
        if p.src in self.local_ips:
            if p.kind == "udp":
                # Flujo UDP saliente (DNS, QUIC...): sus respuestas no deben contar como escaneo.
                # En TCP no hace falta: una respuesta nunca es un SYN sin ACK.
                key = (p.kind, p.dst, p.dport, p.sport)
                self._outbound[key] = p.ts
                self._outbound.move_to_end(key)
                while len(self._outbound) > MAX_OUTBOUND_FLOWS:
                    self._outbound.popitem(last=False)
            return None
        if p.src in self.whitelist:
            return None
        to_me = p.dst in self.local_ips
        if not to_me and not self.watch_all:
            return None

        if p.kind == "tcp":
            return self._tcp(p, to_me)
        if p.kind == "udp":
            return self._udp(p, to_me)
        if p.kind == "icmp" and p.icmp_type == 8:
            if to_me:
                self._record_inbound(p, "ping")
            return self._sweep("ping_sweep", p.src, p.dst, p.ts)
        return None

    def _is_reply(self, p: Packet) -> bool:
        ts = self._outbound.get((p.kind, p.src, p.sport, p.dport))
        return ts is not None and p.ts - ts < 120

    def _tcp(self, p: Packet, to_me: bool) -> Alert | None:
        stealth = stealth_type(p.flags)
        if stealth:
            seen = self._stealth_flags.setdefault((p.src, p.dst), set())
            seen.add(stealth)
            alert = self._distinct("stealth_scan", p.src, p.dst, p.ts, p.dport, self.stealth_threshold)
            if alert:
                alert.flags_seen |= seen
            if to_me:
                self._record_inbound(p, f"{p.dport}/tcp")
            return alert
        if not (p.flags & SYN) or (p.flags & ACK):
            return None
        if to_me:
            self._record_inbound(p, f"{p.dport}/tcp")
        alert = self._distinct("tcp_scan", p.src, p.dst, p.ts, p.dport, self.tcp_threshold)
        if alert and not alert.tool and p.window in NMAP_WINDOWS and p.tcp_opts == ("MSS",):
            alert.tool = "nmap (SYN scan)"
        return alert

    def _udp(self, p: Packet, to_me: bool) -> Alert | None:
        if self._is_reply(p):
            return None
        if to_me:
            self._record_inbound(p, f"{p.dport}/udp")
        return self._distinct("udp_scan", p.src, p.dst, p.ts, p.dport, self.udp_threshold)

    def _arp(self, p: Packet) -> Alert | None:
        # p.src = IP que pregunta (psrc), p.dst = IP por la que pregunta (pdst)
        if p.arp_op != 1 or p.src in ("0.0.0.0", p.dst) or p.src in self.local_ips:
            return None
        if p.src in self.whitelist:
            return None
        return self._sweep("arp_sweep", p.src, p.dst, p.ts)

    # -- ventanas -----------------------------------------------------------

    def _distinct(self, kind: str, src: str, dst: str, ts: float, port: int, threshold: int) -> Alert | None:
        win = self._windows.setdefault((kind, src, dst), _Window(self.window))
        distinct = win.add(ts, port)
        key = (kind, src, dst)
        alert = self.active.get(key)
        if alert is None:
            if distinct < threshold:
                return None
            alert = Alert(kind=kind, src=src, dst=dst, first=win.items[0][0], last=ts,
                          ports=set(win.counter), count=sum(win.counter.values()))
            self.active[key] = alert
            self.stats["alerts"] += 1
            return alert
        alert.ports.add(port)
        alert.count += 1
        alert.last = ts
        alert.dirty = True
        return alert

    def _sweep(self, kind: str, src: str, target: str, ts: float) -> Alert | None:
        win = self._windows.setdefault((kind, src, None), _Window(self.window))
        distinct = win.add(ts, target)
        key = (kind, src, None)
        alert = self.active.get(key)
        if alert is None:
            if distinct < self.sweep_threshold:
                return None
            alert = Alert(kind=kind, src=src, dst=None, first=win.items[0][0], last=ts,
                          hosts=set(win.counter), count=sum(win.counter.values()))
            self.active[key] = alert
            self.stats["alerts"] += 1
            return alert
        alert.hosts.add(target)
        alert.count += 1
        alert.last = ts
        alert.dirty = True
        return alert

    def _record_inbound(self, p: Packet, what: str) -> None:
        entry = self.inbound.get(p.src)
        if entry is None:
            entry = {"src": p.src, "first": p.ts, "last": p.ts, "count": 0, "targets": Counter()}
            self.inbound[p.src] = entry
            while len(self.inbound) > MAX_INBOUND_SOURCES:
                self.inbound.popitem(last=False)
        self.inbound.move_to_end(p.src)
        entry["count"] += 1
        entry["last"] = p.ts
        if len(entry["targets"]) < 200 or what in entry["targets"]:
            entry["targets"][what] += 1

    # -- mantenimiento ------------------------------------------------------

    def expire(self, now: float | None = None) -> list[Alert]:
        """Cierra las alertas sin actividad durante `cooldown` y libera memoria."""
        now = now if now is not None else time.time()
        ended = [a for a in self.active.values() if now - a.last > self.cooldown]
        for a in ended:
            del self.active[a.key]
        stale = [k for k, w in self._windows.items() if now - w.last > self.window]
        for k in stale:
            del self._windows[k]
            if k[0] == "stealth_scan":
                self._stealth_flags.pop((k[1], k[2]), None)
        cutoff = now - 120
        while self._outbound:
            key, ts = next(iter(self._outbound.items()))
            if ts >= cutoff:
                break
            self._outbound.popitem(last=False)
        return ended

    def active_source(self, src: str) -> list[Alert]:
        return [a for a in self.active.values() if a.src == src]

    def inbound_snapshot(self, limit: int = 100) -> list[dict]:
        rows = sorted(self.inbound.values(), key=lambda e: e["last"], reverse=True)[:limit]
        return [
            {"src": e["src"], "first": e["first"], "last": e["last"], "count": e["count"],
             "distinct": len(e["targets"]),
             "top": [f"{k} ×{v}" if v > 1 else k for k, v in e["targets"].most_common(12)]}
            for e in rows
        ]
