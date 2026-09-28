"""Parser de la salida XML de nmap (-oX).

Tolera ficheros incompletos (escaneo cancelado): devuelve los hosts leídos hasta
el punto en que se cortó el fichero.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

_NETBIOS_RE = re.compile(r"NetBIOS name:\s*([^,\s]+)", re.I)
_COMPUTER_RE = re.compile(r"Computer name:\s*([^\s,]+)", re.I)


@dataclass
class PortResult:
    proto: str
    port: int
    state: str
    reason: str = ""
    ttl: int = 0
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class Hop:
    ttl: int
    ip: str
    rtt: float | None = None
    host: str = ""


@dataclass
class HostResult:
    ip: str
    status: str = "unknown"  # up | down | unknown (unknown = -sL, no se sondeó)
    reason: str = ""
    reason_ttl: int = 0
    mac: str | None = None
    vendor: str | None = None
    hostnames: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    os_matches: list[tuple[str, int]] = field(default_factory=list)
    distance: int | None = None
    trace: list[Hop] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def hostname(self) -> str | None:
        return self.hostnames[0] if self.hostnames else None

    @property
    def netbios(self) -> str | None:
        for sid in ("nbstat", "smb-os-discovery"):
            out = self.scripts.get(sid, "")
            m = _NETBIOS_RE.search(out) or _COMPUTER_RE.search(out)
            if m:
                return m.group(1).strip().upper()
        return None


@dataclass
class ScanInfo:
    type: str
    protocol: str
    services: list[tuple[int, int]]

    def covers(self, port: int) -> bool:
        return any(lo <= port <= hi for lo, hi in self.services)


@dataclass
class ScanResult:
    args: str = ""
    version: str = ""
    start: int | None = None
    scaninfo: list[ScanInfo] = field(default_factory=list)
    hosts: list[HostResult] = field(default_factory=list)
    complete: bool = False
    summary: str = ""
    hosts_up: int | None = None
    hosts_down: int | None = None
    hosts_total: int | None = None
    error: str = ""

    def covered(self, proto: str, port: int) -> bool:
        return any(si.protocol == proto and si.covers(port) for si in self.scaninfo)

    @property
    def is_list_scan(self) -> bool:
        return " -sL" in f" {self.args}" or any(si.type == "list" for si in self.scaninfo)

    @property
    def is_ping_scan(self) -> bool:
        return " -sn" in f" {self.args}" or " -sP" in f" {self.args}"


def merge_discovered(result: ScanResult, discovered: dict[str, set[tuple[str, int]]]) -> None:
    """Añade a un resultado parcial los puertos que nmap anunció por consola
    ("Discovered open port 445/tcp on 10.0.0.5") pero que no llegó a escribir en el XML
    porque se canceló antes de terminar ese host."""
    by_ip = {h.ip: h for h in result.hosts}
    for ip, ports in discovered.items():
        host = by_ip.get(ip)
        if host is None:
            host = by_ip[ip] = HostResult(ip=ip, status="up", reason="partial")
            result.hosts.append(host)
        have = {(p.proto, p.port) for p in host.ports}
        for proto, port in sorted(ports):
            if (proto, port) not in have:
                host.ports.append(PortResult(proto=proto, port=port, state="open", reason="discovered"))


def parse_port_ranges(text: str) -> list[tuple[int, int]]:
    """'1,3-4,6' -> [(1,1),(3,4),(6,6)]."""
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        a, _, b = part.partition("-")
        try:
            lo = int(a)
            hi = int(b) if b else lo
        except ValueError:
            continue
        out.append((lo, hi))
    return out


def _int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_host(el: ET.Element) -> HostResult | None:
    ip = None
    host = HostResult(ip="")
    for addr in el.findall("address"):
        kind = addr.get("addrtype")
        if kind in ("ipv4", "ipv6") and ip is None:
            ip = addr.get("addr")
        elif kind == "mac":
            host.mac = (addr.get("addr") or "").upper() or None
            host.vendor = addr.get("vendor") or None
    if not ip:
        return None
    host.ip = ip

    st = el.find("status")
    if st is not None:
        host.status = st.get("state", "unknown")
        host.reason = st.get("reason", "")
        host.reason_ttl = _int(st.get("reason_ttl"), 0)

    names = []
    for hn in el.findall("hostnames/hostname"):
        name = (hn.get("name") or "").strip().rstrip(".").lower()
        if not name:
            continue
        # Los PTR primero; los nombres "user" son los que escribió el usuario.
        if hn.get("type") == "PTR":
            names.insert(0, name)
        else:
            names.append(name)
    host.hostnames = list(dict.fromkeys(names))

    for p in el.findall("ports/port"):
        state_el = p.find("state")
        svc = p.find("service")
        port = PortResult(
            proto=p.get("protocol", "tcp"),
            port=_int(p.get("portid"), 0),
            state=state_el.get("state", "") if state_el is not None else "",
            reason=state_el.get("reason", "") if state_el is not None else "",
            ttl=_int(state_el.get("reason_ttl"), 0) if state_el is not None else 0,
        )
        if svc is not None:
            port.service = svc.get("name", "")
            port.product = svc.get("product", "")
            port.version = svc.get("version", "")
            port.extrainfo = svc.get("extrainfo", "")
        for sc in p.findall("script"):
            port.scripts[sc.get("id", "")] = sc.get("output", "")
        host.ports.append(port)

    for om in el.findall("os/osmatch"):
        host.os_matches.append((om.get("name", ""), _int(om.get("accuracy"), 0)))

    dist = el.find("distance")
    if dist is not None:
        host.distance = _int(dist.get("value"))

    for hop in el.findall("trace/hop"):
        host.trace.append(
            Hop(
                ttl=_int(hop.get("ttl"), 0),
                ip=hop.get("ipaddr", ""),
                rtt=_float(hop.get("rtt")),
                host=(hop.get("host") or "").lower(),
            )
        )

    for sc in el.findall("hostscript/script"):
        host.scripts[sc.get("id", "")] = sc.get("output", "")
    return host


def parse_xml(source: str | Path | bytes) -> ScanResult:
    """Lee un XML de nmap desde una ruta o desde bytes/str con el contenido."""
    import io

    result = ScanResult()
    if isinstance(source, (bytes, bytearray)):
        stream = io.BytesIO(source)
    elif isinstance(source, str) and source.lstrip().startswith("<"):
        stream = io.BytesIO(source.encode("utf-8"))
    else:
        stream = open(source, "rb")

    try:
        for event, el in ET.iterparse(stream, events=("start", "end")):
            tag = el.tag
            if event == "start":
                if tag == "nmaprun":
                    result.args = el.get("args", "")
                    result.version = el.get("version", "")
                    result.start = _int(el.get("start"))
                continue
            if tag == "scaninfo":
                result.scaninfo.append(
                    ScanInfo(
                        type=el.get("type", ""),
                        protocol=el.get("protocol", ""),
                        services=parse_port_ranges(el.get("services", "")),
                    )
                )
            elif tag == "host":
                h = _parse_host(el)
                if h:
                    result.hosts.append(h)
                el.clear()
            elif tag == "finished":
                result.complete = True
                result.summary = el.get("summary", "")
                if el.get("exit") == "error":
                    result.error = el.get("errormsg", "")
            elif tag == "hosts" and result.complete:
                result.hosts_up = _int(el.get("up"))
                result.hosts_down = _int(el.get("down"))
                result.hosts_total = _int(el.get("total"))
    except ET.ParseError:
        # Fichero cortado (nmap cancelado o aún escribiendo): nos quedamos con lo leído.
        result.complete = False
    finally:
        stream.close()
    return result
