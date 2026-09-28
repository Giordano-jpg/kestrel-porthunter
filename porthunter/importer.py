"""Importación de resultados antiguos: tus .txt de `nmap -sL`, salida normal (-oN),
grepable (-oG), XML (-oX) o una lista sencilla "IP nombre".
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .db import to_iso
from .nmap_xml import HostResult, PortResult, ScanResult, parse_xml

MAX_IMPORT_BYTES = 200 * 1024 * 1024

_REPORT_RE = re.compile(r"^Nmap scan report for (?:(\S+) \(([^)]+)\)|(\S+))(\s+\[host down\])?")
_MAC_RE = re.compile(r"^MAC Address: ([0-9A-Fa-f:]{17})(?: \((.*)\))?")
_PORT_LINE_RE = re.compile(r"^(\d+)/(tcp|udp|sctp)\s+(\S+)\s+(\S+)?\s*(.*)$")
_GREP_HOST_RE = re.compile(r"^Host: (\S+) \(([^)]*)\)\s+(.*)$")
_GREP_PORT_RE = re.compile(r"(\d+)/([^/]*)/([^/]*)/[^/]*/([^/]*)/[^/]*/([^/]*)/")
_IP_RE = r"(\d{1,3}(?:\.\d{1,3}){3})"
_SIMPLE_RE = [
    re.compile(rf"^{_IP_RE}[\s,;]+([A-Za-z0-9][\w.\-]*)"),
    re.compile(rf"^([A-Za-z][\w.\-]*)[\s,;]+{_IP_RE}"),
]
_INITIATED_RE = re.compile(r"scan initiated \w{3} (\w{3}) +(\d+) (\d\d):(\d\d):(\d\d) (\d{4})")
_STARTING_RE = re.compile(r"Starting Nmap .*? at (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d)")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def decode_bytes(data: bytes) -> str:
    """PowerShell guarda con `>` en UTF-16; el cmd clásico en la página de códigos OEM."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if data[:200].count(b"\x00") > 20:
        return data.decode("utf-16-le", "replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _local_to_iso(y, mo, d, h, mi, s=0) -> str | None:
    try:
        return to_iso(datetime(int(y), int(mo), int(d), int(h), int(mi), int(s)).timestamp())
    except (ValueError, OverflowError):
        return None


def _detect_ts(text: str) -> str | None:
    head = text[:4000]
    if m := _INITIATED_RE.search(head):
        mon, day, hh, mm, ss, year = m.groups()
        if mon in _MONTHS:
            return _local_to_iso(year, _MONTHS[mon], day, hh, mm, ss)
    if m := _STARTING_RE.search(head):
        return _local_to_iso(*m.groups())
    return None


def _args_line(text: str) -> str:
    m = re.search(r"(?:scan initiated .*? as: |^nmap )(.*)$", text[:4000], re.M)
    return m.group(1) if m else ""


def parse_normal(text: str) -> ScanResult:
    """Salida normal de nmap (-oN o lo que se ve en la consola)."""
    result = ScanResult(args=_args_line(text))
    current: HostResult | None = None
    saw_up = saw_ports = False
    for raw in text.splitlines():
        line = raw.strip()
        if m := _REPORT_RE.match(line):
            name, ip_paren, ip_only, down = m.groups()
            ip = ip_paren or ip_only
            current = HostResult(ip=ip, status="down" if down else "unknown")
            if name:
                current.hostnames = [name.rstrip(".").lower()]
            result.hosts.append(current)
            continue
        if current is None:
            continue
        if line.startswith("Host is up"):
            current.status = "up"
            saw_up = True
            if m := re.search(r"received (\S+?)(?: \(|$| ttl (\d+))", line):
                current.reason = m.group(1)
                current.reason_ttl = int(m.group(2) or 0)
        elif m := _MAC_RE.match(line):
            current.mac = m.group(1).upper()
            current.vendor = m.group(2) or None
        elif m := _PORT_LINE_RE.match(line):
            port, proto, state, service, rest = m.groups()
            current.ports.append(PortResult(proto=proto, port=int(port), state=state,
                                            service=service or "", product=(rest or "").strip()[:120]))
            saw_ports = True
            if current.status == "unknown":
                current.status = "up"
        elif line.startswith("Network Distance:"):
            if m := re.search(r"(\d+) hop", line):
                current.distance = int(m.group(1))
    if " -sL" in f" {result.args}" or (not saw_up and not saw_ports and result.hosts):
        result.args = (result.args + " -sL").strip()
    elif not saw_ports:
        result.args = (result.args + " -sn").strip()
    result.complete = True
    return result


def parse_grepable(text: str) -> ScanResult:
    result = ScanResult(args=_args_line(text))
    hosts: dict[str, HostResult] = {}
    for line in text.splitlines():
        m = _GREP_HOST_RE.match(line.strip())
        if not m:
            continue
        ip, name, rest = m.groups()
        host = hosts.get(ip)
        if host is None:
            host = hosts[ip] = HostResult(ip=ip)
            if name:
                host.hostnames = [name.rstrip(".").lower()]
            result.hosts.append(host)
        if "Status: Up" in rest:
            host.status = "up"
        elif "Status: Down" in rest:
            host.status = "down"
        if "Ports:" in rest:
            host.status = "up"
            for pm in _GREP_PORT_RE.finditer(rest.split("Ports:", 1)[1]):
                port, state, proto, service, version = pm.groups()
                host.ports.append(PortResult(proto=proto or "tcp", port=int(port), state=state,
                                             service=service, product=version))
    result.complete = True
    return result


def parse_simple_list(text: str) -> ScanResult:
    """Líneas tipo "10.10.0.5  PC-JUAN" o "PC-JUAN 10.10.0.5"."""
    result = ScanResult(args="-sL")
    for line in text.splitlines():
        line = line.strip()
        for i, rx in enumerate(_SIMPLE_RE):
            if m := rx.match(line):
                ip, name = m.groups() if i == 0 else m.groups()[::-1]
                result.hosts.append(HostResult(ip=ip, hostnames=[name.rstrip(".").lower()]))
                break
    result.complete = True
    return result


def parse_any(data: bytes) -> tuple[ScanResult, str | None, str]:
    """Detecta el formato. Devuelve (resultado, fecha del escaneo o None, formato)."""
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError("Fichero demasiado grande.")
    text = decode_bytes(data)
    if "<nmaprun" in text[:5000]:
        result = parse_xml(text.encode("utf-8"))
        ts = to_iso(result.start) if result.start else None
        return result, ts, "xml"
    ts = _detect_ts(text)
    if re.search(r"^Host: \S+ \(", text, re.M):
        return parse_grepable(text), ts, "grepable"
    if "Nmap scan report for" in text:
        return parse_normal(text), ts, "normal"
    result = parse_simple_list(text)
    if not result.hosts:
        raise ValueError("No se reconoce el formato: no hay líneas 'Nmap scan report for', "
                         "ni XML de nmap, ni pares 'IP nombre'.")
    return result, ts, "lista"
