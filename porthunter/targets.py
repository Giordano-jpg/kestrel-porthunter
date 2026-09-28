"""Validación y utilidades para especificaciones de objetivos al estilo nmap.

Admite IPs sueltas, CIDR (10.10.0.0/17), rangos por octeto (10.10.0-3.1-254,
10.10.5.*, 10.0.0.1,5,9) y nombres de host.
"""

from __future__ import annotations

import ipaddress
import re

_TOKEN_RE = re.compile(r"^[A-Za-z0-9\[][A-Za-z0-9.\-:/,*_\[\]]*$")
_OCTET_RANGE_RE = re.compile(r"^[0-9*,\-]+$")
MAX_TOKENS = 4096


class TargetError(ValueError):
    pass


def parse_targets(text: str) -> list[str]:
    """Divide el texto en objetivos (separados por espacios, saltos de línea o ';').

    Rechaza cualquier token que empiece por '-' para que nadie pueda colar opciones
    de nmap a través del campo de objetivos.
    """
    tokens = [t for t in re.split(r"[\s;]+", text or "") if t]
    if not tokens:
        raise TargetError("Indica al menos un objetivo (IP, rango o red CIDR).")
    if len(tokens) > MAX_TOKENS:
        raise TargetError(f"Demasiados objetivos ({len(tokens)}); máximo {MAX_TOKENS}.")
    for tok in tokens:
        if tok.startswith("-") or not _TOKEN_RE.match(tok):
            raise TargetError(f"Objetivo no válido: {tok!r}")
    return tokens


def _octet_values(spec: str) -> list[tuple[int, int]] | None:
    if spec == "*":
        return [(0, 255)]
    if not _OCTET_RANGE_RE.match(spec):
        return None
    ranges = []
    for part in spec.split(","):
        if not part:
            return None
        if part == "*":
            lo, hi = 0, 255
        elif "-" in part:
            a, _, b = part.partition("-")
            lo = int(a) if a else 0
            hi = int(b) if b else 255
        else:
            lo = hi = int(part)
        if not (0 <= lo <= hi <= 255):
            return None
        ranges.append((lo, hi))
    return ranges


def _parse_octet_spec(token: str) -> list[list[tuple[int, int]]] | None:
    parts = token.split(".")
    if len(parts) != 4:
        return None
    octets = [_octet_values(p) for p in parts]
    if any(o is None for o in octets):
        return None
    return octets  # type: ignore[return-value]


def _network(token: str):
    try:
        return ipaddress.ip_network(token.strip("[]"), strict=False)
    except ValueError:
        return None


def token_count(token: str) -> int | None:
    """Número de direcciones que representa un objetivo (None si no se sabe)."""
    net = _network(token)
    if net is not None:
        return net.num_addresses
    octets = _parse_octet_spec(token)
    if octets is not None:
        total = 1
        for ranges in octets:
            total *= sum(hi - lo + 1 for lo, hi in ranges)
        return total
    if "/" in token:
        return None
    return 1  # nombre de host


def count_addresses(tokens: list[str]) -> int | None:
    total = 0
    for tok in tokens:
        n = token_count(tok)
        if n is None:
            return None
        total += n
    return total


def contains(tokens: list[str], ip: str) -> bool:
    """¿La dirección `ip` está cubierta por alguno de los objetivos?"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for tok in tokens:
        net = _network(tok)
        if net is not None:
            if addr.version == net.version and addr in net:
                return True
            continue
        if addr.version != 4:
            continue
        octets = _parse_octet_spec(tok)
        if octets is None:
            continue
        values = [int(p) for p in str(addr).split(".")]
        if all(any(lo <= v <= hi for lo, hi in ranges) for v, ranges in zip(values, octets)):
            return True
    return False


def ip_sort_key(ip: str | None):
    """Clave para ordenar IPs numéricamente (las vacías al final)."""
    if not ip:
        return (2, 0, "")
    try:
        addr = ipaddress.ip_address(ip)
        return (0 if addr.version == 4 else 1, int(addr), "")
    except ValueError:
        return (2, 0, ip)
