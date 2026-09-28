"""Inventario de dispositivos.

Aplica los resultados de nmap a la base de datos reconociendo cada equipo aunque
cambie de IP (las IPs privadas por DHCP van rotando). La identidad se decide así:

1. MAC (sólo visible para equipos del mismo segmento de red).
2. Nombre DNS (PTR), que es lo que se veía con `nmap -sL`.
3. Nombre NetBIOS (perfil "Equipos Windows").
4. Si no hay nada de lo anterior, la IP.
"""

from __future__ import annotations

import json
import sqlite3

from .db import from_iso, now_iso
from .nmap_xml import HostResult, ScanResult
from .targets import contains, ip_sort_key

LIVE_SOURCES = {"ping", "ports"}
NEW_DEVICE_EVENT_LIMIT = 20
# Si DNS (-sL) apunta a otra IP pero el equipo respondió hace menos de esto, no nos fiamos del DNS.
DNS_TRUST_AFTER_MINUTES = 60


def display_name(dev: dict | sqlite3.Row) -> str:
    return dev["alias"] or dev["hostname"] or dev["netbios"] or dev["current_ip"] or f"#{dev['id']}"


def estimate_distance(host: HostResult) -> int | None:
    """Saltos hasta el equipo: -O/traceroute si los hay, si no MAC visible (1) o TTL."""
    if host.distance is not None:
        return host.distance
    if host.trace:
        return len(host.trace)
    if host.reason == "localhost-response":
        return 0
    if host.mac or host.reason == "arp-response":
        return 1
    ttl = best_ttl(host)
    if ttl:
        for initial in (64, 128, 255):
            if ttl <= initial:
                return initial - ttl + 1
    return None


def best_ttl(host: HostResult) -> int:
    if host.reason_ttl:
        return host.reason_ttl
    ttls = [p.ttl for p in host.ports if p.ttl]
    return max(ttls) if ttls else 0


def ttl_os_hint(ttl: int | None) -> str | None:
    if not ttl:
        return None
    if ttl <= 64:
        return "Linux/Unix/macOS/Android"
    if ttl <= 128:
        return "Windows"
    return "Equipo de red (router, switch, impresora...)"


def add_event(conn, ts: str, kind: str, message: str, device_id=None, job_id=None) -> None:
    conn.execute(
        "INSERT INTO events(ts, kind, device_id, job_id, message) VALUES (?,?,?,?,?)",
        (ts, kind, device_id, job_id, message),
    )


# ---------------------------------------------------------------------------
# Identidad
# ---------------------------------------------------------------------------

def _find_device(conn, host: HostResult) -> sqlite3.Row | None:
    mac, hostname, netbios = host.mac, host.hostname, host.netbios
    if mac:
        row = conn.execute(
            "SELECT * FROM devices WHERE mac = ? ORDER BY last_seen DESC LIMIT 1", (mac,)
        ).fetchone()
        if row:
            return row
    if hostname:
        row = conn.execute(
            "SELECT * FROM devices WHERE hostname = ? COLLATE NOCASE ORDER BY last_seen DESC LIMIT 1",
            (hostname,),
        ).fetchone()
        if row:
            return row
        short = hostname.split(".")[0].upper()
        row = conn.execute(
            "SELECT * FROM devices WHERE hostname IS NULL AND netbios = ? COLLATE NOCASE "
            "ORDER BY last_seen DESC LIMIT 1",
            (short,),
        ).fetchone()
        if row:
            return row
    if netbios:
        row = conn.execute(
            "SELECT * FROM devices WHERE netbios = ? COLLATE NOCASE "
            "OR hostname = ? COLLATE NOCASE OR hostname LIKE ? ESCAPE '\\' "
            "ORDER BY last_seen DESC LIMIT 1",
            (netbios, netbios, netbios.replace("_", "\\_").replace("%", "\\%") + ".%"),
        ).fetchone()
        if row:
            return row
    if not (mac or hostname or netbios):
        # Sin identificadores: "el equipo que está en esta IP".
        return conn.execute(
            "SELECT * FROM devices WHERE current_ip = ? ORDER BY last_seen DESC LIMIT 1", (host.ip,)
        ).fetchone()
    # Adoptamos un registro anónimo (sólo IP) que estuviera en esta misma IP.
    return conn.execute(
        "SELECT * FROM devices WHERE current_ip = ? AND hostname IS NULL AND mac IS NULL "
        "AND netbios IS NULL ORDER BY last_seen DESC LIMIT 1",
        (host.ip,),
    ).fetchone()


def merge_devices(conn, keep_id: int, drop_id: int) -> None:
    """Fusiona `drop_id` dentro de `keep_id` (puertos, historial de IPs y novedades)."""
    if keep_id == drop_id:
        return
    conn.execute(
        "INSERT INTO ip_history(device_id, ip, first_seen, last_seen, last_up, source) "
        "SELECT ?, ip, first_seen, last_seen, last_up, source FROM ip_history WHERE device_id = ? "
        "ON CONFLICT(device_id, ip) DO UPDATE SET "
        "first_seen = min(first_seen, excluded.first_seen), last_seen = max(last_seen, excluded.last_seen)",
        (keep_id, drop_id),
    )
    conn.execute(
        "INSERT OR IGNORE INTO ports(device_id, proto, port, state, service, product, version, "
        "extrainfo, first_seen, last_seen) SELECT ?, proto, port, state, service, product, version, "
        "extrainfo, first_seen, last_seen FROM ports WHERE device_id = ?",
        (keep_id, drop_id),
    )
    conn.execute("UPDATE events SET device_id = ? WHERE device_id = ?", (keep_id, drop_id))
    conn.execute("DELETE FROM devices WHERE id = ?", (drop_id,))


def _release_ip(conn, dev_id: int, ip: str) -> None:
    """Un equipo confirmado en `ip`: los demás que figuraban ahí dejan de tenerla."""
    others = conn.execute(
        "SELECT * FROM devices WHERE current_ip = ? AND id != ?", (ip, dev_id)
    ).fetchall()
    for other in others:
        anonymous = not (other["hostname"] or other["mac"] or other["netbios"])
        if anonymous and not other["watched"] and not other["alias"] and not other["notes"]:
            merge_devices(conn, dev_id, other["id"])
        else:
            conn.execute(
                "UPDATE devices SET current_ip = NULL, status = 'unknown' WHERE id = ?", (other["id"],)
            )


def _upsert_ip_history(conn, dev_id: int, ip: str, ts: str, up: bool, source: str) -> None:
    conn.execute(
        "INSERT INTO ip_history(device_id, ip, first_seen, last_seen, last_up, source) "
        "VALUES (?,?,?,?,?,?) ON CONFLICT(device_id, ip) DO UPDATE SET "
        "first_seen = min(first_seen, excluded.first_seen), "
        "last_seen = max(last_seen, excluded.last_seen), "
        "last_up = CASE WHEN excluded.last_up IS NULL THEN last_up "
        "WHEN last_up IS NULL THEN excluded.last_up ELSE max(last_up, excluded.last_up) END, "
        "source = excluded.source",
        (dev_id, ip, ts, ts, ts if up else None, source),
    )


def _minutes_between(a: str | None, b: str | None) -> float | None:
    da, db_ = from_iso(a), from_iso(b)
    if not da or not db_:
        return None
    return abs((db_ - da).total_seconds()) / 60


def _upsert_device(conn, host: HostResult, *, up: bool, source: str, ts: str, job_id, touched: set,
                   summary: dict) -> tuple[int, bool, sqlite3.Row | None]:
    dev = _find_device(conn, host)
    distance = estimate_distance(host)
    ttl = best_ttl(host) or None
    os_guess = host.os_matches[0][0] if host.os_matches else None
    trace_json = json.dumps([h.__dict__ for h in host.trace]) if host.trace else None
    netbios = host.netbios

    if dev is None:
        cur = conn.execute(
            "INSERT INTO devices(hostname, netbios, mac, vendor, current_ip, status, distance, ttl, "
            "os_guess, trace_json, first_seen, last_seen, last_up) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (host.hostname, netbios, host.mac, host.vendor, host.ip, "up" if up else "unknown",
             distance, ttl, os_guess, trace_json, ts, ts, ts if up else None),
        )
        dev_id = cur.lastrowid
        if up:
            _release_ip(conn, dev_id, host.ip)
        _upsert_ip_history(conn, dev_id, host.ip, ts, up, source)
        touched.add(dev_id)
        return dev_id, True, None

    dev_id = dev["id"]
    name = display_name(dev)
    newer = ts >= (dev["last_seen"] or "")
    fields: dict = {}

    if newer:
        if host.hostname and host.hostname != (dev["hostname"] or "").lower():
            if dev["hostname"]:
                add_event(conn, ts, "name_change",
                          f"{name}: el nombre cambió de {dev['hostname']} a {host.hostname}", dev_id, job_id)
            fields["hostname"] = host.hostname
        if netbios:
            fields["netbios"] = netbios
        if host.mac:
            fields["mac"] = host.mac
            if host.vendor:
                fields["vendor"] = host.vendor
        if distance is not None:
            fields["distance"] = distance
        if ttl:
            fields["ttl"] = ttl
        if os_guess:
            fields["os_guess"] = os_guess
        if trace_json:
            fields["trace_json"] = trace_json

        # IP actual. En -sL un nombre puede aparecer con varias IPs (registros DNS viejos):
        # sólo la primera de este escaneo cuenta como actual.
        move_ip = host.ip != dev["current_ip"] and not (source == "list" and dev_id in touched)
        if move_ip and source == "list" and dev["status"] == "up":
            mins = _minutes_between(dev["last_up"], ts)
            if mins is not None and mins < DNS_TRUST_AFTER_MINUTES:
                move_ip = False
        if move_ip:
            if dev["current_ip"]:
                add_event(conn, ts, "ip_change", f"{name}: cambió de IP {dev['current_ip']} → {host.ip}",
                          dev_id, job_id)
                summary["ip_changes"] += 1
            fields["current_ip"] = host.ip

        if up:
            if dev["watched"] and dev["status"] == "down":
                add_event(conn, ts, "up", f"{name} vuelve a responder en {host.ip}", dev_id, job_id)
            fields["status"] = "up"
            fields["last_up"] = ts
        fields["last_seen"] = ts

    if fields:
        cols = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE devices SET {cols} WHERE id = ?", (*fields.values(), dev_id))
    if up and newer:
        _release_ip(conn, dev_id, host.ip)
    _upsert_ip_history(conn, dev_id, host.ip, ts, up, source)
    touched.add(dev_id)
    return dev_id, False, dev


def _update_ports(conn, dev_id: int, prev: sqlite3.Row | None, host: HostResult, result: ScanResult,
                  ts: str, job_id, summary: dict) -> None:
    open_now = {(p.proto, p.port): p for p in host.ports if p.state == "open"}
    existing = {
        (r["proto"], r["port"]): r
        for r in conn.execute("SELECT * FROM ports WHERE device_id = ?", (dev_id,))
    }
    last_scan = prev["last_port_scan"] if prev is not None else None
    had_scan = last_scan is not None
    newer = not last_scan or ts >= last_scan
    name = display_name(conn.execute("SELECT * FROM devices WHERE id = ?", (dev_id,)).fetchone())

    for key, p in open_now.items():
        summary["open_ports"] += 1
        if key in existing:
            if newer:
                conn.execute(
                    "UPDATE ports SET state = ?, service = COALESCE(NULLIF(?, ''), service), "
                    "product = COALESCE(NULLIF(?, ''), product), version = COALESCE(NULLIF(?, ''), version), "
                    "extrainfo = COALESCE(NULLIF(?, ''), extrainfo), last_seen = max(last_seen, ?) "
                    "WHERE device_id = ? AND proto = ? AND port = ?",
                    (p.state, p.service, p.product, p.version, p.extrainfo, ts, dev_id, p.proto, p.port),
                )
            continue
        conn.execute(
            "INSERT INTO ports(device_id, proto, port, state, service, product, version, extrainfo, "
            "first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (dev_id, p.proto, p.port, p.state, p.service, p.product, p.version, p.extrainfo, ts, ts),
        )
        if had_scan and newer:
            svc = f" ({p.service})" if p.service else ""
            add_event(conn, ts, "port_open", f"{name}: nuevo puerto abierto {p.port}/{p.proto}{svc}",
                      dev_id, job_id)

    if newer:
        # Un resultado parcial (cancelado) no sirve para dar puertos por cerrados.
        for key, row in existing.items():
            if result.complete and key not in open_now and result.covered(*key):
                conn.execute(
                    "DELETE FROM ports WHERE device_id = ? AND proto = ? AND port = ?", (dev_id, *key)
                )
                add_event(conn, ts, "port_closed", f"{name}: el puerto {key[1]}/{key[0]} ya no está abierto",
                          dev_id, job_id)
        conn.execute("UPDATE devices SET last_port_scan = ? WHERE id = ?", (ts, dev_id))


def _mark_down(conn, targets: list[str], seen_up: set[str], ts: str, job_id, summary: dict) -> None:
    rows = conn.execute(
        "SELECT * FROM devices WHERE status IN ('up', 'unknown') AND current_ip IS NOT NULL"
    ).fetchall()
    for dev in rows:
        ip = dev["current_ip"]
        if ip in seen_up or not contains(targets, ip) or ts < (dev["last_seen"] or ""):
            continue
        conn.execute("UPDATE devices SET status = 'down' WHERE id = ?", (dev["id"],))
        if dev["status"] == "up":
            summary["went_down"] += 1
            if dev["watched"]:
                add_event(conn, ts, "down", f"{display_name(dev)} no responde en {ip}", dev["id"], job_id)


def source_for(result: ScanResult) -> str:
    if result.is_list_scan:
        return "list"
    if result.is_ping_scan:
        return "ping"
    return "ports"


def apply_scan(conn, result: ScanResult, *, source: str | None = None, job_id=None,
               targets: list[str] | None = None, ts: str | None = None) -> dict:
    """Vuelca un resultado de nmap en el inventario y devuelve un resumen."""
    source = source or source_for(result)
    ts = ts or now_iso()
    summary = {"source": source, "hosts": 0, "up": 0, "named": 0, "new": 0, "ip_changes": 0,
               "open_ports": 0, "went_down": 0, "complete": result.complete}
    touched: set[int] = set()
    seen_up: set[str] = set()
    new_names: list[str] = []

    for host in result.hosts:
        if source == "list":
            if not host.hostname:
                continue
            up = False
        else:
            if host.status != "up":
                continue
            up = True
            seen_up.add(host.ip)
            summary["up"] += 1
        summary["hosts"] += 1
        if host.hostname or host.netbios:
            summary["named"] += 1

        dev_id, created, prev = _upsert_device(
            conn, host, up=up, source=source, ts=ts, job_id=job_id, touched=touched, summary=summary
        )
        if created:
            summary["new"] += 1
            new_names.append(f"{host.hostname or host.netbios or host.ip} ({host.ip})")
        if source == "ports" and up:
            _update_ports(conn, dev_id, prev, host, result, ts, job_id, summary)

    if source == "ping" and targets and result.complete:
        _mark_down(conn, targets, seen_up, ts, job_id, summary)

    if new_names:
        if len(new_names) <= NEW_DEVICE_EVENT_LIMIT:
            for n in new_names:
                add_event(conn, ts, "new", f"Nuevo dispositivo: {n}", None, job_id)
        else:
            add_event(conn, ts, "new", f"{len(new_names)} dispositivos nuevos añadidos al inventario",
                      None, job_id)
    return summary


# ---------------------------------------------------------------------------
# Consultas
# ---------------------------------------------------------------------------

_DEVICE_LIST_SQL = """
SELECT d.*,
       (SELECT count(*) FROM ports p WHERE p.device_id = d.id) AS port_count,
       (SELECT group_concat(port || '/' || proto, ', ') FROM
            (SELECT port, proto FROM ports p WHERE p.device_id = d.id ORDER BY port LIMIT 10)) AS port_list
FROM devices d
"""


def list_devices(conn, q: str = "", status: str = "", watched: bool = False, with_ports: bool = False,
                 limit: int = 1000) -> dict:
    where, params = [], []
    for term in (q or "").split():
        like = f"%{term}%"
        where.append(
            "(d.hostname LIKE ? OR d.alias LIKE ? OR d.netbios LIKE ? OR d.current_ip LIKE ? "
            "OR d.mac LIKE ? OR d.vendor LIKE ? OR d.notes LIKE ? OR d.os_guess LIKE ? "
            "OR EXISTS (SELECT 1 FROM ip_history h WHERE h.device_id = d.id AND h.ip = ?) "
            "OR EXISTS (SELECT 1 FROM ports p WHERE p.device_id = d.id "
            "           AND (CAST(p.port AS TEXT) = ? OR p.service LIKE ? OR p.product LIKE ?)))"
        )
        params += [like] * 8 + [term, term, like, like]
    if status:
        where.append("d.status = ?")
        params.append(status)
    if watched:
        where.append("d.watched = 1")
    if with_ports:
        where.append("EXISTS (SELECT 1 FROM ports p WHERE p.device_id = d.id)")
    sql = _DEVICE_LIST_SQL + (" WHERE " + " AND ".join(where) if where else "")
    rows = [dict(r) for r in conn.execute(sql, params)]
    rows.sort(key=lambda r: (not r["watched"], ip_sort_key(r["current_ip"])))
    for r in rows:
        r["name"] = display_name(r)
        r["ttl_hint"] = ttl_os_hint(r["ttl"])
        r.pop("trace_json", None)
    return {"total": len(rows), "items": rows[:limit]}


def device_detail(conn, dev_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (dev_id,)).fetchone()
    if not row:
        return None
    dev = dict(row)
    dev["name"] = display_name(dev)
    dev["ttl_hint"] = ttl_os_hint(dev["ttl"])
    dev["trace"] = json.loads(dev.pop("trace_json") or "[]")
    dev["ip_history"] = [dict(r) for r in conn.execute(
        "SELECT * FROM ip_history WHERE device_id = ? ORDER BY last_seen DESC", (dev_id,))]
    dev["ports"] = [dict(r) for r in conn.execute(
        "SELECT * FROM ports WHERE device_id = ? ORDER BY proto, port", (dev_id,))]
    dev["events"] = [dict(r) for r in conn.execute(
        "SELECT * FROM events WHERE device_id = ? ORDER BY id DESC LIMIT 50", (dev_id,))]
    return dev
