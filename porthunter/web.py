"""Servidor web local (Flask) con la API y la interfaz."""

from __future__ import annotations

import csv
import io
import json
import re
import time
from pathlib import Path

from flask import Flask, Response, jsonify, request, send_from_directory

from . import nmap_cmd, system
from .config import DATA_DIR, Settings, ensure_dirs
from .db import Database, now_iso
from .detector import KIND_LABELS
from .importer import MAX_IMPORT_BYTES, parse_any
from .inventory import device_detail, list_devices
from .jobs import JOB_KINDS, JobError, JobManager
from .monitor import MonitorService
from .nmap_cmd import ArgsError
from .targets import TargetError, ip_sort_key

STATIC_DIR = Path(__file__).resolve().parent / "static"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
_JOB_FILE_RE = re.compile(r"^job_(\d+)(?:_[\w]+)?\.(xml|log|txt)$")


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _body() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _int_arg(name: str, default: int, maximum: int = 100_000) -> int:
    try:
        return max(1, min(int(request.args.get(name, default)), maximum))
    except ValueError:
        return default


def _job_row(row: dict) -> dict:
    row = dict(row)
    for key, default in (("options_json", "{}"), ("commands", "[]"), ("summary_json", "[]"), ("xml_files", "[]")):
        target = key.replace("_json", "")
        row[target] = json.loads(row.pop(key) or default)
    row["kind_label"] = JOB_KINDS.get(row["kind"], row["kind"])
    return row


def create_app(data_dir: Path | None = None, allowed_hosts: set[str] | None = None,
               start_background: bool = True) -> Flask:
    settings = Settings(data_dir or DATA_DIR)
    ensure_dirs(settings.data_dir)
    db = Database(settings.db_path)
    jobs = JobManager(db, settings)
    monitor = MonitorService(db, settings)
    if start_background:
        jobs.start()

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_IMPORT_BYTES
    app.extensions["porthunter"] = {"db": db, "jobs": jobs, "monitor": monitor, "settings": settings}
    hosts_ok = LOCAL_HOSTS | set(allowed_hosts or ())
    diag_cache: dict = {"at": 0.0, "data": None}

    def diagnostics(refresh: bool = False) -> dict:
        if refresh or not diag_cache["data"] or time.time() - diag_cache["at"] > 300:
            diag_cache["data"] = system.diagnostics(settings.get())
            diag_cache["at"] = time.time()
        return diag_cache["data"]

    # -- seguridad --------------------------------------------------------------

    @app.before_request
    def guard():
        host = request.host
        host = host[1:host.index("]")] if host.startswith("[") else host.rsplit(":", 1)[0]
        if host not in hosts_ok:
            # Protección frente a DNS rebinding: sólo se atiende a localhost.
            return jsonify(error="Host no permitido"), 403
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-PortHunter") != "1":
            # Una cabecera propia obliga al navegador a hacer preflight CORS, que no
            # respondemos: otra web no puede lanzar escaneos a través de esta API.
            return jsonify(error="Falta la cabecera X-PortHunter"), 403
        return None

    @app.after_request
    def headers(resp: Response):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ApiError)
    def api_error(exc: ApiError):
        return jsonify(error=str(exc)), exc.status

    @app.errorhandler(TargetError)
    @app.errorhandler(ArgsError)
    @app.errorhandler(JobError)
    @app.errorhandler(ValueError)
    def bad_request(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(413)
    def too_large(_exc):
        return jsonify(error="Fichero demasiado grande"), 413

    # -- interfaz ---------------------------------------------------------------

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_file(name):
        return send_from_directory(STATIC_DIR, name)

    # -- meta / diagnóstico -------------------------------------------------------

    @app.get("/api/meta")
    def meta():
        return jsonify(
            kinds=JOB_KINDS,
            profiles={k: v["label"] + (" · requiere privilegios" if v.get("raw") else "")
                      for k, v in nmap_cmd.PORT_PROFILES.items()},
            timings=list(nmap_cmd.TIMINGS),
            alert_kinds=KIND_LABELS,
        )

    @app.get("/api/diagnostics")
    def get_diagnostics():
        return jsonify(diagnostics(request.args.get("refresh") == "1"))

    def counts() -> dict:
        row = db.one(
            "SELECT count(*) AS total, "
            "sum(status = 'up') AS up, sum(status = 'down') AS down, sum(watched) AS watched, "
            "(SELECT count(*) FROM ports) AS ports, "
            "(SELECT count(*) FROM alerts WHERE acknowledged = 0) AS alerts, "
            "(SELECT count(*) FROM jobs WHERE status = 'running') AS running, "
            "(SELECT count(*) FROM jobs WHERE status = 'queued') AS queued "
            "FROM devices")
        return {k: v or 0 for k, v in row.items()}

    @app.get("/api/summary")
    def summary():
        return jsonify(**counts(), monitor_running=monitor.running)

    @app.get("/api/dashboard")
    def dashboard():
        with db.connect() as conn:
            watched = list_devices(conn, watched=True, limit=200)["items"]
        active_jobs = [_job_row(r) for r in db.query(
            "SELECT * FROM jobs WHERE status IN ('running', 'queued') ORDER BY id")]
        recent_jobs = [_job_row(r) for r in db.query(
            "SELECT * FROM jobs WHERE status NOT IN ('running', 'queued') ORDER BY id DESC LIMIT 5")]
        for j in active_jobs:
            live = jobs.live_state(j["id"])
            if live:
                j["progress"], j["phase"] = live["progress"], live["phase"]
        return jsonify(
            counts=counts(),
            watched=watched,
            events=db.query("SELECT * FROM events ORDER BY id DESC LIMIT 20"),
            active_jobs=active_jobs,
            recent_jobs=recent_jobs,
            alerts=db.query("SELECT * FROM alerts ORDER BY last_seen DESC LIMIT 5"),
            monitor_running=monitor.running,
        )

    # -- dispositivos -----------------------------------------------------------

    @app.get("/api/devices")
    def devices():
        with db.connect() as conn:
            return jsonify(list_devices(
                conn,
                q=request.args.get("q", ""),
                status=request.args.get("status", ""),
                watched=request.args.get("watched") == "1",
                with_ports=request.args.get("ports") == "1",
                limit=_int_arg("limit", 1000, 20000),
            ))

    @app.get("/api/devices/<int:dev_id>")
    def device(dev_id: int):
        with db.connect() as conn:
            dev = device_detail(conn, dev_id)
        if not dev:
            raise ApiError("Dispositivo no encontrado", 404)
        return jsonify(dev)

    @app.patch("/api/devices/<int:dev_id>")
    def update_device(dev_id: int):
        body = _body()
        fields = {}
        for key in ("alias", "notes"):
            if key in body:
                fields[key] = (str(body[key] or "").strip()[:500]) or None
        if "watched" in body:
            fields["watched"] = 1 if body["watched"] else 0
        if fields:
            cols = ", ".join(f"{k} = ?" for k in fields)
            db.execute(f"UPDATE devices SET {cols} WHERE id = ?", (*fields.values(), dev_id))
        return device(dev_id)

    @app.delete("/api/devices/<int:dev_id>")
    def delete_device(dev_id: int):
        db.execute("DELETE FROM devices WHERE id = ?", (dev_id,))
        return jsonify(ok=True)

    def _ids(body) -> list[int]:
        ids = [int(i) for i in body.get("ids", []) if str(i).isdigit()]
        if not ids:
            raise ApiError("No hay dispositivos seleccionados")
        return ids[:5000]

    @app.post("/api/devices/watch")
    def watch_devices():
        body = _body()
        ids = _ids(body)
        with db.connect() as conn:
            conn.executemany("UPDATE devices SET watched = ? WHERE id = ?",
                             [(1 if body.get("watched", True) else 0, i) for i in ids])
        return jsonify(ok=True, count=len(ids))

    @app.post("/api/devices/scan")
    def scan_devices():
        body = _body()
        ids = _ids(body)
        rows = db.query(f"SELECT current_ip FROM devices WHERE id IN ({','.join('?' * len(ids))}) "
                        "AND current_ip IS NOT NULL", ids)
        ips = sorted({r["current_ip"] for r in rows}, key=ip_sort_key)
        if not ips:
            raise ApiError("Los dispositivos seleccionados no tienen IP conocida")
        job_id = jobs.submit(body.get("kind", "ports"), " ".join(ips), body.get("options") or {},
                             label=body.get("label") or f"Puertos de {len(ips)} dispositivo(s)")
        return jsonify(job_id=job_id)

    # -- tareas -----------------------------------------------------------------

    @app.get("/api/jobs")
    def list_jobs():
        rows = [_job_row(r) for r in db.query("SELECT * FROM jobs ORDER BY id DESC LIMIT ?",
                                              (_int_arg("limit", 100, 1000),))]
        for j in rows:
            live = jobs.live_state(j["id"]) if j["status"] == "running" else None
            if live:
                j["progress"], j["phase"] = live["progress"], live["phase"]
        return jsonify(rows)

    @app.post("/api/jobs")
    def create_job():
        body = _body()
        job_id = jobs.submit(body.get("kind", "ping"), body.get("targets", ""), body.get("options") or {},
                             label=(body.get("label") or "").strip() or None)
        return jsonify(job_id=job_id)

    @app.post("/api/jobs/preview")
    def preview_job():
        body = _body()
        return jsonify(commands=jobs.preview(body.get("kind", "ping"), body.get("targets", ""),
                                             body.get("options") or {}))

    @app.get("/api/jobs/<int:job_id>")
    def get_job(job_id: int):
        row = db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise ApiError("Tarea no encontrada", 404)
        job = _job_row(row)
        live = jobs.live_state(job_id) if job["status"] == "running" else None
        if live:
            job["progress"], job["phase"] = live["progress"], live["phase"]
        job["log"] = jobs.log_tail(job_id, _int_arg("lines", 300, 5000))
        job["events"] = db.query("SELECT * FROM events WHERE job_id = ? ORDER BY id DESC LIMIT 100", (job_id,))
        return jsonify(job)

    @app.post("/api/jobs/<int:job_id>/cancel")
    def cancel_job(job_id: int):
        jobs.cancel(job_id)
        return jsonify(ok=True)

    @app.delete("/api/jobs")
    def clear_jobs():
        db.execute("DELETE FROM jobs WHERE status NOT IN ('running', 'queued')")
        return jsonify(ok=True)

    @app.get("/api/jobs/<int:job_id>/files/<name>")
    def job_file(job_id: int, name: str):
        m = _JOB_FILE_RE.match(name)
        if not m or int(m.group(1)) != job_id:
            raise ApiError("Fichero no válido", 404)
        return send_from_directory(settings.scans_dir, name, as_attachment=request.args.get("dl") == "1")

    # -- redes guardadas --------------------------------------------------------

    def _network_payload(body: dict, partial: bool = False) -> dict:
        from .targets import parse_targets

        out = {}
        if "name" in body or not partial:
            name = str(body.get("name") or "").strip()
            if not name:
                raise ApiError("La red necesita un nombre")
            out["name"] = name[:100]
        if "targets" in body or not partial:
            out["targets"] = " ".join(parse_targets(body.get("targets", "")))
        if "kind" in body or not partial:
            kind = body.get("kind", "ping")
            if kind not in JOB_KINDS or kind == "import":
                raise ApiError("Tipo de escaneo no válido")
            out["kind"] = kind
        if "options" in body or not partial:
            out["options_json"] = json.dumps(body.get("options") or {})
        if "interval_min" in body or not partial:
            try:
                out["interval_min"] = max(0, int(body.get("interval_min") or 0))
            except ValueError as exc:
                raise ApiError("Intervalo no válido") from exc
        return out

    @app.get("/api/networks")
    def networks():
        rows = db.query("SELECT * FROM networks ORDER BY name")
        for r in rows:
            r["options"] = json.loads(r.pop("options_json") or "{}")
        return jsonify(rows)

    @app.post("/api/networks")
    def create_network():
        payload = _network_payload(_body())
        cols = ", ".join(payload)
        net_id = db.execute(f"INSERT INTO networks({cols}) VALUES ({','.join('?' * len(payload))})",
                            tuple(payload.values()))
        return jsonify(id=net_id)

    @app.patch("/api/networks/<int:net_id>")
    def update_network(net_id: int):
        payload = _network_payload(_body(), partial=True)
        if payload:
            cols = ", ".join(f"{k} = ?" for k in payload)
            db.execute(f"UPDATE networks SET {cols} WHERE id = ?", (*payload.values(), net_id))
        return jsonify(ok=True)

    @app.delete("/api/networks/<int:net_id>")
    def delete_network(net_id: int):
        db.execute("DELETE FROM networks WHERE id = ?", (net_id,))
        return jsonify(ok=True)

    @app.post("/api/networks/<int:net_id>/run")
    def run_network(net_id: int):
        return jsonify(job_id=jobs.submit_network(net_id))

    # -- novedades y alertas ----------------------------------------------------

    @app.get("/api/events")
    def events():
        return jsonify(db.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (_int_arg("limit", 100, 2000),)))

    @app.get("/api/alerts")
    def alerts():
        where = "WHERE acknowledged = 0" if request.args.get("unack") == "1" else ""
        return jsonify(db.query(f"SELECT * FROM alerts {where} ORDER BY last_seen DESC LIMIT ?",
                                (_int_arg("limit", 200, 5000),)))

    @app.post("/api/alerts/<int:alert_id>/ack")
    def ack_alert(alert_id: int):
        db.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        return jsonify(ok=True)

    @app.post("/api/alerts/ack-all")
    def ack_all():
        db.execute("UPDATE alerts SET acknowledged = 1")
        return jsonify(ok=True)

    @app.delete("/api/alerts")
    def clear_alerts():
        db.execute("DELETE FROM alerts")
        return jsonify(ok=True)

    @app.get("/api/alerts/<int:alert_id>/pcap")
    def alert_pcap(alert_id: int):
        row = db.one("SELECT pcap FROM alerts WHERE id = ?", (alert_id,))
        if not row or not row["pcap"] or not (settings.captures_dir / row["pcap"]).exists():
            raise ApiError("No hay captura para esta alerta", 404)
        return send_from_directory(settings.captures_dir, row["pcap"], as_attachment=True)

    # -- monitor ----------------------------------------------------------------

    @app.get("/api/monitor")
    def monitor_status():
        return jsonify(monitor.status())

    @app.get("/api/monitor/interfaces")
    def monitor_interfaces():
        return jsonify(MonitorService.interfaces())

    @app.post("/api/monitor/start")
    def monitor_start():
        body = _body()
        iface = body.pop("iface", None)
        try:
            return jsonify(monitor.start(iface, body))
        except RuntimeError as exc:
            raise ApiError(str(exc)) from exc

    @app.post("/api/monitor/stop")
    def monitor_stop():
        return jsonify(monitor.stop())

    # -- ajustes ----------------------------------------------------------------

    @app.get("/api/settings")
    def get_settings():
        return jsonify(settings.get())

    @app.patch("/api/settings")
    def patch_settings():
        body = _body()
        nmap_path = body.get("nmap_path")
        if nmap_path and not Path(nmap_path).is_file():
            raise ApiError(f"No existe el fichero {nmap_path}")
        if body.get("dns_servers"):
            nmap_cmd.dns_args({"dns_servers": body["dns_servers"]})
        data = settings.update(body)
        diagnostics(refresh=True)
        return jsonify(data)

    @app.delete("/api/inventory")
    def clear_inventory():
        if request.args.get("confirm") != "BORRAR":
            raise ApiError("Confirmación requerida")
        with db.connect() as conn:
            conn.execute("DELETE FROM ports")
            conn.execute("DELETE FROM ip_history")
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM devices")
        return jsonify(ok=True)

    # -- importar / exportar ------------------------------------------------------

    @app.post("/api/import")
    def import_file():
        files = request.files.getlist("file")
        if not files:
            raise ApiError("No se ha enviado ningún fichero")
        results = []
        for f in files:
            name = Path(f.filename or "fichero").name
            data = f.read()
            try:
                result, scan_ts, fmt = parse_any(data)
            except ValueError as exc:
                results.append({"file": name, "error": str(exc)})
                continue
            summary = jobs.import_result(name, fmt, result, scan_ts)
            results.append({"file": name, "format": fmt, **summary})
        return jsonify(results=results)

    @app.get("/api/export/<fmt>")
    def export(fmt: str):
        with db.connect() as conn:
            items = list_devices(conn, q=request.args.get("q", ""), status=request.args.get("status", ""),
                                 watched=request.args.get("watched") == "1", limit=10**6)["items"]
        items.sort(key=lambda r: ip_sort_key(r["current_ip"]))
        stamp = now_iso().replace(":", "").replace("-", "")[:13]
        if fmt == "txt":
            lines = [f"# Kestrel PortHunter · inventario exportado {now_iso()} · {len(items)} dispositivos",
                     f"# {'IP':<16}{'NOMBRE':<42}{'ESTADO':<9}{'ÚLTIMA VEZ':<22}{'ALIAS / PUERTOS'}"]
            for r in items:
                extra = " · ".join(x for x in (r["alias"], r["port_list"]) if x)
                name = r["hostname"] or r["netbios"] or "-"
                lines.append(f"{r['current_ip'] or '-':<18}{name:<42}{r['status']:<9}{r['last_seen']:<22}{extra}")
            body, mime, ext = "\r\n".join(lines) + "\r\n", "text/plain; charset=utf-8", "txt"
        elif fmt == "targets":
            ips = [r["current_ip"] for r in items if r["current_ip"]]
            body, mime, ext = "\n".join(ips) + "\n", "text/plain; charset=utf-8", "txt"
        elif fmt == "csv":
            buf = io.StringIO()
            cols = ["current_ip", "hostname", "netbios", "alias", "status", "mac", "vendor", "distance", "ttl",
                    "os_guess", "port_list", "watched", "first_seen", "last_seen", "last_up", "notes"]
            writer = csv.writer(buf, delimiter=";")
            writer.writerow(cols)
            for r in items:
                writer.writerow(["" if r.get(c) is None else r.get(c) for c in cols])
            body, mime, ext = "﻿" + buf.getvalue(), "text/csv; charset=utf-8", "csv"
        else:
            raise ApiError("Formato no soportado", 404)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="porthunter_{fmt}_{stamp}.{ext}"'})

    return app
