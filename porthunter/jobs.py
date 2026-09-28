"""Cola de tareas: ejecuta nmap en segundo plano, sigue su progreso y vuelca los resultados."""

from __future__ import annotations

import json
import logging
import queue
import re
import subprocess
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone

from . import nmap_cmd
from .config import Settings
from .db import Database, from_iso, now_iso
from .inventory import apply_scan
from .nmap_xml import ScanResult, merge_discovered, parse_xml
from .targets import count_addresses, parse_targets

log = logging.getLogger(__name__)

JOB_KINDS = {
    "list": "Lista DNS (-sL)",
    "ping": "Descubrir activos (-sn)",
    "listping": "DNS + activos (-sL y -sn)",
    "ports": "Escaneo de puertos",
    "smart": "Inteligente (activos → puertos)",
    "custom": "Personalizado",
    "import": "Importación",
}

_STATS_RE = re.compile(r"(\d+) hosts completed \((\d+) up\), (\d+) undergoing")
_PCT_RE = re.compile(r"About ([\d.]+)% done")
_TASK_RE = re.compile(r"^Initiating (.+?)(?: at [\d:]+)?$")
_DISCOVERED_RE = re.compile(r"^Discovered open port (\d+)/(\w+) on (\S+)")
INLINE_TARGETS_MAX = 40
LIVE_JOBS_KEPT = 30


class JobError(ValueError):
    pass


@dataclass
class Phase:
    label: str
    args: list[str]
    source: str | None  # cómo aplicar el resultado: list | ping | ports | None (deducir)
    use_previous_up: bool = False  # objetivos = hosts activos de la fase anterior


def plan_phases(kind: str, options: dict) -> list[Phase]:
    extra = nmap_cmd.split_extra_args(options.get("extra_args", ""))
    if kind == "list":
        phases = [Phase("Lista DNS", nmap_cmd.discovery_args("list", options), "list")]
    elif kind == "ping":
        phases = [Phase("Descubrimiento", nmap_cmd.discovery_args("ping", options), "ping")]
    elif kind == "listping":
        phases = [
            Phase("Lista DNS", nmap_cmd.discovery_args("list", options), "list"),
            Phase("Descubrimiento", nmap_cmd.discovery_args("ping", options), "ping"),
        ]
    elif kind == "ports":
        phases = [Phase("Puertos", nmap_cmd.port_args(options), "ports")]
    elif kind == "smart":
        phases = [
            Phase("Descubrimiento", nmap_cmd.discovery_args("ping", {**options, "traceroute": False}), "ping"),
            # Ya sabemos que están vivos: -Pn evita repetir el descubrimiento.
            Phase("Puertos", nmap_cmd.port_args({**options, "no_ping": True}), "ports", use_previous_up=True),
        ]
    elif kind == "custom":
        if not extra:
            raise JobError("Escribe los argumentos de nmap para el modo personalizado.")
        return [Phase("Personalizado", extra, None)]
    else:
        raise JobError(f"Tipo de tarea desconocido: {kind}")
    phases[-1].args += extra
    return phases


class JobManager:
    def __init__(self, db: Database, settings: Settings):
        self.db = db
        self.settings = settings
        self._queue: queue.Queue[int] = queue.Queue()
        self._live: dict[int, dict] = {}
        self._running: set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # -- ciclo de vida ------------------------------------------------------

    def start(self) -> None:
        self.db.execute(
            "UPDATE jobs SET status = 'interrupted', finished = ? WHERE status IN ('queued', 'running')",
            (now_iso(),),
        )
        threading.Thread(target=self._dispatcher, name="jobs-dispatcher", daemon=True).start()
        threading.Thread(target=self._scheduler, name="jobs-scheduler", daemon=True).start()

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            for live in self._live.values():
                proc = live.get("proc")
                if proc and proc.poll() is None:
                    proc.terminate()

    # -- API ----------------------------------------------------------------

    def nmap_path(self) -> str:
        path = nmap_cmd.find_nmap(self.settings.get()["nmap_path"])
        if not path:
            raise JobError("No se encuentra nmap. Instálalo desde https://nmap.org/download o "
                           "indica la ruta en Ajustes.")
        return path

    def build_command(self, nmap: str, phase: Phase, options: dict, xml_path: str,
                      targets: list[str] | None, target_file: str | None) -> list[str]:
        settings = self.settings.get()
        opts = {**options, "unprivileged": options.get("unprivileged") or settings.get("unprivileged")}
        cmd = [nmap, *nmap_cmd.common_args(opts, settings), *phase.args, *nmap_cmd.monitoring_args(xml_path)]
        return cmd + (["-iL", target_file] if target_file else list(targets or []))

    def preview(self, kind: str, targets_text: str, options: dict) -> list[str]:
        tokens = parse_targets(targets_text)
        phases = plan_phases(kind, options)
        nmap = nmap_cmd.find_nmap(self.settings.get()["nmap_path"]) or "nmap"
        out = []
        for phase in phases:
            if phase.use_previous_up:
                cmd = self.build_command(nmap, phase, options, "resultado.xml", None,
                                         "<hosts-activos-de-la-fase-anterior>")
            else:
                cmd = self.build_command(nmap, phase, options, "resultado.xml", tokens, None)
            out.append(nmap_cmd.format_command(cmd))
        return out

    def submit(self, kind: str, targets_text: str, options: dict | None = None, label: str | None = None,
               network_id: int | None = None) -> int:
        options = dict(options or {})
        tokens = parse_targets(targets_text)
        phases = plan_phases(kind, options)  # valida argumentos
        self.nmap_path()
        commands = self.preview(kind, targets_text, options)
        job_id = self.db.execute(
            "INSERT INTO jobs(kind, label, targets, options_json, commands, status, created, network_id) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (kind, label or JOB_KINDS.get(kind, kind), " ".join(tokens), json.dumps(options),
             json.dumps(commands), "queued", now_iso(), network_id),
        )
        log.info("Tarea %s en cola: %s %s (%d fases)", job_id, kind, " ".join(tokens), len(phases))
        self._queue.put(job_id)
        return job_id

    def submit_network(self, network_id: int, auto: bool = False) -> int:
        net = self.db.one("SELECT * FROM networks WHERE id = ?", (network_id,))
        if not net:
            raise JobError("Red no encontrada.")
        job_id = self.submit(net["kind"], net["targets"], json.loads(net["options_json"] or "{}"),
                             label=f"{net['name']}{' (automático)' if auto else ''}", network_id=network_id)
        self.db.execute("UPDATE networks SET last_run = ? WHERE id = ?", (now_iso(), network_id))
        return job_id

    def cancel(self, job_id: int) -> bool:
        with self._lock:
            live = self._live.get(job_id)
            if live and job_id in self._running:
                live["cancel"] = True
                proc = live.get("proc")
                if proc and proc.poll() is None:
                    proc.terminate()
                return True
        self.db.execute(
            "UPDATE jobs SET status = 'cancelled', finished = ? WHERE id = ? AND status = 'queued'",
            (now_iso(), job_id),
        )
        return True

    def live_state(self, job_id: int) -> dict | None:
        with self._lock:
            live = self._live.get(job_id)
            if not live:
                return None
            return {"log": list(live["log"]), "progress": live["progress"], "phase": live["phase"]}

    def log_tail(self, job_id: int, lines: int = 300) -> list[str]:
        live = self.live_state(job_id)
        if live:
            return live["log"][-lines:]
        path = self.settings.scans_dir / f"job_{job_id}.log"
        if not path.exists():
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in deque(fh, maxlen=lines)]

    def running_count(self) -> int:
        with self._lock:
            return len(self._running)

    # -- internos -----------------------------------------------------------

    def _limit(self) -> int:
        return max(1, int(self.settings.get().get("max_parallel_jobs", 2)))

    def _dispatcher(self) -> None:
        while not self._stop.is_set():
            try:
                job_id = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            while not self._stop.is_set() and self.running_count() >= self._limit():
                time.sleep(0.5)
            job = self.db.one("SELECT status FROM jobs WHERE id = ?", (job_id,))
            if not job or job["status"] != "queued":
                continue
            with self._lock:
                self._running.add(job_id)
                self._live[job_id] = {"log": deque(maxlen=400), "progress": 0.0, "phase": "", "proc": None,
                                      "cancel": False}
                for old in sorted(self._live)[:-LIVE_JOBS_KEPT]:
                    if old not in self._running:
                        self._live.pop(old, None)
            threading.Thread(target=self._run_job, args=(job_id,), name=f"job-{job_id}", daemon=True).start()

    def _scheduler(self) -> None:
        while not self._stop.wait(20):
            try:
                now = datetime.now(timezone.utc)
                for net in self.db.query("SELECT * FROM networks WHERE interval_min > 0"):
                    last = from_iso(net["last_run"])
                    if last and (now - last).total_seconds() < net["interval_min"] * 60:
                        continue
                    busy = self.db.one(
                        "SELECT 1 FROM jobs WHERE network_id = ? AND status IN ('queued', 'running')",
                        (net["id"],),
                    )
                    if not busy:
                        self.submit_network(net["id"], auto=True)
            except Exception:  # noqa: BLE001 - el planificador no debe morir nunca
                log.exception("Error en el planificador")

    def _run_job(self, job_id: int) -> None:
        job = self.db.one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        live = self._live[job_id]
        options = json.loads(job["options_json"] or "{}")
        tokens = job["targets"].split()
        scans_dir = self.settings.scans_dir
        scans_dir.mkdir(parents=True, exist_ok=True)
        log_path = scans_dir / f"job_{job_id}.log"
        self.db.execute("UPDATE jobs SET status = 'running', started = ? WHERE id = ?", (now_iso(), job_id))

        status, error, summaries, xml_files = "done", None, [], []
        try:
            nmap = self.nmap_path()
            phases = plan_phases(job["kind"], options)
            prev_up: list[str] | None = None
            with open(log_path, "a", encoding="utf-8", errors="replace") as log_fh:
                for idx, phase in enumerate(phases):
                    target_file = None
                    phase_tokens: list[str] | None = tokens
                    if phase.use_previous_up:
                        if not prev_up:
                            self._log(live, log_fh, "No hay hosts activos: no queda nada que escanear.")
                            break
                        target_file = scans_dir / f"job_{job_id}_activos.txt"
                        target_file.write_text("\n".join(prev_up) + "\n", encoding="utf-8")
                        phase_tokens, total = None, len(prev_up)
                    else:
                        total = count_addresses(tokens)
                        if len(tokens) > INLINE_TARGETS_MAX:
                            target_file = scans_dir / f"job_{job_id}_objetivos.txt"
                            target_file.write_text("\n".join(tokens) + "\n", encoding="utf-8")
                            phase_tokens = None

                    xml_path = scans_dir / f"job_{job_id}_{idx + 1}.xml"
                    cmd = self.build_command(nmap, phase, options, str(xml_path), phase_tokens,
                                             str(target_file) if target_file else None)
                    live["phase"] = phase.label
                    live["discovered"] = {}
                    rc = self._exec(job_id, live, log_fh, cmd, idx, len(phases), total)

                    result = parse_xml(xml_path) if xml_path.exists() else ScanResult()
                    if not result.complete:
                        merge_discovered(result, live["discovered"])
                    xml_files.append(xml_path.name)
                    with self.db.connect() as conn:
                        summary = apply_scan(conn, result, source=phase.source, job_id=job_id,
                                             targets=None if phase.use_previous_up else tokens)
                    summary["phase"] = phase.label
                    summaries.append(summary)
                    prev_up = [h.ip for h in result.hosts if h.status == "up"]

                    if live["cancel"]:
                        status = "cancelled"
                        break
                    if rc != 0:
                        status = "error"
                        tail = [ln for ln in list(live["log"])[-8:] if ln.strip()]
                        error = f"nmap terminó con código {rc}. " + " | ".join(tail[-3:])
                        break
        except Exception as exc:  # noqa: BLE001
            status, error = "error", str(exc)
            live["log"].append(traceback.format_exc())
            log.exception("La tarea %s falló", job_id)
        finally:
            self.db.execute(
                "UPDATE jobs SET status = ?, progress = ?, finished = ?, summary_json = ?, error = ?, "
                "xml_files = ?, phase = NULL WHERE id = ?",
                (status, 1.0 if status == "done" else live["progress"], now_iso(), json.dumps(summaries),
                 error, json.dumps(xml_files), job_id),
            )
            with self._lock:
                live["proc"] = None
                self._running.discard(job_id)

    @staticmethod
    def _log(live: dict, fh, line: str) -> None:
        live["log"].append(line)
        fh.write(line + "\n")

    def _exec(self, job_id: int, live: dict, log_fh, cmd: list[str], phase_idx: int, phase_count: int,
              total: int | None) -> int:
        self._log(live, log_fh, "$ " + nmap_cmd.format_command(cmd))
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                creationflags=nmap_cmd._popen_flags(),
            )
        except OSError as exc:
            raise JobError(f"No se pudo ejecutar nmap: {exc}") from exc
        with self._lock:
            live["proc"] = proc
            if live["cancel"]:
                proc.terminate()

        reports = completed = undergoing = 0
        task_pct = 0.0
        last_write = 0.0
        base_phase = live["phase"]
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip()
            if not line:
                continue
            self._log(live, log_fh, line)
            if line.startswith("Nmap scan report for"):
                reports += 1
            if m := _STATS_RE.search(line):
                completed, undergoing = int(m.group(1)), int(m.group(3))
            if m := _PCT_RE.search(line):
                task_pct = float(m.group(1))
            if m := _TASK_RE.match(line):
                live["phase"] = f"{base_phase} · {m.group(1)}"
            if m := _DISCOVERED_RE.match(line):
                live["discovered"].setdefault(m.group(3), set()).add((m.group(2), int(m.group(1))))

            if total:
                done = max(completed + undergoing * task_pct / 100, reports)
                frac = done / total
            else:
                frac = task_pct / 100
            overall = (phase_idx + min(max(frac, 0.0), 0.99)) / phase_count
            live["progress"] = max(live["progress"], overall)
            if time.monotonic() - last_write > 2:
                last_write = time.monotonic()
                self.db.execute("UPDATE jobs SET progress = ?, phase = ? WHERE id = ?",
                                (live["progress"], live["phase"], job_id))
        rc = proc.wait()
        if rc == 0 and not live["cancel"]:
            live["progress"] = max(live["progress"], (phase_idx + 1) / phase_count)
        log_fh.flush()
        return rc

    # -- importación ----------------------------------------------------------

    def import_result(self, filename: str, fmt: str, result: ScanResult, scan_ts: str | None) -> dict:
        """Registra una importación como tarea terminada y vuelca sus hosts al inventario."""
        ts = now_iso()
        job_id = self.db.execute(
            "INSERT INTO jobs(kind, label, targets, options_json, status, progress, created, started, "
            "finished) VALUES ('import', ?, ?, ?, 'done', 1, ?, ?, ?)",
            (f"Importado: {filename}", filename, json.dumps({"format": fmt}), ts, ts, ts),
        )
        with self.db.connect() as conn:
            summary = apply_scan(conn, result, job_id=job_id, ts=scan_ts)
        summary.update(phase=f"Importación ({fmt})", job_id=job_id, scan_date=scan_ts)
        self.db.execute("UPDATE jobs SET summary_json = ? WHERE id = ?", (json.dumps([summary]), job_id))
        return summary
