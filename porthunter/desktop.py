"""Modo escritorio: ventana nativa (WebView2 en Windows) sin servidor HTTP y sin ningún puerto.

La interfaz es la misma que la versión web, pero en lugar de hacer peticiones HTTP a
127.0.0.1 llama a Python directamente con el puente JS <-> Python de pywebview
(`window.pywebview.api.*`). Por dentro, cada llamada se pasa a las rutas de Flask con su
cliente de pruebas, que ejecuta la ruta en el mismo proceso sin abrir sockets.

La página se carga desde un fichero local (file://), así que pywebview tampoco arranca su
servidor HTTP interno.
"""

from __future__ import annotations

import base64
import io
import logging
import re
from pathlib import Path

from flask import Flask

from .web import STATIC_DIR

log = logging.getLogger(__name__)

_API_HEADERS = {"X-PortHunter": "1"}
_FILENAME_RE = re.compile(r'filename="?([^";]+)"?')
_SAVE_DIALOG = 30  # webview.FileDialog.SAVE


def available() -> tuple[bool, str]:
    try:
        import webview  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        return False, f"pywebview no está instalado ({exc}). Ejecuta: pip install pywebview"
    return True, "pywebview disponible"


def build_page(out_dir: Path) -> Path:
    """Genera un HTML autocontenido (CSS, JS e icono en línea) para cargarlo por file://."""
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    css = (STATIC_DIR / "style.css").read_text(encoding="utf-8")
    js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")
    icon = "data:image/svg+xml;base64," + base64.b64encode((STATIC_DIR / "favicon.svg").read_bytes()).decode()
    if "</script" in js.lower():
        raise ValueError("app.js no puede contener '</script' para ir en línea")

    replacements = {
        '<link rel="stylesheet" href="/static/style.css">': f"<style>\n{css}\n</style>",
        '<script src="/static/app.js"></script>':
            f"<script>window.PH_DESKTOP = true;</script>\n<script>\n{js}\n</script>",
    }
    for marker, content in replacements.items():
        if marker not in html:
            raise ValueError(f"index.html ha cambiado: no se encuentra {marker!r}")
        html = html.replace(marker, content)
    html = html.replace("/static/favicon.svg", icon)

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "porthunter.html"
    path.write_text(html, encoding="utf-8")
    return path


class Bridge:
    """Lo que la interfaz ve como `window.pywebview.api`. Los atributos con `_` no se exponen."""

    def __init__(self, app: Flask):
        self._app = app
        self._window = None

    def _client(self):
        return self._app.test_client()

    def request(self, method: str, path: str, body=None) -> dict:
        """Equivalente a fetch() contra la API: devuelve {status, data}."""
        if not isinstance(path, str) or not path.startswith("/api/"):
            return {"status": 404, "data": {"error": "Ruta no válida"}}
        method = (method or "GET").upper()
        kwargs: dict = {"method": method, "headers": _API_HEADERS}
        if body is not None and method != "GET":
            kwargs["json"] = body
        resp = self._client().open(path, **kwargs)
        try:
            return {"status": resp.status_code, "data": resp.get_json(silent=True)}
        finally:
            resp.close()

    def upload(self, files: list[dict]) -> dict:
        """Importación: [{name, data (base64)}] -> mismo resultado que POST /api/import."""
        data = {"file": [(io.BytesIO(base64.b64decode(f.get("data") or "")), Path(f.get("name") or "fichero").name)
                         for f in files or []]}
        resp = self._client().post("/api/import", data=data, headers=_API_HEADERS,
                                   content_type="multipart/form-data")
        try:
            return {"status": resp.status_code, "data": resp.get_json(silent=True)}
        finally:
            resp.close()

    def download(self, path: str) -> dict:
        """Exportaciones, XML, logs y .pcap: pide dónde guardarlo con el diálogo de Windows."""
        if not isinstance(path, str) or not path.startswith("/api/"):
            return {"error": "Ruta no válida"}
        resp = self._client().get(path)
        try:
            if resp.status_code != 200:
                data = resp.get_json(silent=True) or {}
                return {"error": data.get("error") or f"Error {resp.status_code}"}
            content = resp.get_data()
            m = _FILENAME_RE.search(resp.headers.get("Content-Disposition", ""))
            name = m.group(1) if m else Path(path.split("?", 1)[0]).name
        finally:
            resp.close()
        if self._window is None:
            return {"error": "Ventana no disponible"}
        target = self._window.create_file_dialog(_SAVE_DIALOG, save_filename=name)
        if not target:
            return {"cancelled": True}
        target = target if isinstance(target, str) else target[0]
        Path(target).write_bytes(content)
        return {"saved": target}


def run(app: Flask, data_dir: Path, *, debug: bool = False, hidden: bool = False, on_start=None) -> None:
    """Abre la ventana y bloquea hasta que se cierre. `on_start(window)` es para pruebas."""
    import webview

    bridge = Bridge(app)
    page = build_page(Path(data_dir) / "ui")
    window = webview.create_window(
        "Kestrel PortHunter", url=page.as_uri(), js_api=bridge, width=1400, height=900,
        min_size=(900, 600), background_color="#0f1419", hidden=hidden,
    )
    bridge._window = window
    log.info("Modo escritorio: %s (sin servidor HTTP)", page)
    webview.start(on_start, window if on_start else None, debug=debug, http_server=False,
                  private_mode=False, storage_path=str(Path(data_dir) / "webview"))
