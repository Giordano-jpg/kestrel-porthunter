"""Arranca Kestrel PortHunter.

    python run.py            ventana de escritorio, sin puertos (por defecto en Windows)
    python run.py --web      servidor local en 127.0.0.1:8765 y navegador (por defecto en Linux)
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import webbrowser
from pathlib import Path

from porthunter import __version__
from porthunter.config import DATA_DIR, ensure_dirs


def _message_box(text: str) -> None:
    """Con pythonw no hay consola: los errores graves se muestran en una ventana."""
    print(text, file=sys.stderr)
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, "Kestrel PortHunter", 0x10)
        except Exception:  # noqa: BLE001
            pass


def _setup_logging(data_dir: Path, debug: bool) -> None:
    for stream in (sys.stdout, sys.stderr):
        # La consola de Windows (cp850/cp1252) no tiene todos los caracteres: nunca debe tumbar la app.
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    handlers: list[logging.Handler] = [logging.FileHandler(data_dir / "porthunter.log", encoding="utf-8")]
    if sys.stderr is not None:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def run_web(app, args) -> None:
    from porthunter.web import LOCAL_HOSTS

    if args.host not in LOCAL_HOSTS:
        print("AVISO: la app escucha fuera de localhost. Cualquiera que llegue a este puerto desde tu red "
              "podrá lanzar escaneos con nmap desde este equipo.")
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    print(f"\n  Kestrel PortHunter {__version__}  ->  {url}\n  (Ctrl+C para salir)\n", flush=True)
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, (url,)).start()
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False, debug=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="Kestrel PortHunter: inventario de red y escaneo con nmap")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--desktop", action="store_true", help="Ventana de escritorio sin servidor ni puertos")
    mode.add_argument("--web", action="store_true", help="Servidor local y navegador")
    ap.add_argument("--host", default="127.0.0.1",
                    help="[web] Dirección donde escuchar (por defecto sólo este equipo: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8765, help="[web] Puerto")
    ap.add_argument("--allow-host", action="append", default=[],
                    help="[web] Nombre/IP extra aceptado en la cabecera Host (si escuchas fuera de localhost)")
    ap.add_argument("--no-browser", action="store_true", help="[web] No abrir el navegador al arrancar")
    ap.add_argument("--data", help="Carpeta de datos (por defecto ./data)")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    desktop = args.desktop or (not args.web and sys.platform == "win32")
    data_dir = Path(args.data) if args.data else DATA_DIR
    ensure_dirs(data_dir)
    _setup_logging(data_dir, args.debug)

    if desktop:
        from porthunter import desktop as desktop_mode

        ok, reason = desktop_mode.available()
        if not ok:
            _message_box(f"No se puede abrir la ventana de escritorio: {reason}\n\n"
                         "Instala las dependencias (pip install -r requirements.txt) o usa el modo "
                         "navegador: iniciar_web.bat / python run.py --web")
            return 1

    from porthunter.web import create_app

    allowed = set(args.allow_host) | ({args.host} if args.web else set())
    app = create_app(data_dir, allowed_hosts=allowed)
    ext = app.extensions["porthunter"]
    try:
        if desktop:
            desktop_mode.run(app, data_dir, debug=args.debug)
        else:
            run_web(app, args)
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("porthunter").exception("Error fatal")
        _message_box(f"Error: {exc}\n\nDetalles en {data_dir / 'porthunter.log'}")
        return 1
    finally:
        ext["monitor"].stop()
        ext["jobs"].shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
