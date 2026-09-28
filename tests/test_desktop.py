"""Modo escritorio: el puente JS <-> Python y la página autocontenida (sin abrir ventana)."""

import base64

import pytest

from porthunter.desktop import Bridge, build_page
from porthunter.web import create_app


@pytest.fixture
def bridge(tmp_path):
    return Bridge(create_app(tmp_path, start_background=False))


def test_page_is_self_contained(tmp_path):
    html = build_page(tmp_path / "ui").read_text(encoding="utf-8")
    assert "/static/" not in html
    assert "window.PH_DESKTOP = true" in html
    assert "<style>" in html and "async function api(" in html
    assert "data:image/svg+xml;base64," in html


def test_request_goes_through_the_api_without_a_server(bridge):
    r = bridge.request("GET", "/api/summary")
    assert r["status"] == 200 and r["data"]["total"] == 0
    r = bridge.request("POST", "/api/jobs/preview", {"kind": "list", "targets": "10.10.0.0/17", "options": {}})
    assert r["status"] == 200 and " -sL " in r["data"]["commands"][0]
    r = bridge.request("POST", "/api/jobs/preview", {"kind": "ping", "targets": "-oN x"})
    assert r["status"] == 400 and "no válido" in r["data"]["error"]


def test_request_only_reaches_the_api(bridge):
    assert bridge.request("GET", "/")["status"] == 404
    assert bridge.request("GET", "http://example.com/api/x")["status"] == 404


def test_upload_imports_files(bridge, fixture_text):
    files = [{"name": "ping.xml", "data": base64.b64encode(fixture_text("ping_scan.xml").encode()).decode()}]
    r = bridge.upload(files)
    assert r["status"] == 200 and r["data"]["results"][0]["up"] == 3
    assert bridge.request("GET", "/api/summary")["data"]["total"] == 3


def test_download_saves_where_the_user_chooses(bridge, fixture_text, tmp_path):
    bridge.upload([{"name": "ping.xml", "data": base64.b64encode(fixture_text("ping_scan.xml").encode()).decode()}])
    target = tmp_path / "elegido.txt"
    asked = {}

    class FakeWindow:
        def create_file_dialog(self, dialog_type, save_filename):
            asked["name"] = save_filename
            return str(target)

    bridge._window = FakeWindow()
    r = bridge.download("/api/export/targets")
    assert r == {"saved": str(target)}
    assert asked["name"].startswith("porthunter_targets_") and asked["name"].endswith(".txt")
    assert target.read_text(encoding="utf-8").split() == ["10.10.0.1", "10.10.0.5", "10.10.0.6"]
    assert bridge.download("/api/alerts/999/pcap")["error"] == "No hay captura para esta alerta"
