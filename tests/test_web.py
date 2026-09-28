import io

import pytest

from porthunter.web import create_app

H = {"X-PortHunter": "1"}


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path, start_background=False)
    return app.test_client()


def test_post_without_custom_header_is_rejected(client):
    assert client.post("/api/jobs", json={"kind": "ping", "targets": "10.0.0.1"}).status_code == 403


def test_foreign_host_header_is_rejected(client):
    r = client.get("/api/dashboard", headers={"Host": "evil.example:8765"})
    assert r.status_code == 403


def test_preview_builds_two_phase_smart_command(client):
    r = client.post("/api/jobs/preview", headers=H, json={
        "kind": "smart", "targets": "10.10.0.0/17", "options": {"profile": "rapido", "reinforced": True}})
    cmds = r.get_json()["commands"]
    assert len(cmds) == 2
    assert " -sn " in cmds[0] and "-PS21,22,23,80,135,139,443,445,3389,8080" in cmds[0]
    assert cmds[0].endswith("10.10.0.0/17")
    assert " -F " in cmds[1] and " -Pn " in cmds[1] and "-iL" in cmds[1]


def test_preview_rejects_output_options_and_bad_targets(client):
    r = client.post("/api/jobs/preview", headers=H, json={
        "kind": "custom", "targets": "10.0.0.1", "options": {"extra_args": "-sV -oN C:\\x.txt"}})
    assert r.status_code == 400 and "-oN" in r.get_json()["error"]
    r = client.post("/api/jobs/preview", headers=H, json={"kind": "ping", "targets": "10.0.0.1 -iL x"})
    assert r.status_code == 400


def test_import_then_search_and_export(client, fixture_text):
    data = {"file": [(io.BytesIO(fixture_text("list_scan.xml").encode()), "lista.xml"),
                     (io.BytesIO(fixture_text("ping_scan.xml").encode()), "ping.xml")]}
    r = client.post("/api/import", headers=H, data=data, content_type="multipart/form-data")
    results = r.get_json()["results"]
    assert [x["format"] for x in results] == ["xml", "xml"]
    assert results[1]["ip_changes"] == 1

    found = client.get("/api/devices?q=juan").get_json()
    assert found["total"] == 1 and found["items"][0]["current_ip"] == "10.10.0.6"

    dev_id = found["items"][0]["id"]
    r = client.patch(f"/api/devices/{dev_id}", headers=H, json={"alias": "PC de Juan", "watched": True})
    assert r.get_json()["alias"] == "PC de Juan"
    dash = client.get("/api/dashboard").get_json()
    assert [d["name"] for d in dash["watched"]] == ["PC de Juan"]
    assert any("10.10.0.2 → 10.10.0.6" in e["message"] for e in dash["events"])

    txt = client.get("/api/export/txt").get_data(as_text=True)
    assert "pc-juan.empresa.local" in txt and "PC de Juan" in txt
    assert client.get("/api/export/targets?status=up").get_data(as_text=True).split() == [
        "10.10.0.1", "10.10.0.5", "10.10.0.6"]


def test_networks_crud(client):
    r = client.post("/api/networks", headers=H, json={
        "name": "Oficina", "targets": "10.10.0.0/17", "kind": "smart", "options": {"profile": "rapido"},
        "interval_min": 60})
    net_id = r.get_json()["id"]
    client.patch(f"/api/networks/{net_id}", headers=H, json={"interval_min": 0})
    nets = client.get("/api/networks").get_json()
    assert nets[0]["interval_min"] == 0 and nets[0]["options"] == {"profile": "rapido"}
    client.delete(f"/api/networks/{net_id}", headers=H)
    assert client.get("/api/networks").get_json() == []
