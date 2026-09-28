from porthunter.inventory import apply_scan, device_detail, estimate_distance, list_devices
from porthunter.nmap_xml import merge_discovered, parse_xml

T1, T2, T3, T4 = ("2026-09-28T14:00:00Z", "2026-09-28T15:00:00Z", "2026-09-28T16:00:00Z",
                  "2026-09-28T17:00:00Z")
NET = ["10.10.0.0/29"]


def by_name(conn, hostname):
    return conn.execute("SELECT * FROM devices WHERE hostname = ?", (hostname,)).fetchone()


def events(conn, kind=None):
    sql = "SELECT * FROM events" + (" WHERE kind = ?" if kind else "")
    return [dict(r) for r in conn.execute(sql, (kind,) if kind else ())]


def test_list_scan_only_keeps_named_hosts(db, fixture_text):
    with db.connect() as conn:
        s = apply_scan(conn, parse_xml(fixture_text("list_scan.xml")), job_id=1, targets=NET, ts=T1)
        assert s["source"] == "list" and s["hosts"] == 3 and s["new"] == 3
        juan = by_name(conn, "pc-juan.empresa.local")
        assert juan["current_ip"] == "10.10.0.2" and juan["status"] == "unknown"


def test_device_followed_across_ip_change(db, fixture_text):
    with db.connect() as conn:
        apply_scan(conn, parse_xml(fixture_text("list_scan.xml")), targets=NET, ts=T1)
        conn.execute("UPDATE devices SET watched = 1 WHERE hostname = 'impresora-2p.empresa.local'")
        s = apply_scan(conn, parse_xml(fixture_text("ping_scan.xml")), job_id=2, targets=NET, ts=T2)

        assert s["source"] == "ping" and s["up"] == 3 and s["ip_changes"] == 1
        juan = by_name(conn, "pc-juan.empresa.local")
        assert juan["current_ip"] == "10.10.0.6" and juan["status"] == "up"
        assert juan["mac"] == "AA:BB:CC:00:00:02" and juan["vendor"] == "Dell" and juan["distance"] == 1
        hist = {r["ip"] for r in conn.execute("SELECT ip FROM ip_history WHERE device_id = ?", (juan["id"],))}
        assert hist == {"10.10.0.2", "10.10.0.6"}
        assert "10.10.0.2 → 10.10.0.6" in events(conn, "ip_change")[0]["message"]

        # La impresora está en el rango, no respondió y estaba vigilada -> "down".
        printer = by_name(conn, "impresora-2p.empresa.local")
        assert printer["status"] == "down"

        # Equipo remoto sin nombre: TTL 126 -> Windows a 3 saltos.
        remote = conn.execute("SELECT * FROM devices WHERE current_ip = '10.10.0.5'").fetchone()
        assert remote["hostname"] is None and remote["distance"] == 3 and remote["ttl"] == 126


def test_watched_device_down_and_up_events(db, fixture_text):
    ping = parse_xml(fixture_text("ping_scan.xml"))
    with db.connect() as conn:
        apply_scan(conn, ping, targets=NET, ts=T1)
        conn.execute("UPDATE devices SET watched = 1 WHERE hostname = 'gw.empresa.local'")
        ping_without_gw = parse_xml(fixture_text("ping_scan.xml"))
        ping_without_gw.hosts = [h for h in ping_without_gw.hosts if h.ip != "10.10.0.1"]
        s = apply_scan(conn, ping_without_gw, targets=NET, ts=T2)
        assert s["went_down"] == 1
        assert by_name(conn, "gw.empresa.local")["status"] == "down"
        apply_scan(conn, ping, targets=NET, ts=T3)
        assert by_name(conn, "gw.empresa.local")["status"] == "up"
        kinds = [e["kind"] for e in events(conn) if e["kind"] in ("up", "down")]
        assert kinds == ["down", "up"]


def test_ports_new_and_closed_events_respect_coverage(db, fixture_text):
    xml = fixture_text("port_scan.xml")
    with db.connect() as conn:
        s = apply_scan(conn, parse_xml(xml), ts=T1)
        assert s["source"] == "ports" and s["open_ports"] == 4
        juan = by_name(conn, "pc-juan.empresa.local")
        assert juan["netbios"] == "PC-JUAN" and juan["os_guess"].startswith("Microsoft Windows 10")
        assert not events(conn, "port_open")  # primer escaneo: no es "nuevo"

        # Segundo escaneo: 3389 cerrado, 139 abierto.
        second = xml.replace('portid="3389"><state state="open"', 'portid="3389"><state state="closed"')
        second = second.replace('portid="139"><state state="closed"', 'portid="139"><state state="open"')
        apply_scan(conn, parse_xml(second), ts=T2)
        ports = {(r["proto"], r["port"]) for r in conn.execute("SELECT * FROM ports")}
        assert ports == {("tcp", 135), ("tcp", 139), ("tcp", 445), ("udp", 137)}
        assert "139/tcp" in events(conn, "port_open")[0]["message"]
        assert "3389/tcp" in events(conn, "port_closed")[0]["message"]

        # Un escaneo que no cubre el 445 no debe darlo por cerrado.
        narrow = second.replace('services="135,139,445,3389"', 'services="135,139"')
        narrow = narrow.replace('portid="445"><state state="open"', 'portid="445"><state state="filtered"')
        apply_scan(conn, parse_xml(narrow), ts=T3)
        assert conn.execute("SELECT 1 FROM ports WHERE port = 445").fetchone()


def test_older_import_does_not_override_current_ip(db, fixture_text):
    with db.connect() as conn:
        apply_scan(conn, parse_xml(fixture_text("ping_scan.xml")), targets=NET, ts=T3)
        apply_scan(conn, parse_xml(fixture_text("list_scan.xml")), ts=T1)  # fichero antiguo
        juan = by_name(conn, "pc-juan.empresa.local")
        assert juan["current_ip"] == "10.10.0.6"
        hist = {r["ip"] for r in conn.execute("SELECT ip FROM ip_history WHERE device_id = ?", (juan["id"],))}
        assert hist == {"10.10.0.2", "10.10.0.6"}


def test_anonymous_device_is_adopted_when_name_appears(db, fixture_text):
    ping = parse_xml(fixture_text("ping_scan.xml"))
    with db.connect() as conn:
        apply_scan(conn, ping, targets=NET, ts=T1)
        anon = conn.execute("SELECT id FROM devices WHERE current_ip = '10.10.0.5'").fetchone()["id"]
        named = parse_xml(fixture_text("ping_scan.xml"))
        named.hosts[3].hostnames = ["srv-backup.empresa.local"]
        apply_scan(conn, named, targets=NET, ts=T2)
        row = conn.execute("SELECT * FROM devices WHERE current_ip = '10.10.0.5'").fetchall()
        assert len(row) == 1 and row[0]["id"] == anon and row[0]["hostname"] == "srv-backup.empresa.local"


def test_confirmed_ip_is_released_by_previous_owner(db, fixture_text):
    with db.connect() as conn:
        apply_scan(conn, parse_xml(fixture_text("list_scan.xml")), ts=T1)
        # Otro equipo aparece vivo en la antigua IP de PC-JUAN (10.10.0.2).
        ping = parse_xml(fixture_text("ping_scan.xml"))
        ping.hosts[1].ip = "10.10.0.2"
        ping.hosts[1].hostnames = ["portatil-ana.empresa.local"]
        ping.hosts[1].mac = "AA:BB:CC:00:00:99"
        apply_scan(conn, ping, targets=NET, ts=T4)
        assert by_name(conn, "pc-juan.empresa.local")["current_ip"] is None
        assert by_name(conn, "portatil-ana.empresa.local")["current_ip"] == "10.10.0.2"


def test_search_by_name_port_and_old_ip(db, fixture_text):
    with db.connect() as conn:
        apply_scan(conn, parse_xml(fixture_text("list_scan.xml")), ts=T1)
        apply_scan(conn, parse_xml(fixture_text("ping_scan.xml")), targets=NET, ts=T2)
        apply_scan(conn, parse_xml(fixture_text("port_scan.xml")), ts=T3)
        assert [d["hostname"] for d in list_devices(conn, q="juan")["items"]] == ["pc-juan.empresa.local"]
        assert [d["hostname"] for d in list_devices(conn, q="3389")["items"]] == ["pc-juan.empresa.local"]
        # Buscar por una IP antigua encuentra al equipo que la tuvo.
        assert [d["hostname"] for d in list_devices(conn, q="10.10.0.2")["items"]] == ["pc-juan.empresa.local"]
        juan_id = by_name(conn, "pc-juan.empresa.local")["id"]
        detail = device_detail(conn, juan_id)
        assert detail["trace"][0]["ip"] == "10.10.0.6" and len(detail["ports"]) == 4


def test_cancelled_scan_keeps_discovered_ports_and_closes_nothing(db, fixture_text):
    xml = fixture_text("port_scan.xml")
    with db.connect() as conn:
        apply_scan(conn, parse_xml(xml), ts=T1)
        partial = parse_xml(xml[: xml.index("<host ")])  # nmap cancelado antes de escribir el host
        assert not partial.complete and not partial.hosts
        merge_discovered(partial, {"10.10.0.6": {("tcp", 8080)}})
        s = apply_scan(conn, partial, ts=T2)
        assert s["source"] == "ports" and s["open_ports"] == 1
        ports = {(r["proto"], r["port"]) for r in conn.execute("SELECT * FROM ports")}
        assert ports == {("tcp", 135), ("tcp", 445), ("tcp", 3389), ("udp", 137), ("tcp", 8080)}


def test_estimate_distance_from_ttl(fixture_text):
    host = parse_xml(fixture_text("ping_scan.xml")).hosts[3]
    assert estimate_distance(host) == 3
    host.reason_ttl = 63
    assert estimate_distance(host) == 2
