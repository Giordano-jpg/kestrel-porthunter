from porthunter.nmap_xml import parse_port_ranges, parse_xml


def test_list_scan(fixture_text):
    r = parse_xml(fixture_text("list_scan.xml"))
    assert r.complete and r.is_list_scan and not r.is_ping_scan
    assert len(r.hosts) == 5
    named = {h.ip: h.hostname for h in r.hosts if h.hostname}
    assert named == {"10.10.0.1": "gw.empresa.local", "10.10.0.2": "pc-juan.empresa.local",
                     "10.10.0.3": "impresora-2p.empresa.local"}
    assert all(h.status == "unknown" for h in r.hosts)


def test_ping_scan(fixture_text):
    r = parse_xml(fixture_text("ping_scan.xml"))
    assert r.is_ping_scan and r.hosts_up == 3
    gw = r.hosts[0]
    assert gw.status == "up" and gw.reason == "arp-response"
    assert gw.mac == "AA:BB:CC:00:00:01" and gw.vendor == "Cisco Systems"
    remote = [h for h in r.hosts if h.ip == "10.10.0.5"][0]
    assert remote.reason_ttl == 126 and remote.hostname is None


def test_port_scan(fixture_text):
    r = parse_xml(fixture_text("port_scan.xml"))
    h = r.hosts[0]
    assert [(p.proto, p.port, p.state) for p in h.ports if p.state == "open"] == [
        ("tcp", 135, "open"), ("tcp", 445, "open"), ("tcp", 3389, "open"), ("udp", 137, "open")]
    assert h.ports[0].product == "Microsoft Windows RPC" and h.ports[0].ttl == 128
    assert h.netbios == "PC-JUAN"
    assert h.distance == 1 and h.trace[0].ip == "10.10.0.6"
    assert h.os_matches[0] == ("Microsoft Windows 10 1709 - 21H2", 97)
    assert r.covered("tcp", 3389) and r.covered("udp", 137)
    assert not r.covered("tcp", 22) and not r.covered("udp", 135)


def test_truncated_file_returns_partial_results(fixture_text):
    text = fixture_text("ping_scan.xml")
    cut = text[: text.index('<address addr="10.10.0.6"')]
    r = parse_xml(cut)
    assert not r.complete
    assert [h.ip for h in r.hosts] == ["10.10.0.1"]


def test_parse_port_ranges():
    assert parse_port_ranges("1,3-4,6,,x") == [(1, 1), (3, 4), (6, 6)]
