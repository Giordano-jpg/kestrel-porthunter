from porthunter.importer import parse_any

NORMAL_SL = """Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-10 09:12 Romance Standard Time
Nmap scan report for 10.10.0.0
Nmap scan report for gw.empresa.local (10.10.0.1)
Nmap scan report for PC-JUAN.empresa.local (10.10.0.2)
Nmap scan report for 10.10.0.3
Nmap done: 4 IP addresses (0 hosts up) scanned in 0.50 seconds
"""

NORMAL_PORTS = """# Nmap 7.95 scan initiated Mon Sep 28 16:07:03 2026 as: nmap -sV -oN out.txt 10.10.0.6
Nmap scan report for pc-juan.empresa.local (10.10.0.6)
Host is up, received arp-response (0.0010s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
MAC Address: AA:BB:CC:00:00:02 (Dell)
Nmap scan report for 10.10.0.9 [host down]
"""

GREPABLE = """# Nmap 7.95 scan initiated Mon Sep 28 16:07:03 2026 as: nmap -oG - 10.10.0.6
Host: 10.10.0.6 (pc-juan.empresa.local)\tStatus: Up
Host: 10.10.0.6 (pc-juan.empresa.local)\tPorts: 22/open/tcp//ssh//OpenSSH 8.9/, 80/closed/tcp//http///\tIgnored State: closed (998)
"""


def test_old_sl_txt_saved_by_powershell_redirect_in_utf16():
    result, ts, fmt = parse_any(NORMAL_SL.encode("utf-16"))
    assert fmt == "normal" and result.is_list_scan
    assert [(h.ip, h.hostname) for h in result.hosts if h.hostname] == [
        ("10.10.0.1", "gw.empresa.local"), ("10.10.0.2", "pc-juan.empresa.local")]
    assert ts is not None and ts.startswith("2025-03-10T")


def test_normal_output_with_ports():
    result, ts, fmt = parse_any(NORMAL_PORTS.encode())
    assert fmt == "normal" and not result.is_list_scan and not result.is_ping_scan
    h = result.hosts[0]
    assert h.status == "up" and h.mac == "AA:BB:CC:00:00:02" and h.vendor == "Dell"
    assert [(p.port, p.state, p.service) for p in h.ports] == [
        (135, "open", "msrpc"), (445, "open", "microsoft-ds?"), (3389, "open", "ms-wbt-server")]
    assert result.hosts[1].status == "down"
    assert ts.startswith("2026-09-28T")


def test_grepable():
    result, _, fmt = parse_any(GREPABLE.encode())
    assert fmt == "grepable" and len(result.hosts) == 1
    h = result.hosts[0]
    assert h.status == "up" and [(p.port, p.state, p.service) for p in h.ports] == [
        (22, "open", "ssh"), (80, "closed", "http")]


def test_simple_list():
    result, ts, fmt = parse_any(b"10.10.0.2\tPC-JUAN\nimpresora 10.10.0.3\nbasura\n")
    assert fmt == "lista" and ts is None and result.is_list_scan
    assert [(h.ip, h.hostname) for h in result.hosts] == [("10.10.0.2", "pc-juan"), ("10.10.0.3", "impresora")]


def test_xml(fixture_text):
    result, ts, fmt = parse_any(fixture_text("ping_scan.xml").encode())
    assert fmt == "xml" and result.is_ping_scan and ts == "2026-09-28T15:07:03Z"
