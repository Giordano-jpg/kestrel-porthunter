"""Integración del monitor con paquetes reales de Scapy (sin capturar de la red).

En Windows importar Scapy carga Npcap, que en modo "sólo administradores" pide UAC;
por eso aquí sólo se ejecuta si PORTHUNTER_SCAPY_TESTS=1.
"""

import os
import sys

import pytest

if sys.platform == "win32" and not os.environ.get("PORTHUNTER_SCAPY_TESTS"):
    pytest.skip("En Windows importar Scapy carga Npcap (puede pedir UAC)", allow_module_level=True)

pytest.importorskip("scapy")

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.utils import rdpcap  # noqa: E402

from porthunter.config import Settings, ensure_dirs  # noqa: E402
from porthunter.db import Database  # noqa: E402
from porthunter.detector import ScanDetector  # noqa: E402
from porthunter.monitor import MonitorService  # noqa: E402

ME, ATTACKER = "10.10.5.20", "10.10.2.33"
MACS = {"src": "aa:bb:cc:00:00:33", "dst": "aa:bb:cc:00:00:70"}


def test_interfaces_load_in_a_fresh_process():
    """Regresión: comprobar sólo scapy.config (sin scapy.arch) daba "Npcap no disponible"
    y ninguna interfaz. Hace falta un proceso nuevo, porque este módulo ya importó Scapy."""
    import subprocess
    from pathlib import Path

    code = ("from porthunter.monitor import MonitorService, scapy_status; "
            "print(scapy_status()[0], len(MonitorService.interfaces()))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=120,
                         cwd=Path(__file__).resolve().parents[1])
    ok, count = out.stdout.split()
    assert ok == "True" and int(count) > 0, out.stderr


def test_normalize():
    syn = Ether(**MACS) / IP(src=ATTACKER, dst=ME) / TCP(dport=22, flags="S", window=1024, options=[("MSS", 1460)])
    p = MonitorService.normalize(syn)
    assert (p.kind, p.src, p.dst, p.dport, p.flags, p.window, p.tcp_opts) == ("tcp", ATTACKER, ME, 22, 2, 1024, ("MSS",))
    assert MonitorService.normalize(Ether(**MACS) / IP(src=ATTACKER, dst=ME) / UDP(sport=5000, dport=161)).kind == "udp"
    icmp = MonitorService.normalize(Ether(**MACS) / IP(src=ATTACKER, dst=ME) / ICMP(type=8))
    assert icmp.kind == "icmp" and icmp.icmp_type == 8
    arp = MonitorService.normalize(Ether(**MACS) / ARP(op=1, psrc=ATTACKER, pdst="10.10.0.9"))
    assert (arp.kind, arp.src, arp.dst, arp.arp_op) == ("arp", ATTACKER, "10.10.0.9", 1)


def test_scan_creates_named_alert_and_pcap(tmp_path):
    settings = Settings(tmp_path)
    ensure_dirs(tmp_path)
    db = Database(settings.db_path)
    db.execute("INSERT INTO devices(hostname, current_ip, status, first_seen, last_seen) "
               "VALUES ('portatil-pepe.empresa.local', ?, 'up', 'x', 'x')", (ATTACKER,))
    mon = MonitorService(db, settings)
    mon.detector = ScanDetector({ME}, tcp_ports_threshold=10)
    mon._save_pcap = True

    for i, port in enumerate(range(20, 40)):
        pkt = (Ether(**MACS) / IP(src=ATTACKER, dst=ME)
               / TCP(sport=40000, dport=port, flags="S", window=1024, options=[("MSS", 1460)]))
        pkt.time = 1000 + i * 0.01
        mon._on_packet(pkt)
    mon._flush(final=True)

    alerts = db.query("SELECT * FROM alerts")
    assert len(alerts) == 1
    a = alerts[0]
    assert a["kind"] == "tcp_scan" and a["severity"] == "alta"
    assert a["src_name"] == "portatil-pepe.empresa.local" and "nmap" in a["note"]
    assert a["count"] == 20 and a["ports"].split(",")[:3] == ["20", "21", "22"]
    # El .pcap incluye también los paquetes anteriores a que saltara la alerta.
    assert len(rdpcap(str(settings.captures_dir / a["pcap"]))) == 20
