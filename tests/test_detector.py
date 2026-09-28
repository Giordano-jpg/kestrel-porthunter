from porthunter.detector import ACK, FIN, PSH, SYN, URG, Packet, ScanDetector

ME = "10.10.5.20"
ATTACKER = "10.10.2.33"


def detector(**kw):
    return ScanDetector({ME}, tcp_ports_threshold=10, udp_ports_threshold=10, stealth_threshold=3,
                        sweep_hosts_threshold=10, window_seconds=10, alert_cooldown_seconds=30, **kw)


def syn(ts, dport, src=ATTACKER, dst=ME, window=64240, opts=("MSS", "SAckOK", "Timestamp", "WScale")):
    return Packet(ts, "tcp", src, dst, 40000 + dport % 1000, dport, SYN, window, opts)


def test_syn_scan_detected_with_nmap_signature():
    d = detector()
    alerts = [d.process(syn(100 + i * 0.01, port, window=1024, opts=("MSS",))) for i, port in enumerate(range(1, 21))]
    first = next(a for a in alerts if a)
    assert first.kind == "tcp_scan" and first.src == ATTACKER and first.dst == ME
    assert first.tool == "nmap (SYN scan)" and first.severity == "alta"
    assert alerts.index(first) == 9  # salta al llegar al umbral de 10 puertos distintos
    assert len(first.ports) == 20 and first.count == 20


def test_many_connections_to_one_port_is_not_a_scan():
    d = detector()
    assert not any(d.process(syn(100 + i * 0.01, 445)) for i in range(200))
    assert d.inbound_snapshot()[0]["count"] == 200


def test_slow_scan_outside_window_is_not_detected():
    d = detector()
    assert not any(d.process(syn(100 + i * 2.0, port)) for i, port in enumerate(range(1, 30)))


def test_synack_and_outbound_are_ignored():
    d = detector()
    for i in range(50):
        assert d.process(Packet(1 + i, "tcp", ATTACKER, ME, 80 + i, 50000, SYN | ACK)) is None
        assert d.process(syn(1 + i, 1000 + i, src=ME, dst=ATTACKER)) is None
    assert not d.active


def test_stealth_scans():
    d = detector()
    kinds = [FIN, 0, FIN | PSH | URG]
    alert = None
    for i, flags in enumerate(kinds):
        alert = d.process(Packet(10 + i, "tcp", ATTACKER, ME, 555, 20 + i, flags)) or alert
    assert alert.kind == "stealth_scan" and alert.flags_seen == {"FIN", "NULL", "XMAS"}
    # Un FIN normal lleva ACK: no cuenta.
    d2 = detector()
    assert not any(d2.process(Packet(i, "tcp", ATTACKER, ME, 555, 20 + i, FIN | ACK)) for i in range(20))


def test_udp_replies_are_not_a_scan():
    d = detector()
    dns = "10.10.0.10"
    for i in range(50):
        d.process(Packet(i * 0.1, "udp", ME, dns, 50000 + i, 53))
        assert d.process(Packet(i * 0.1 + 0.01, "udp", dns, ME, 53, 50000 + i)) is None
    alert = None
    for i in range(12):
        alert = d.process(Packet(20 + i * 0.1, "udp", ATTACKER, ME, 61000, 100 + i)) or alert
    assert alert and alert.kind == "udp_scan"


def test_arp_sweep_and_whitelist():
    d = detector(whitelist=["10.10.0.1"])
    alert = None
    for i in range(15):
        alert = d.process(Packet(i * 0.05, "arp", ATTACKER, f"10.10.1.{i}", arp_op=1)) or alert
        assert d.process(Packet(i * 0.05, "arp", "10.10.0.1", f"10.10.1.{i}", arp_op=1)) is None
        # Anuncios ARP gratuitos y sondas desde 0.0.0.0 no cuentan.
        assert d.process(Packet(i * 0.05, "arp", "0.0.0.0", f"10.10.3.{i}", arp_op=1)) is None
    assert alert.kind == "arp_sweep" and len(alert.hosts) == 15


def test_other_hosts_traffic_only_with_watch_all():
    other = "10.10.7.7"
    d = detector()
    assert not any(d.process(syn(i * 0.01, i, dst=other)) for i in range(1, 30))
    d = detector(watch_all=True)
    assert any(d.process(syn(i * 0.01, i, dst=other)) for i in range(1, 30))


def test_expire_closes_alert_and_allows_a_new_one():
    d = detector()
    for i, port in enumerate(range(1, 15)):
        d.process(syn(100 + i * 0.01, port))
    assert len(d.active) == 1
    assert d.expire(now=110) == []
    ended = d.expire(now=200)
    assert len(ended) == 1 and not d.active
    alert = None
    for i, port in enumerate(range(100, 115)):
        alert = d.process(syn(300 + i * 0.01, port)) or alert
    assert alert is not ended[0] and alert.kind == "tcp_scan"
