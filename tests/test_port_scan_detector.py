from datetime import datetime, timedelta, timezone

from idps.detect.port_scan_detector import detect_port_scans, find_scan_evidence
from idps.models import Packet

BASE = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def _syn(src_ip: str, dst_port: int, offset_seconds: float) -> Packet:
    return Packet(
        timestamp=BASE + timedelta(seconds=offset_seconds), src_ip=src_ip, dst_ip="10.0.0.10",
        src_port=40000, dst_port=dst_port, protocol="TCP", flags="SYN",
    )


def test_detects_fanout_within_window():
    packets = [_syn("10.0.0.5", 20 + i, i * 0.1) for i in range(12)]
    results = detect_port_scans(packets, port_threshold=10, window_seconds=5)
    assert len(results) == 1
    assert results[0].src_ip == "10.0.0.5"
    assert results[0].severity == "high"


def test_no_detection_below_threshold():
    packets = [_syn("10.0.0.5", 20 + i, i * 0.1) for i in range(5)]
    results = detect_port_scans(packets, port_threshold=10, window_seconds=5)
    assert results == []


def test_no_detection_when_spread_outside_window():
    # 12 distinct ports, but 10 seconds apart each - never 10 within a 5s window
    packets = [_syn("10.0.0.5", 20 + i, i * 10) for i in range(12)]
    results = detect_port_scans(packets, port_threshold=10, window_seconds=5)
    assert results == []


def test_ignores_synack_and_non_syn_packets():
    packets = [
        Packet(timestamp=BASE, src_ip="10.0.0.10", dst_ip="10.0.0.5", src_port=20, dst_port=40000,
               protocol="TCP", flags="SYN,ACK")
        for _ in range(15)
    ]
    results = detect_port_scans(packets, port_threshold=10, window_seconds=5)
    assert results == []


def test_repeated_port_does_not_inflate_distinct_count():
    packets = [_syn("10.0.0.5", 20, i * 0.1) for i in range(15)]  # same port every time
    evidence = find_scan_evidence(packets, port_threshold=10, window_seconds=5)
    assert evidence == []


def test_multiple_sources_each_evaluated_independently():
    packets = [_syn("10.0.0.5", 20 + i, i * 0.1) for i in range(12)]
    packets += [_syn("10.0.0.6", 20 + i, i * 0.1) for i in range(3)]  # below threshold
    results = detect_port_scans(packets, port_threshold=10, window_seconds=5)
    assert {r.src_ip for r in results} == {"10.0.0.5"}
