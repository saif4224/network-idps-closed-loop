#!/usr/bin/env python3
"""One-time (dev-only) generator for tests/fixtures/synthetic_scan.pcap.

Builds a real, valid PCAP with scapy: one source IP sending SYN
packets to 15 distinct destination ports within ~150ms - a synthetic
but structurally real port-scan pattern, used to exercise the
detection/capture code against genuine tshark/Suricata output in
tests, without needing a live 3-container sandbox running.

Usage: python scripts/generate_pcap_fixture.py
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, TCP, Ether, wrpcap

OUT_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic_scan.pcap"
SRC_IP = "10.0.0.5"
DST_IP = "10.0.0.10"


def main() -> None:
    base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc).timestamp()
    packets = []
    for i, port in enumerate(range(20, 35)):
        pkt = Ether() / IP(src=SRC_IP, dst=DST_IP) / TCP(sport=40000 + i, dport=port, flags="S")
        pkt.time = base + i * 0.01
        packets.append(pkt)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} synthetic packets to {OUT_PATH}")


if __name__ == "__main__":
    main()
