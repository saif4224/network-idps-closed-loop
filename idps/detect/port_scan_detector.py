"""Deterministic port-scan detector: flags a source IP that touches
too many distinct destination ports within a sliding time window - the
classic signature of an nmap-style SYN scan.

Deliberately simple and fully under our control (unlike Suricata's
tuned ruleset) so it's the reliable, reproducible trigger for the
automated response - Suricata's alerts are captured separately as
corroborating evidence, not as the primary trigger. Pure function over
a list of Packets, so it's testable with hand-built fixtures and needs
no live capture or external tool.
"""
from __future__ import annotations

from datetime import timedelta

from idps.models import DetectionResult, Packet, ScanEvidence

DEFAULT_PORT_THRESHOLD = 10
DEFAULT_WINDOW_SECONDS = 5


def _syn_packets_by_src(packets: list[Packet]) -> dict[str, list[Packet]]:
    by_src: dict[str, list[Packet]] = {}
    for pkt in packets:
        if pkt.protocol == "TCP" and "SYN" in pkt.flags and "ACK" not in pkt.flags:
            by_src.setdefault(pkt.src_ip, []).append(pkt)
    return by_src


def find_scan_evidence(
    packets: list[Packet],
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[ScanEvidence]:
    evidence: list[ScanEvidence] = []
    window = timedelta(seconds=window_seconds)

    for src_ip, syn_packets in _syn_packets_by_src(packets).items():
        syn_packets = sorted(syn_packets, key=lambda p: p.timestamp)

        window_start_idx = 0
        for i in range(len(syn_packets)):
            while syn_packets[i].timestamp - syn_packets[window_start_idx].timestamp > window:
                window_start_idx += 1

            in_window = syn_packets[window_start_idx : i + 1]
            distinct_ports = sorted({p.dst_port for p in in_window})

            if len(distinct_ports) >= port_threshold:
                evidence.append(
                    ScanEvidence(
                        src_ip=src_ip,
                        distinct_dst_ports=distinct_ports,
                        window_start=in_window[0].timestamp,
                        window_end=in_window[-1].timestamp,
                        packet_count=len(in_window),
                    )
                )
                break  # one finding per source IP is enough to trigger a response

    return evidence


def detect_port_scans(
    packets: list[Packet],
    port_threshold: int = DEFAULT_PORT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> list[DetectionResult]:
    evidence = find_scan_evidence(packets, port_threshold, window_seconds)
    return [
        DetectionResult(
            detector="port_scan_fanout",
            src_ip=e.src_ip,
            severity="high",
            description=(
                f"{e.src_ip} touched {len(e.distinct_dst_ports)} distinct ports within "
                f"{window_seconds}s ({e.packet_count} SYN packets) - consistent with a port scan."
            ),
            evidence={
                "distinct_dst_ports": e.distinct_dst_ports,
                "window_start": e.window_start.isoformat(),
                "window_end": e.window_end.isoformat(),
                "packet_count": e.packet_count,
            },
        )
        for e in evidence
    ]
