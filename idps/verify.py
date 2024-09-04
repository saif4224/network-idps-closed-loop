"""Verification: did the firewall block actually change what's on the
wire? Compares a capture against which of the scanned ports produced
*any* response from the victim (SYN-ACK for open, RST for closed) -
before the block, every probed port should respond one way or another;
after a working block, none of them should, because iptables drops the
attacker's packets before the victim's TCP stack ever sees them.

This is deliberately capture-based rather than attacker-reported: the
sensor's own packet evidence is the single source of truth for both
detection and verification, so "the loop closed" is something this
pipeline can prove, not just assert.
"""
from __future__ import annotations

from idps.models import Packet, VerificationAttempt


def verify_from_capture(
    packets: list[Packet], phase: str, attacker_ip: str, victim_ip: str, scanned_ports: list[int]
) -> VerificationAttempt:
    responded_ports = {
        p.src_port
        for p in packets
        if p.src_ip == victim_ip and p.dst_ip == attacker_ip and p.src_port in scanned_ports
    }

    return VerificationAttempt(
        phase=phase,
        target=victim_ip,
        ports_reachable=sorted(responded_ports),
        ports_blocked=sorted(set(scanned_ports) - responded_ports),
    )
