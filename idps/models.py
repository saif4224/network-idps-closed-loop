"""Core data model for the closed-loop pipeline: capture -> detect ->
respond -> verify.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Packet:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP | UDP
    flags: str = ""  # e.g. "SYN", "SYN,ACK", "RST"
    length: int = 0


@dataclass
class ScanEvidence:
    src_ip: str
    distinct_dst_ports: list[int]
    window_start: datetime
    window_end: datetime
    packet_count: int


@dataclass
class DetectionResult:
    detector: str  # e.g. "port_scan_fanout" | "suricata"
    src_ip: str
    severity: str  # low | medium | high | critical
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class SuricataAlert:
    signature: str
    category: str
    severity: int  # Suricata's own 1 (high) - 3 (low) scale
    src_ip: str
    dst_ip: str
    dst_port: int
    timestamp: datetime


@dataclass
class FirewallRule:
    src_ip: str
    action: str  # DROP | REJECT
    rule_spec: str
    applied_at: datetime


@dataclass
class VerificationAttempt:
    phase: str  # "before_block" | "after_block"
    target: str
    ports_reachable: list[int]
    ports_blocked: list[int]

    @property
    def fully_blocked(self) -> bool:
        return len(self.ports_reachable) == 0


@dataclass
class IncidentReport:
    generated_at: datetime
    detections: list[DetectionResult]
    suricata_alerts: list[SuricataAlert]
    applied_rule: FirewallRule | None
    verification_before: VerificationAttempt | None
    verification_after: VerificationAttempt | None
    closed_loop_confirmed: bool
