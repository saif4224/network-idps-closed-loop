"""Assembles the final incident report and decides whether the closed
loop is actually confirmed: a real block was applied, the target was
genuinely reachable beforehand, and it's genuinely unreachable
afterward - all three, or it doesn't count.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import asdict

from idps.models import DetectionResult, FirewallRule, IncidentReport, SuricataAlert, VerificationAttempt


def _closed_loop_confirmed(
    applied_rule: FirewallRule | None,
    verification_before: VerificationAttempt | None,
    verification_after: VerificationAttempt | None,
) -> bool:
    if applied_rule is None or verification_before is None or verification_after is None:
        return False
    was_reachable = len(verification_before.ports_reachable) > 0
    now_blocked = verification_after.fully_blocked
    return was_reachable and now_blocked


def build_incident_report(
    detections: list[DetectionResult],
    suricata_alerts: list[SuricataAlert],
    applied_rule: FirewallRule | None,
    verification_before: VerificationAttempt | None,
    verification_after: VerificationAttempt | None,
) -> IncidentReport:
    return IncidentReport(
        generated_at=dt.datetime.now(dt.timezone.utc),
        detections=detections,
        suricata_alerts=suricata_alerts,
        applied_rule=applied_rule,
        verification_before=verification_before,
        verification_after=verification_after,
        closed_loop_confirmed=_closed_loop_confirmed(applied_rule, verification_before, verification_after),
    )


def incident_report_to_dict(report: IncidentReport) -> dict:
    payload = asdict(report)
    payload["generated_at"] = report.generated_at.isoformat()
    if payload["applied_rule"]:
        payload["applied_rule"]["applied_at"] = report.applied_rule.applied_at.isoformat()
    for alert in payload["suricata_alerts"]:
        timestamp = alert["timestamp"]
        alert["timestamp"] = timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp
    return payload
