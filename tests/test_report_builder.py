import json
from datetime import datetime, timezone

from idps.models import DetectionResult, FirewallRule, VerificationAttempt
from idps.report.report_builder import build_incident_report, incident_report_to_dict

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def _rule() -> FirewallRule:
    return FirewallRule(src_ip="10.0.0.5", action="DROP", rule_spec="iptables -I INPUT ...", applied_at=NOW)


def test_closed_loop_confirmed_when_fully_verified():
    before = VerificationAttempt(
        phase="before_block", target="10.0.0.10", ports_reachable=[20, 21], ports_blocked=[]
    )
    after = VerificationAttempt(
        phase="after_block", target="10.0.0.10", ports_reachable=[], ports_blocked=[20, 21]
    )
    report = build_incident_report([], [], _rule(), before, after)
    assert report.closed_loop_confirmed


def test_not_confirmed_without_applied_rule():
    before = VerificationAttempt(phase="before_block", target="10.0.0.10", ports_reachable=[20], ports_blocked=[])
    after = VerificationAttempt(phase="after_block", target="10.0.0.10", ports_reachable=[], ports_blocked=[20])
    report = build_incident_report([], [], None, before, after)
    assert not report.closed_loop_confirmed


def test_not_confirmed_if_still_reachable_after_block():
    before = VerificationAttempt(phase="before_block", target="10.0.0.10", ports_reachable=[20], ports_blocked=[])
    after = VerificationAttempt(phase="after_block", target="10.0.0.10", ports_reachable=[20], ports_blocked=[])
    report = build_incident_report([], [], _rule(), before, after)
    assert not report.closed_loop_confirmed


def test_not_confirmed_if_never_reachable_before():
    # nothing to prove was fixed if it was never reachable in the first place
    before = VerificationAttempt(phase="before_block", target="10.0.0.10", ports_reachable=[], ports_blocked=[20])
    after = VerificationAttempt(phase="after_block", target="10.0.0.10", ports_reachable=[], ports_blocked=[20])
    report = build_incident_report([], [], _rule(), before, after)
    assert not report.closed_loop_confirmed


def test_to_dict_is_json_serializable():
    detection = DetectionResult(detector="port_scan_fanout", src_ip="10.0.0.5", severity="high", description="d")
    report = build_incident_report([detection], [], _rule(), None, None)
    payload = incident_report_to_dict(report)
    json.dumps(payload)  # must not raise
    assert payload["applied_rule"]["src_ip"] == "10.0.0.5"
