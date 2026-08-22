from datetime import datetime, timezone

from idps.models import Packet
from idps.verify import verify_from_capture

BASE = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
ATTACKER, VICTIM = "10.0.0.5", "10.0.0.10"


def test_all_ports_reachable_before_block():
    packets = [
        Packet(timestamp=BASE, src_ip=VICTIM, dst_ip=ATTACKER, src_port=port, dst_port=40000,
               protocol="TCP", flags="SYN,ACK")
        for port in (20, 21, 22)
    ]
    result = verify_from_capture(packets, "before_block", ATTACKER, VICTIM, [20, 21, 22])
    assert result.ports_reachable == [20, 21, 22]
    assert result.ports_blocked == []
    assert not result.fully_blocked


def test_no_ports_reachable_after_block():
    # only the attacker's outbound SYNs are captured - no responses at all from the victim
    packets = [
        Packet(timestamp=BASE, src_ip=ATTACKER, dst_ip=VICTIM, src_port=40000, dst_port=port,
               protocol="TCP", flags="SYN")
        for port in (20, 21, 22)
    ]
    result = verify_from_capture(packets, "after_block", ATTACKER, VICTIM, [20, 21, 22])
    assert result.ports_reachable == []
    assert result.ports_blocked == [20, 21, 22]
    assert result.fully_blocked


def test_partial_reachability():
    packets = [
        Packet(timestamp=BASE, src_ip=VICTIM, dst_ip=ATTACKER, src_port=20, dst_port=40000,
               protocol="TCP", flags="SYN,ACK")
    ]
    result = verify_from_capture(packets, "before_block", ATTACKER, VICTIM, [20, 21, 22])
    assert result.ports_reachable == [20]
    assert result.ports_blocked == [21, 22]
