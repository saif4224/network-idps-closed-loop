import tempfile
from pathlib import Path

from idps.models import DetectionResult, VerificationAttempt
from idps.report.visualize import plot_port_fanout, plot_verification_comparison


def test_plot_port_fanout_writes_png():
    detections = [
        DetectionResult(
            detector="port_scan_fanout", src_ip="10.0.0.5", severity="high", description="d",
            evidence={"distinct_dst_ports": list(range(20, 35))},
        )
    ]
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "fanout.png"
        plot_port_fanout(detections, out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_port_fanout_handles_no_detections():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "fanout.png"
        plot_port_fanout([], out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_verification_comparison_writes_png():
    before = VerificationAttempt(phase="before_block", target="x", ports_reachable=[20, 21], ports_blocked=[])
    after = VerificationAttempt(phase="after_block", target="x", ports_reachable=[], ports_blocked=[20, 21])
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "verify.png"
        plot_verification_comparison(before, after, out)
        assert out.exists() and out.stat().st_size > 0


def test_plot_verification_comparison_handles_none():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "verify.png"
        plot_verification_comparison(None, None, out)
        assert out.exists() and out.stat().st_size > 0
