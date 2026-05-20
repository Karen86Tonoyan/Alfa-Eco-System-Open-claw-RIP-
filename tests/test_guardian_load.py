from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from .adversarial.load_testing import build_burst_payloads, run_cerber_burst, run_guardian_burst


def test_guardian_burst_handles_large_payload_mix_without_losing_accounting():
    metrics = run_guardian_burst(cycles=4)

    assert metrics.total_requests == len(build_burst_payloads(cycles=4))
    assert metrics.malicious_requests > metrics.clean_requests
    assert metrics.hold_count + metrics.deny_count > 0
    assert metrics.average_risk >= 0.0
    assert metrics.duration_ms >= 0.0


def test_cerber_burst_stays_stable_and_blocks_malicious_mix():
    metrics = run_cerber_burst(cycles=2)

    assert metrics.total_requests == len(build_burst_payloads(cycles=2))
    assert metrics.deny_count > 0
    assert metrics.allow_count > 0
    assert metrics.average_risk >= 0.0


def test_guardian_burst_completes_quickly_enough_for_local_regression():
    metrics = run_guardian_burst(cycles=2)

    assert metrics.duration_ms < 3000
