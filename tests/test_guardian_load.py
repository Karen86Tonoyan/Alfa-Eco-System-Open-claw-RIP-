from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from .adversarial.load_testing import (
    build_burst_payloads,
    run_accumulation_pressure,
    run_audit_integrity,
    run_cerber_burst,
    run_cerber_latency,
    run_guardian_burst,
)


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


# ---------------------------------------------------------------------------
# Scenario 3 — Accumulation under sustained pressure
# ---------------------------------------------------------------------------

def test_accumulation_pressure_risk_stays_stable_across_sustained_load():
    metrics = run_accumulation_pressure(cycles=6)

    assert metrics.total_emitted > 0
    assert metrics.allow_count + metrics.deny_count == metrics.total_emitted
    assert metrics.risk_stable, (
        f"Risk drifted: Q1={metrics.risk_q1_avg} Q4={metrics.risk_q4_avg} "
        f"(delta={abs(metrics.risk_q4_avg - metrics.risk_q1_avg):.3f} > 0.30)"
    )


def test_accumulation_pressure_malicious_payloads_are_denied_under_load():
    metrics = run_accumulation_pressure(cycles=4)

    # With malicious > clean in the mix, deny must dominate
    assert metrics.deny_count > metrics.allow_count


# ---------------------------------------------------------------------------
# Scenario 4 — Audit trail integrity
# ---------------------------------------------------------------------------

def test_audit_integrity_no_hash_mismatches():
    metrics = run_audit_integrity(cycles=3)

    assert metrics.hash_mismatches == 0, (
        f"{metrics.hash_mismatches} verdict records failed hash verification"
    )


def test_audit_integrity_insertion_order_matches_memory_timeline():
    metrics = run_audit_integrity(cycles=3)

    assert metrics.ordering_violations == 0, (
        f"{metrics.ordering_violations} ordering violations in audit timeline"
    )


def test_audit_integrity_all_records_present():
    metrics = run_audit_integrity(cycles=2)

    assert metrics.total_records > 0
    assert metrics.unique_threat_ids > 0
    assert metrics.integrity_valid


# ---------------------------------------------------------------------------
# Scenario 5 — Cerber gate latency under 1 000-decision load
# ---------------------------------------------------------------------------

def test_cerber_latency_p99_under_5ms():
    metrics = run_cerber_latency(n=500)

    assert metrics.latency_acceptable, (
        f"P99 latency {metrics.p99_latency_us:.0f}µs exceeds 5 000µs limit"
    )


def test_cerber_latency_all_decisions_accounted():
    metrics = run_cerber_latency(n=200)

    assert metrics.total_decisions == metrics.allow_count + metrics.deny_count


def test_cerber_latency_blocks_majority_of_malicious_mix():
    metrics = run_cerber_latency(n=400)

    # Malicious payloads dominate burst mix — deny must exceed allow
    assert metrics.deny_count > metrics.allow_count
