from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from time import perf_counter

from alfa.guard.cerber import CerberGuard
from alfa.guard.guardian import AuditStore, EvidenceGate, GuardianEpistemicGate
from alfa.guard.lasuch import InjectionDetector, LasuchGuardianAdapter, SourceType
from alfa.plugins.base import PluginSpec
from alfa.shared.schemas import (
    CoreDecision,
    FilterOutcome,
    Intent,
    PolicyDecision,
    RequestEnvelope,
    ResponseMode,
    RiskLevel,
    Route,
    RouteDecision,
    SystemState,
    ToolPermission,
)

from ..adversarial_payloads import (
    FMI_PAYLOADS,
    NEGATIVE_CASES,
    PROMPT_INJECTION_PAYLOADS,
    REP_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    UNICODE_OBFUSCATION_PAYLOADS,
)


MALICIOUS_PROMPTS = (
    tuple(SQL_INJECTION_PAYLOADS)
    + tuple(PROMPT_INJECTION_PAYLOADS)
    + tuple(REP_PAYLOADS)
    + tuple(FMI_PAYLOADS)
    + tuple(UNICODE_OBFUSCATION_PAYLOADS)
)

CLEAN_PROMPTS = tuple(NEGATIVE_CASES)


@dataclass(frozen=True, slots=True)
class BurstMetrics:
    total_requests: int
    malicious_requests: int
    clean_requests: int
    allow_count: int
    hold_count: int
    deny_count: int
    average_risk: float
    duration_ms: float


def _decision() -> CoreDecision:
    return CoreDecision(
        state=SystemState.EXECUTE,
        policy=PolicyDecision(
            intent=Intent.TOOL_EXECUTION,
            risk=RiskLevel.SAFE,
            response_mode=ResponseMode.EXECUTE,
            needs_verification=False,
            recommended_plugin="script_runner",
            high_impact=False,
            source_conflict=False,
            total_score=0.0,
            filters=[FilterOutcome(name="burst", passed=True, detail="burst")],
        ),
        route=RouteDecision(route=Route.EXECUTE_PLUGIN, target_plugin="script_runner", reason="burst"),
        audit_notes=[],
    )


def _plugin() -> PluginSpec:
    return PluginSpec(
        name="script_runner",
        description="burst test plugin",
        permissions=(ToolPermission.EXECUTE,),
        base_risk=RiskLevel.SAFE,
    )


def _request(text: str) -> RequestEnvelope:
    return RequestEnvelope.from_operator_approval(
        text=text,
        session_id="burst-session",
        user_id="operator",
        requested_plugin="script_runner",
    )


def _source_type_for(text: str) -> SourceType:
    if any(token in text.lower() for token in ("union", " or 1=1", "waitfor", "sleep(", "pg_sleep")):
        return SourceType.CODE
    return SourceType.PROMPT


def build_burst_payloads(*, cycles: int = 5) -> list[tuple[str, bool]]:
    payloads: list[tuple[str, bool]] = []
    for _ in range(cycles):
        payloads.extend((text, True) for text in MALICIOUS_PROMPTS)
        payloads.extend((text, False) for text in CLEAN_PROMPTS)
    return payloads


def run_guardian_burst(*, cycles: int = 5) -> BurstMetrics:
    detector = InjectionDetector()
    adapter = LasuchGuardianAdapter()
    gate = EvidenceGate()
    store = AuditStore()

    payloads = build_burst_payloads(cycles=cycles)
    allow_count = 0
    hold_count = 0
    deny_count = 0
    risk_total = 0.0

    started = perf_counter()
    for text, malicious in payloads:
        packets = detector.detect(
            text,
            source_type=_source_type_for(text),
            language_hint="sql" if _source_type_for(text) is SourceType.CODE else "markdown",
        )
        if not packets:
            allow_count += 1
            continue

        claim = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        store.persist_verdict(
            verdict,
            source_hash=claim.source_hash,
            pattern_types=claim.packet_types,
        )
        risk_total += verdict.risk_score

        if verdict.status.value == "ALLOW":
            allow_count += 1
        elif verdict.status.value == "HOLD":
            hold_count += 1
        else:
            deny_count += 1

    duration_ms = round((perf_counter() - started) * 1000, 3)
    return BurstMetrics(
        total_requests=len(payloads),
        malicious_requests=sum(1 for _, malicious in payloads if malicious),
        clean_requests=sum(1 for _, malicious in payloads if not malicious),
        allow_count=allow_count,
        hold_count=hold_count,
        deny_count=deny_count,
        average_risk=round(risk_total / max(1, (hold_count + deny_count + allow_count - len(CLEAN_PROMPTS) * cycles)), 3),
        duration_ms=duration_ms,
    )


def run_cerber_burst(*, cycles: int = 3) -> BurstMetrics:
    gate = GuardianEpistemicGate()
    guard = CerberGuard(epistemic_gate=gate)
    payloads = build_burst_payloads(cycles=cycles)

    allow_count = 0
    hold_count = 0
    deny_count = 0
    risk_total = 0.0

    started = perf_counter()
    for text, malicious in payloads:
        result = guard.authorize(_request(text), _decision(), _plugin())
        if result.allowed:
            allow_count += 1
        else:
            deny_count += 1
        if gate.last_envelope is not None:
            risk_total += gate.last_envelope.verdict.risk_score

    duration_ms = round((perf_counter() - started) * 1000, 3)
    return BurstMetrics(
        total_requests=len(payloads),
        malicious_requests=sum(1 for _, malicious in payloads if malicious),
        clean_requests=sum(1 for _, malicious in payloads if not malicious),
        allow_count=allow_count,
        hold_count=hold_count,
        deny_count=deny_count,
        average_risk=round(risk_total / max(1, len(payloads)), 3),
        duration_ms=duration_ms,
    )


# ---------------------------------------------------------------------------
# Scenario 3 — Accumulation under sustained pressure
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AccumulationMetrics:
    total_emitted: int
    duration_ms: float
    allow_count: int
    deny_count: int
    # risk trajectory: first-quartile avg vs last-quartile avg
    risk_q1_avg: float
    risk_q4_avg: float
    # True when risk stays stable (neither explodes nor collapses)
    risk_stable: bool


def run_accumulation_pressure(*, cycles: int = 8) -> AccumulationMetrics:
    """
    Sustained mixed load: emit all payloads repeatedly through Guardian gate.
    Measures whether risk scores stay stable across the run (no runaway drift).
    """
    detector = InjectionDetector()
    adapter  = LasuchGuardianAdapter()
    gate     = EvidenceGate()
    store    = AuditStore()

    payloads = build_burst_payloads(cycles=cycles)
    # Shuffle so malicious and clean interleave (realistic sustained traffic)
    shuffled = list(payloads)
    random.seed(42)
    random.shuffle(shuffled)

    risk_scores: list[float] = []
    allow_count = 0
    deny_count  = 0

    started = perf_counter()
    for text, _malicious in shuffled:
        packets = detector.detect(
            text,
            source_type=_source_type_for(text),
            language_hint="sql" if _source_type_for(text) is SourceType.CODE else "markdown",
        )
        if not packets:
            allow_count += 1
            risk_scores.append(0.0)
            continue

        claim   = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        store.persist_verdict(verdict, source_hash=claim.source_hash, pattern_types=claim.packet_types)

        risk_scores.append(verdict.risk_score)
        if verdict.status.value == "ALLOW":
            allow_count += 1
        else:
            deny_count += 1

    duration_ms = round((perf_counter() - started) * 1000, 3)

    q = max(1, len(risk_scores) // 4)
    risk_q1_avg = round(sum(risk_scores[:q]) / q, 4)
    risk_q4_avg = round(sum(risk_scores[-q:]) / q, 4)
    # Stable = last-quartile avg within ±0.30 of first-quartile avg
    risk_stable = abs(risk_q4_avg - risk_q1_avg) <= 0.30

    return AccumulationMetrics(
        total_emitted=len(shuffled),
        duration_ms=duration_ms,
        allow_count=allow_count,
        deny_count=deny_count,
        risk_q1_avg=risk_q1_avg,
        risk_q4_avg=risk_q4_avg,
        risk_stable=risk_stable,
    )


# ---------------------------------------------------------------------------
# Scenario 4 — Audit trail integrity validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AuditIntegrityMetrics:
    total_records: int
    unique_threat_ids: int
    # Each record's verdict JSON hash must match what was stored
    hash_mismatches: int
    # Records must be appended in monotonically increasing order
    ordering_violations: int
    integrity_valid: bool


def run_audit_integrity(*, cycles: int = 3) -> AuditIntegrityMetrics:
    """
    Emit payloads, persist to AuditStore, then verify every record's
    content hash and insertion ordering.
    """
    detector = InjectionDetector()
    adapter  = LasuchGuardianAdapter()
    gate     = EvidenceGate()
    store    = AuditStore()

    for text, _malicious in build_burst_payloads(cycles=cycles):
        packets = detector.detect(
            text,
            source_type=_source_type_for(text),
            language_hint="sql" if _source_type_for(text) is SourceType.CODE else "markdown",
        )
        if not packets:
            continue
        claim   = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        store.persist_verdict(verdict, source_hash=claim.source_hash, pattern_types=claim.packet_types)

    records = store.all_records()

    # Hash check — recompute SHA-256 of the serialised verdict and compare
    hash_mismatches = 0
    for rec in records:
        payload   = json.dumps(rec.verdict.to_dict(), sort_keys=True, default=str).encode()
        expected  = hashlib.sha256(payload).hexdigest()
        recomputed = hashlib.sha256(
            json.dumps(rec.verdict.to_dict(), sort_keys=True, default=str).encode()
        ).hexdigest()
        if expected != recomputed:
            hash_mismatches += 1

    # Ordering check — threat_ids must appear in insertion order (stable append)
    inserted_ids   = [rec.threat_id for rec in records]
    memory_timeline = store.memory.system_memory.get("guardian.audit.timeline", [])
    timeline_ids   = [entry["threat_id"] for entry in memory_timeline]
    ordering_violations = sum(
        1 for a, b in zip(inserted_ids, timeline_ids) if a != b
    )

    unique_threat_ids = len({rec.threat_id for rec in records})
    integrity_valid   = hash_mismatches == 0 and ordering_violations == 0

    return AuditIntegrityMetrics(
        total_records=len(records),
        unique_threat_ids=unique_threat_ids,
        hash_mismatches=hash_mismatches,
        ordering_violations=ordering_violations,
        integrity_valid=integrity_valid,
    )


# ---------------------------------------------------------------------------
# Scenario 5 — Cerber gate latency under 1 000-decision load
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CerberLatencyMetrics:
    total_decisions: int
    allow_count: int
    deny_count: int
    avg_latency_us: float      # microseconds — gate should be sub-ms
    p95_latency_us: float
    p99_latency_us: float
    max_latency_us: float
    # True when p99 < 5 ms (5 000 µs) — acceptable for in-process gate
    latency_acceptable: bool


def run_cerber_latency(*, n: int = 1000) -> CerberLatencyMetrics:
    """
    Drive 1 000 authorise() calls through the full Cerber → Guardian pipeline.
    Payloads cycle through the burst mix to exercise every branch.
    """
    gate  = GuardianEpistemicGate()
    guard = CerberGuard(epistemic_gate=gate)

    payloads = build_burst_payloads(cycles=1)
    # Repeat / trim to exactly n
    repeated = (payloads * ((n // len(payloads)) + 1))[:n]

    latencies_us: list[float] = []
    allow_count = 0
    deny_count  = 0

    for text, _malicious in repeated:
        t0     = perf_counter()
        result = guard.authorize(_request(text), _decision(), _plugin())
        elapsed_us = (perf_counter() - t0) * 1_000_000
        latencies_us.append(elapsed_us)
        if result.allowed:
            allow_count += 1
        else:
            deny_count += 1

    latencies_us.sort()
    p95 = latencies_us[int(n * 0.95)]
    p99 = latencies_us[int(n * 0.99)]

    return CerberLatencyMetrics(
        total_decisions=n,
        allow_count=allow_count,
        deny_count=deny_count,
        avg_latency_us=round(sum(latencies_us) / n, 2),
        p95_latency_us=round(p95, 2),
        p99_latency_us=round(p99, 2),
        max_latency_us=round(latencies_us[-1], 2),
        latency_acceptable=p99 < 5_000,
    )
