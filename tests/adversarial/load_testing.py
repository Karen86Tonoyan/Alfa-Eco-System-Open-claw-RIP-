from __future__ import annotations

from dataclasses import dataclass
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
