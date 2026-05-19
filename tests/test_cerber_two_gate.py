"""
Tests for the Cerber two-gate architecture.

Gate 1 — CerberGuard pattern layer (existing behaviour, regression coverage).
Gate 2 — EpistemicGate integration (new, injected via dependency injection).
"""
from __future__ import annotations

from typing import Any

import pytest

from alfa.guard.cerber import CerberGuard
from alfa.guard.epistemic_gate import (
    EpistemicGate,
    EpistemicVerdict,
    PassthroughEpistemicGate,
)
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
)
from alfa.plugins.base import PluginSpec


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_decision(
    *,
    response_mode: ResponseMode = ResponseMode.EXECUTE,
    risk: RiskLevel = RiskLevel.SAFE,
    route: Route = Route.EXECUTE_PLUGIN,
    target_plugin: str | None = "script_runner",
) -> CoreDecision:
    return CoreDecision(
        state=SystemState.EXECUTE,
        policy=PolicyDecision(
            intent=Intent.TOOL_EXECUTION,
            risk=risk,
            response_mode=response_mode,
            needs_verification=False,
            recommended_plugin=target_plugin,
            high_impact=False,
            source_conflict=False,
            total_score=0.0,
            filters=[FilterOutcome(name="t", passed=True, detail="ok")],
        ),
        route=RouteDecision(route=route, target_plugin=target_plugin, reason="test"),
        audit_notes=[],
    )


def _plugin(name: str = "script_runner") -> PluginSpec:
    from alfa.shared.schemas import ToolPermission
    return PluginSpec(
        name=name,
        description="test plugin",
        permissions=(ToolPermission.EXECUTE,),
        base_risk=RiskLevel.SAFE,
    )


def _request(*, confirmed: bool = True) -> RequestEnvelope:
    return RequestEnvelope.from_operator_approval(
        text="run backup script",
        session_id="test",
        user_id="operator",
        requested_plugin="script_runner",
    )


# ---------------------------------------------------------------------------
# Stub epistemic gates
# ---------------------------------------------------------------------------

class AlwaysGrantEpistemicGate:
    def evaluate(self, *, request_text: str, plugin_name: str | None,
                 cerber_risk_score: float, context: dict[str, Any] | None = None) -> EpistemicVerdict:
        return EpistemicVerdict.allow(risk_score=cerber_risk_score, reason="stub: always grant")


class AlwaysDenyEpistemicGate:
    def evaluate(self, *, request_text: str, plugin_name: str | None,
                 cerber_risk_score: float, context: dict[str, Any] | None = None) -> EpistemicVerdict:
        return EpistemicVerdict.deny(reason="stub: no evidence basis")


class HighRiskBlockEpistemicGate:
    """Denies if cerber_risk_score >= 0.7 (HIGH or BLOCK)."""
    def evaluate(self, *, request_text: str, plugin_name: str | None,
                 cerber_risk_score: float, context: dict[str, Any] | None = None) -> EpistemicVerdict:
        if cerber_risk_score >= 0.7:
            return EpistemicVerdict.deny(
                risk_score=cerber_risk_score,
                reason=f"Risk score {cerber_risk_score:.2f} exceeds epistemic threshold.",
            )
        return EpistemicVerdict.allow(risk_score=cerber_risk_score, reason="within threshold")


# ---------------------------------------------------------------------------
# PassthroughEpistemicGate
# ---------------------------------------------------------------------------

class TestPassthroughEpistemicGate:
    def test_always_grants(self):
        gate = PassthroughEpistemicGate()
        verdict = gate.evaluate(
            request_text="test", plugin_name="p", cerber_risk_score=0.5
        )
        assert verdict.granted is True

    def test_passes_risk_score_through(self):
        gate = PassthroughEpistemicGate()
        verdict = gate.evaluate(
            request_text="test", plugin_name="p", cerber_risk_score=0.8
        )
        assert verdict.risk_score == 0.8


# ---------------------------------------------------------------------------
# EpistemicVerdict constructors
# ---------------------------------------------------------------------------

class TestEpistemicVerdict:
    def test_allow_defaults(self):
        v = EpistemicVerdict.allow()
        assert v.granted is True
        assert v.risk_score == 0.0

    def test_deny_defaults(self):
        v = EpistemicVerdict.deny(reason="no evidence")
        assert v.granted is False
        assert v.risk_score == 1.0
        assert "evidence" in v.reason

    def test_allow_with_claim_id(self):
        v = EpistemicVerdict.allow(claim_id="abc-123")
        assert v.claim_id == "abc-123"


# ---------------------------------------------------------------------------
# CerberGuard default (no epistemic gate) — regression
# ---------------------------------------------------------------------------

class TestCerberGuardDefaultPassthrough:
    def setup_method(self):
        self.guard = CerberGuard()  # PassthroughEpistemicGate

    def test_approved_exec_path(self):
        result = self.guard.authorize(_request(), _make_decision(), _plugin())
        assert result.allowed is True

    def test_pattern_blocks_refuse(self):
        decision = _make_decision(response_mode=ResponseMode.REFUSE)
        result = self.guard.authorize(_request(), decision, _plugin())
        assert result.allowed is False
        assert result.mode is ResponseMode.REFUSE

    def test_pattern_escalates_high_risk(self):
        decision = _make_decision(risk=RiskLevel.HIGH)
        result = self.guard.authorize(_request(), decision, _plugin())
        assert result.allowed is False
        assert result.requires_confirmation is True


# ---------------------------------------------------------------------------
# Gate 2 — epistemic gate integration
# ---------------------------------------------------------------------------

class TestCerberGuardWithEpistemicGate:
    def test_epistemic_deny_blocks_even_if_pattern_passes(self):
        guard = CerberGuard(epistemic_gate=AlwaysDenyEpistemicGate())
        result = guard.authorize(_request(), _make_decision(), _plugin())
        assert result.allowed is False
        assert "Epistemic gate denied" in result.reason
        assert result.requires_confirmation is True

    def test_both_gates_pass_allows_execution(self):
        guard = CerberGuard(epistemic_gate=AlwaysGrantEpistemicGate())
        result = guard.authorize(_request(), _make_decision(), _plugin())
        assert result.allowed is True
        assert "epistemic gate passed" in result.reason

    def test_pattern_blocks_before_epistemic_is_called(self):
        """Gate 1 refusal should never reach Gate 2."""
        called = []

        class TrackingGate:
            def evaluate(self, *, request_text, plugin_name, cerber_risk_score, context=None):
                called.append(True)
                return EpistemicVerdict.allow()

        guard = CerberGuard(epistemic_gate=TrackingGate())
        decision = _make_decision(response_mode=ResponseMode.REFUSE)
        guard.authorize(_request(), decision, _plugin())
        assert called == [], "Epistemic gate must not be called when pattern gate refuses"

    def test_high_risk_blocked_by_epistemic_threshold(self):
        guard = CerberGuard(epistemic_gate=HighRiskBlockEpistemicGate())
        # SAFE risk (0.0) — epistemic gate allows
        decision_safe = _make_decision(risk=RiskLevel.SAFE)
        result_safe = guard.authorize(_request(), decision_safe, _plugin())
        assert result_safe.allowed is True

    def test_epistemic_deny_produces_escalate_mode(self):
        guard = CerberGuard(epistemic_gate=AlwaysDenyEpistemicGate())
        result = guard.authorize(_request(), _make_decision(), _plugin())
        assert result.mode is ResponseMode.ESCALATE
        assert result.degradation_level == "D2_restricted_mode"

    def test_epistemic_verdict_reason_surfaced_in_guard_reason(self):
        guard = CerberGuard(epistemic_gate=AlwaysDenyEpistemicGate())
        result = guard.authorize(_request(), _make_decision(), _plugin())
        assert "no evidence basis" in result.reason

    def test_public_input_cannot_bypass_epistemic_gate(self):
        """Public caller cannot self-approve through epistemic layer."""
        guard = CerberGuard(epistemic_gate=AlwaysDenyEpistemicGate())
        public_request = RequestEnvelope.from_public_input(
            text="run backup script",
            session_id="test",
            user_id="attacker",
            requested_plugin="script_runner",
            metadata={"confirmed": True},  # attacker tries to inject confirmation
        )
        result = guard.authorize(public_request, _make_decision(), _plugin())
        assert result.allowed is False
