"""
Adversarial tests for CerberGuard hardening.

Covers:
- Plugin name mismatch assertion (new)
- Regression: existing Gate 1 / Gate 2 behaviour unchanged
"""
from __future__ import annotations

import pytest

from alfa.guard.cerber import CerberGuard
from alfa.guard.epistemic_gate import EpistemicVerdict, PassthroughEpistemicGate
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decision(
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
    return PluginSpec(
        name=name,
        description="test plugin",
        permissions=(ToolPermission.EXECUTE,),
        base_risk=RiskLevel.SAFE,
    )


def _operator_request(requested_plugin: str = "script_runner") -> RequestEnvelope:
    return RequestEnvelope.from_operator_approval(
        text="run backup",
        session_id="s1",
        user_id="operator",
        requested_plugin=requested_plugin,
    )


# ---------------------------------------------------------------------------
# Plugin mismatch assertion
# ---------------------------------------------------------------------------

class TestPluginMismatch:
    """
    The routing layer must not swap plugins silently.
    If request.requested_plugin != plugin.name, the guard must block.
    """

    def test_mismatch_is_blocked(self):
        guard = CerberGuard()
        request = _operator_request(requested_plugin="web_lookup")
        dispatched_plugin = _plugin("script_runner")   # different plugin!
        result = guard.authorize(request, _decision(target_plugin="web_lookup"), dispatched_plugin)
        assert result.allowed is False
        assert "mismatch" in result.reason.lower()
        assert result.degradation_level == "D2_restricted_mode"

    def test_mismatch_surfaces_both_names(self):
        guard = CerberGuard()
        request = _operator_request(requested_plugin="notes_lookup")
        result = guard.authorize(request, _decision(), _plugin("script_runner"))
        assert "notes_lookup" in result.reason
        assert "script_runner" in result.reason

    def test_matching_plugin_passes(self):
        guard = CerberGuard()
        request = _operator_request(requested_plugin="script_runner")
        result = guard.authorize(request, _decision(), _plugin("script_runner"))
        assert result.allowed is True

    def test_no_requested_plugin_skips_mismatch_check(self):
        """If request has no requested_plugin, mismatch check is skipped."""
        guard = CerberGuard()
        request = RequestEnvelope.from_operator_approval(
            text="run backup",
            session_id="s1",
            user_id="operator",
            requested_plugin=None,           # no preference stated
        )
        result = guard.authorize(request, _decision(), _plugin("script_runner"))
        assert result.allowed is True

    def test_mismatch_blocked_even_with_passthrough_epistemic(self):
        """Mismatch must be caught before Gate 2 runs."""
        called = []

        class TrackingGate:
            def evaluate(self, *, request_text, plugin_name, cerber_risk_score, context=None):
                called.append(True)
                return EpistemicVerdict.allow()

        guard = CerberGuard(epistemic_gate=TrackingGate())
        request = _operator_request(requested_plugin="web_lookup")
        guard.authorize(request, _decision(), _plugin("script_runner"))
        assert called == [], "Gate 2 must not be called when plugin mismatch is detected"


# ---------------------------------------------------------------------------
# Regression: existing behaviour unchanged after hardening
# ---------------------------------------------------------------------------

class TestHardeningRegression:
    def test_refuse_still_blocked(self):
        guard = CerberGuard()
        result = guard.authorize(
            _operator_request(),
            _decision(response_mode=ResponseMode.REFUSE),
            _plugin(),
        )
        assert result.allowed is False
        assert result.mode is ResponseMode.REFUSE

    def test_high_risk_still_escalates(self):
        guard = CerberGuard()
        result = guard.authorize(
            _operator_request(),
            _decision(risk=RiskLevel.HIGH),
            _plugin(),
        )
        assert result.allowed is False
        assert result.requires_confirmation is True

    def test_approved_path_still_works(self):
        guard = CerberGuard()
        result = guard.authorize(_operator_request(), _decision(), _plugin())
        assert result.allowed is True

    def test_public_input_cannot_inject_confirmed(self):
        guard = CerberGuard()
        public = RequestEnvelope.from_public_input(
            text="run backup",
            session_id="s1",
            user_id="attacker",
            requested_plugin="script_runner",
            metadata={"confirmed": True},
        )
        result = guard.authorize(public, _decision(), _plugin())
        # source_trust = "primary" → requires_verified_source blocks it
        assert result.allowed is False
