from __future__ import annotations

from alfa.guard.epistemic_gate import EpistemicGate, PassthroughEpistemicGate
from alfa.plugins.base import PluginSpec
from alfa.shared.policies import DEFAULT_PLUGIN_POLICIES
from alfa.shared.schemas import (
    CoreDecision,
    GuardDecision,
    RequestEnvelope,
    ResponseMode,
    RiskLevel,
)


RISK_ORDER = {
    RiskLevel.SAFE: 0,
    RiskLevel.REVIEW: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.BLOCK: 3,
}

_RISK_FLOAT = {
    RiskLevel.SAFE:   0.0,
    RiskLevel.REVIEW: 0.35,
    RiskLevel.HIGH:   0.7,
    RiskLevel.BLOCK:  1.0,
}


class CerberGuard:
    """
    Cerber two-gate execution guard.

    Gate 1 — pattern layer (this class): intent, risk level, plugin policy,
              trust origin, confirmation flag.
    Gate 2 — epistemic layer (injected EpistemicGate): claim evidence basis,
              corroboration, domain policy.  Defaults to PassthroughEpistemicGate
              when no backend is wired in.

    Usage with epistemic backend::

        from alfa.guard.cerber import CerberGuard
        guard = CerberGuard(epistemic_gate=AlfaEOSAdapter())

    Without backend (public proof mode)::

        guard = CerberGuard()   # passthrough — Gate 2 always grants
    """

    def __init__(self, epistemic_gate: EpistemicGate | None = None) -> None:
        self._epistemic_gate: EpistemicGate = epistemic_gate or PassthroughEpistemicGate()

    def authorize(
        self,
        request: RequestEnvelope,
        decision: CoreDecision,
        plugin: PluginSpec | None,
    ) -> GuardDecision:
        if decision.policy.response_mode is ResponseMode.REFUSE:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.REFUSE,
                reason="Blocked by core risk policy.",
                degradation_level="D3_safe_freeze",
            )

        if decision.route.route.value in {"clarify", "main_model"}:
            return GuardDecision(
                allowed=True,
                mode=decision.policy.response_mode,
                reason="No execution permission needed.",
            )

        if decision.policy.response_mode is ResponseMode.ESCALATE:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason="Operator review required before execution.",
                approved_plugin=plugin.name if plugin else None,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        if plugin is None:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason="Requested plugin is missing.",
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        # Verify the dispatched plugin matches what the request actually asked for.
        # Mismatch means the routing layer substituted a different plugin — block it.
        if (
            request.requested_plugin is not None
            and request.requested_plugin != plugin.name
        ):
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=(
                    f"Plugin mismatch: request asked for '{request.requested_plugin}' "
                    f"but guard received '{plugin.name}'."
                ),
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        policy = DEFAULT_PLUGIN_POLICIES.get(plugin.name)
        if policy is None:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=f"Plugin '{plugin.name}' has no public guard policy.",
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        if RISK_ORDER[decision.policy.risk] > RISK_ORDER[policy.max_auto_risk]:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=f"Risk too high for plugin '{plugin.name}'.",
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        if policy.requires_verified_source and request.source_trust not in {"verified", "operator"}:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=f"Plugin '{plugin.name}' requires verified source.",
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        confirmed = bool(request.metadata.get("confirmed", False))
        if policy.requires_confirmation and not confirmed:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=f"Plugin '{plugin.name}' requires explicit confirmation.",
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        # Gate 2 — epistemic layer
        cerber_risk_float = _RISK_FLOAT[decision.policy.risk]
        verdict = self._epistemic_gate.evaluate(
            request_text=request.text,
            plugin_name=plugin.name,
            cerber_risk_score=cerber_risk_float,
            context={
                "session_id": request.session_id,
                "user_id": request.user_id,
                "source_trust": request.source_trust,
                "mission": request.mission,
            },
        )
        if not verdict.granted:
            return GuardDecision(
                allowed=False,
                mode=ResponseMode.ESCALATE,
                reason=f"Epistemic gate denied: {verdict.reason}",
                approved_plugin=plugin.name,
                requires_confirmation=True,
                degradation_level="D2_restricted_mode",
            )

        return GuardDecision(
            allowed=True,
            mode=decision.policy.response_mode,
            reason="Guard approved — pattern gate + epistemic gate passed.",
            approved_plugin=plugin.name,
        )

