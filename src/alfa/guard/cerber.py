from __future__ import annotations

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


class CerberGuard:
    """
    Public preview of the Cerber execution gate.

    The production enforcement core is stricter and private. This layer
    exposes the public control idea: the model proposes, Cerber approves or blocks.
    """

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

        return GuardDecision(
            allowed=True,
            mode=decision.policy.response_mode,
            reason="Guard approved request within public preview policy.",
            approved_plugin=plugin.name,
        )

