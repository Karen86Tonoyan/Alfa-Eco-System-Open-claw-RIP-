from __future__ import annotations

from alfa.shared.schemas import PolicyDecision, ResponseMode, Route, RouteDecision


class OperationalRouter:
    """Deterministic routing layer over policy output."""

    def route(self, policy: PolicyDecision) -> RouteDecision:
        if policy.response_mode is ResponseMode.CLARIFY:
            return RouteDecision(Route.CLARIFY, None, "Need clarification.")
        if policy.response_mode is ResponseMode.REFUSE:
            return RouteDecision(Route.SAFE_REFUSAL, None, "Blocked by policy.")
        if policy.response_mode is ResponseMode.ESCALATE:
            return RouteDecision(
                Route.ESCALATE,
                policy.recommended_plugin,
                "Critical review required.",
            )
        if policy.response_mode is ResponseMode.VERIFY:
            return RouteDecision(
                Route.VERIFY,
                policy.recommended_plugin or "web_lookup",
                "Verification workflow selected.",
            )
        if policy.response_mode is ResponseMode.EXECUTE:
            return RouteDecision(
                Route.EXECUTE_PLUGIN,
                policy.recommended_plugin,
                "Plugin execution workflow selected.",
            )
        return RouteDecision(Route.MAIN_MODEL, None, "Main model answer path.")

