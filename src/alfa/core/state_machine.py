from __future__ import annotations

from alfa.shared.schemas import Route, SystemState


class StateMachine:
    """Minimal state machine where state changes system behavior."""

    state_map = {
        Route.MAIN_MODEL: SystemState.RESPOND,
        Route.VERIFY: SystemState.VERIFY,
        Route.EXECUTE_PLUGIN: SystemState.EXECUTE,
        Route.SAFE_REFUSAL: SystemState.SAFEBLOCK,
        Route.CLARIFY: SystemState.RESPOND,
        Route.ESCALATE: SystemState.ESCALATE,
    }

    def resolve(self, route: Route) -> SystemState:
        return self.state_map[route]

