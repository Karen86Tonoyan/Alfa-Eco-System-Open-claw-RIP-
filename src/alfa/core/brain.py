from __future__ import annotations

from alfa.shared.schemas import CoreDecision, RequestEnvelope

from .policy import PolicyEngine
from .router import OperationalRouter
from .state_machine import StateMachine


class ALFACoreBrain:
    """Brain thinks: policy -> route -> state."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        router: OperationalRouter | None = None,
        state_machine: StateMachine | None = None,
    ):
        self.policy = policy or PolicyEngine()
        self.router = router or OperationalRouter()
        self.state_machine = state_machine or StateMachine()

    def decide(self, request: RequestEnvelope) -> CoreDecision:
        audit_notes = [
            "state=IDLE",
            "transition=IDLE->ANALYZE",
            f"source_id={request.source_id}",
            f"source_trust={request.source_trust}",
        ]
        policy = self.policy.analyze(request)
        audit_notes.extend(
            [
                f"intent={policy.intent.value}",
                f"risk={policy.risk.value}",
                f"verification={policy.needs_verification}",
                f"recommended_plugin={policy.recommended_plugin or 'none'}",
            ]
        )
        route = self.router.route(policy)
        audit_notes.append(f"route={route.route.value}")
        state = self.state_machine.resolve(route.route)
        audit_notes.append(f"transition=ANALYZE->{state.value}")
        return CoreDecision(state=state, policy=policy, route=route, audit_notes=audit_notes)

