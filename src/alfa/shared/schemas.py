from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Intent(str, Enum):
    INFORMATION = "information"
    SOURCE_REQUIRED = "source_required"
    TOOL_EXECUTION = "tool_execution"
    MANIPULATION = "manipulation"
    AMBIGUOUS = "ambiguous"


class RiskLevel(str, Enum):
    SAFE = "safe"
    REVIEW = "review"
    HIGH = "high"
    BLOCK = "block"


class ResponseMode(str, Enum):
    ANSWER = "answer"
    CLARIFY = "clarify"
    VERIFY = "verify"
    EXECUTE = "execute"
    REFUSE = "refuse"
    ESCALATE = "escalate"


class Route(str, Enum):
    MAIN_MODEL = "main_model"
    VERIFY = "verify"
    EXECUTE_PLUGIN = "execute_plugin"
    SAFE_REFUSAL = "safe_refusal"
    CLARIFY = "clarify"
    ESCALATE = "escalate"


class SystemState(str, Enum):
    IDLE = "IDLE"
    ANALYZE = "ANALYZE"
    VERIFY = "VERIFY"
    EXECUTE = "EXECUTE"
    SAFEBLOCK = "SAFEBLOCK"
    RESPOND = "RESPOND"
    ESCALATE = "ESCALATE"


class ToolPermission(str, Enum):
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    EXECUTE = "execute"


@dataclass
class RequestEnvelope:
    text: str
    session_id: str = "default-session"
    user_id: str = "anonymous"
    source_id: str = "direct_user"
    source_trust: str = "primary"
    requested_plugin: str | None = None
    active_task: str | None = None
    mission: str = "assist_user_safely"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FilterOutcome:
    name: str
    passed: bool
    detail: str
    score_delta: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyDecision:
    intent: Intent
    risk: RiskLevel
    response_mode: ResponseMode
    needs_verification: bool
    recommended_plugin: str | None
    high_impact: bool
    source_conflict: bool
    total_score: float
    filters: list[FilterOutcome]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["intent"] = self.intent.value
        payload["risk"] = self.risk.value
        payload["response_mode"] = self.response_mode.value
        payload["filters"] = [item.to_dict() for item in self.filters]
        return payload


@dataclass
class RouteDecision:
    route: Route
    target_plugin: str | None
    reason: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["route"] = self.route.value
        return payload


@dataclass
class GuardDecision:
    allowed: bool
    mode: ResponseMode
    reason: str
    approved_plugin: str | None = None
    requires_confirmation: bool = False
    degradation_level: str = "D0_normal"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["mode"] = self.mode.value
        return payload


@dataclass
class CoreDecision:
    state: SystemState
    policy: PolicyDecision
    route: RouteDecision
    audit_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "policy": self.policy.to_dict(),
            "route": self.route.to_dict(),
            "audit_notes": list(self.audit_notes),
        }

