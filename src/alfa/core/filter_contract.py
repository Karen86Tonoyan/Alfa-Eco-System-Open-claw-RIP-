from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any
from uuid import uuid4


class FilterAction(IntEnum):
    UNSPECIFIED = 0
    PROCEED = 1
    CLARIFY = 2
    ESCALATE = 3
    BLOCK = 4



def _normalize_timestamp(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
    datetime.fromisoformat(normalized)
    return normalized



def _require_non_empty(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} cannot be empty")
    return value.strip()


@dataclass(slots=True)
class FilterRequestModel:
    query: str
    user_id: str
    session_id: str
    timestamp: str
    metadata: dict[str, str] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        self.query = _require_non_empty(self.query, "query")
        self.user_id = _require_non_empty(self.user_id, "user_id")
        self.session_id = _require_non_empty(self.session_id, "session_id")
        self.timestamp = _normalize_timestamp(self.timestamp)
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dictionary")
        self.metadata = {str(k): str(v) for k, v in self.metadata.items()}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FilterRequestModel":
        return cls(
            query=payload["query"],
            user_id=payload["user_id"],
            session_id=payload["session_id"],
            timestamp=payload["timestamp"],
            metadata=payload.get("metadata", {}),
            correlation_id=payload.get("correlation_id", str(uuid4())),
        )


@dataclass(slots=True)
class FilterResult:
    filter_id: str
    risk_score: float
    confidence: float
    flags: list[str] = field(default_factory=list)
    action: FilterAction = FilterAction.UNSPECIFIED
    context: dict[str, str] = field(default_factory=dict)
    timed_out: bool = False

    def __post_init__(self) -> None:
        self.filter_id = _require_non_empty(self.filter_id, "filter_id")
        self.risk_score = float(self.risk_score)
        self.confidence = float(self.confidence)
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        self.flags = [str(flag) for flag in self.flags]
        self.context = {str(k): str(v) for k, v in self.context.items()}


@dataclass(slots=True)
class DecisionResult:
    action: FilterAction
    score: float
    confidence: float
    reason: str | None = None
    warning: str | None = None
    message: str | None = None
    filter_results: list[FilterResult] = field(default_factory=list)
    timed_out_filters: list[str] = field(default_factory=list)
    correlation_id: str = field(default_factory=lambda: str(uuid4()))

    def __post_init__(self) -> None:
        self.score = float(self.score)
        self.confidence = float(self.confidence)
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be between 0.0 and 1.0")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
