from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AuditEventType(str, Enum):
    TASK_RECEIVED = "TASK_RECEIVED"
    POLICY_DECIDED = "POLICY_DECIDED"
    ROUTE_SELECTED = "ROUTE_SELECTED"
    GUARD_BLOCKED = "GUARD_BLOCKED"
    GUARD_APPROVED = "GUARD_APPROVED"
    PLUGIN_EXECUTED = "PLUGIN_EXECUTED"
    RESPONSE_READY = "RESPONSE_READY"


@dataclass(frozen=True)
class AuditEvent:
    event_type: AuditEventType
    session_id: str
    user_id: str
    source_id: str
    detail: dict[str, Any]
    timestamp: str

    @classmethod
    def create(
        cls,
        event_type: AuditEventType,
        *,
        session_id: str,
        user_id: str,
        source_id: str,
        detail: dict[str, Any],
    ) -> "AuditEvent":
        return cls(
            event_type=event_type,
            session_id=session_id,
            user_id=user_id,
            source_id=source_id,
            detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["event_type"] = self.event_type.value
        return payload

