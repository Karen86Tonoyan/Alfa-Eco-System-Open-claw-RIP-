from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from alfa.shared.events import AuditEvent, AuditEventType


@dataclass
class MemoryLayer:
    """Separated operational memory stores."""

    session_memory: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_memory: dict[str, dict[str, Any]] = field(default_factory=dict)
    system_memory: dict[str, Any] = field(default_factory=dict)
    tool_cache: dict[str, Any] = field(default_factory=dict)
    audit_log: list[AuditEvent] = field(default_factory=list)

    def remember_session(self, session_id: str, key: str, value: Any) -> None:
        self.session_memory.setdefault(session_id, {})[key] = value

    def remember_user(self, user_id: str, key: str, value: Any) -> None:
        self.user_memory.setdefault(user_id, {})[key] = value

    def set_system_value(self, key: str, value: Any) -> None:
        self.system_memory[key] = value

    def get_session_value(self, session_id: str, key: str, default: Any = None) -> Any:
        return self.session_memory.get(session_id, {}).get(key, default)

    def get_user_value(self, user_id: str, key: str, default: Any = None) -> Any:
        return self.user_memory.get(user_id, {}).get(key, default)

    def cache_tool_result(self, cache_key: str, value: Any) -> None:
        self.tool_cache[cache_key] = value

    def get_tool_result(self, cache_key: str) -> Any:
        return self.tool_cache.get(cache_key)

    def append_audit(
        self,
        event_type: AuditEventType,
        *,
        session_id: str,
        user_id: str,
        source_id: str,
        detail: dict[str, Any],
    ) -> AuditEvent:
        event = AuditEvent.create(
            event_type,
            session_id=session_id,
            user_id=user_id,
            source_id=source_id,
            detail=detail,
        )
        self.audit_log.append(event)
        return event
