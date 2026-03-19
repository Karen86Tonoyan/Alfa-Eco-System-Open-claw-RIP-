from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from alfa.shared.schemas import RiskLevel, ToolPermission


@dataclass(frozen=True)
class PluginSpec:
    name: str
    description: str
    permissions: tuple[ToolPermission, ...]
    base_risk: RiskLevel
    requires_confirmation: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["permissions"] = [item.value for item in self.permissions]
        payload["base_risk"] = self.base_risk.value
        return payload


class BasePlugin(Protocol):
    spec: PluginSpec

    def execute(self, text: str, *, session_id: str, user_id: str, memory: Any) -> dict[str, Any]:
        ...

