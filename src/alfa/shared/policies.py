from __future__ import annotations

from dataclasses import dataclass

from .schemas import RiskLevel


@dataclass(frozen=True)
class PluginPolicy:
    max_auto_risk: RiskLevel
    requires_verified_source: bool = False
    requires_confirmation: bool = False
    high_impact: bool = False


DEFAULT_PLUGIN_POLICIES: dict[str, PluginPolicy] = {
    "web_lookup": PluginPolicy(max_auto_risk=RiskLevel.REVIEW),
    "notes_lookup": PluginPolicy(max_auto_risk=RiskLevel.SAFE),
    "script_runner": PluginPolicy(
        max_auto_risk=RiskLevel.REVIEW,
        requires_verified_source=True,
        requires_confirmation=True,
        high_impact=True,
    ),
}
