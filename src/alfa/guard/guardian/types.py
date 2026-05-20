from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class ClaimStatus(StrEnum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    claim_id: str
    source_hash: str
    category: str
    risk_score: float
    confidence_score: float
    severity_score: float
    evidence_refs: list[str]
    packet_ids: list[str]
    observed_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceVerdict:
    status: ClaimStatus
    claim_id: str
    risk_score: float
    confidence_score: float
    accumulated_entries: int
    reason: str
    evidence_refs: list[str]
    decided_at: datetime
    audit_trail: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "claim_id": self.claim_id,
            "risk_score": self.risk_score,
            "confidence_score": self.confidence_score,
            "accumulated_entries": self.accumulated_entries,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "decided_at": self.decided_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "audit_trail": [dict(item) for item in self.audit_trail],
        }


@dataclass(frozen=True, slots=True)
class EvidenceGateConfig:
    allow_threshold: float = 0.35
    hold_threshold: float = 0.65
    deny_threshold: float = 0.85
    confidence_boost_per_repeat: float = 0.08
    confidence_decay_seconds: int = 3600

    def confidence_decay_window(self) -> timedelta:
        return timedelta(seconds=self.confidence_decay_seconds)
