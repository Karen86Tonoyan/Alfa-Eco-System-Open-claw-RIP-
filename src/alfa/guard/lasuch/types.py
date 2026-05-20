from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any
from uuid import UUID


class SourceType(StrEnum):
    PROMPT = "prompt"
    CODE = "code"
    TEMPLATE = "template"
    MESSAGE = "message"
    FILE = "file"


class QuarantineState(StrEnum):
    ISOLATED = "ISOLATED"
    ANALYZED = "ANALYZED"
    CONTAINED = "CONTAINED"


def compute_source_hash(source: str) -> str:
    return sha256(source.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ThreatPacket:
    """
    Frozen contract between Lasuch, Guardian, and Cerber.

    The packet must be serializable for logging, graph ingestion, and audit
    trails without any extra enrichment step.
    """

    threat_id: str
    pattern_type: str
    severity: int
    confidence: float
    matched_text: str
    normalized_text: str
    source_type: SourceType
    language_hint: str | None
    span_start: int | None
    span_end: int | None
    quarantine_state: QuarantineState
    evidence_refs: list[str]
    source_hash: str
    observed_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "matched_text": self.matched_text,
            "normalized_text": self.normalized_text,
            "source_type": self.source_type.value,
            "language_hint": self.language_hint,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "quarantine_state": self.quarantine_state.value,
            "evidence_refs": list(self.evidence_refs),
            "source_hash": self.source_hash,
            "observed_at": self.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ThreatPacket":
        observed_at = payload["observed_at"]
        if isinstance(observed_at, str):
            observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))

        source_type = payload["source_type"]
        if not isinstance(source_type, SourceType):
            source_type = SourceType(source_type)

        quarantine_state = payload["quarantine_state"]
        if not isinstance(quarantine_state, QuarantineState):
            quarantine_state = QuarantineState(quarantine_state)

        return cls(
            threat_id=payload["threat_id"],
            pattern_type=payload["pattern_type"],
            severity=int(payload["severity"]),
            confidence=float(payload["confidence"]),
            matched_text=payload["matched_text"],
            normalized_text=payload["normalized_text"],
            source_type=source_type,
            language_hint=payload.get("language_hint"),
            span_start=payload.get("span_start"),
            span_end=payload.get("span_end"),
            quarantine_state=quarantine_state,
            evidence_refs=list(payload.get("evidence_refs", [])),
            source_hash=payload["source_hash"],
            observed_at=observed_at,
        )

    def uuid(self) -> UUID:
        return UUID(self.threat_id)
