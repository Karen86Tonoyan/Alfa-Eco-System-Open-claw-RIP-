from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterable

from ..types import ThreatPacket

_CATEGORY_MAP = {
    "SQL_INJECTION": "threat.sql_injection",
    "PROMPT_INJECTION": "threat.prompt_injection",
    "REP": "threat.role_escalation",
    "FMI": "threat.false_memory_injection",
    "UNICODE_OBFUSCATION": "threat.unicode_obfuscation",
}


@dataclass(frozen=True, slots=True)
class GuardianClaimInput:
    claim_id: str
    claim_category: str
    risk_score: float
    summary: str
    evidence_refs: list[str]
    source_hash: str
    packet_ids: list[str]
    packet_types: list[str]
    packet_count: int
    max_severity: int
    max_confidence: float
    quarantine_required: bool
    observed_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_category": self.claim_category,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "source_hash": self.source_hash,
            "packet_ids": list(self.packet_ids),
            "packet_types": list(self.packet_types),
            "packet_count": self.packet_count,
            "max_severity": self.max_severity,
            "max_confidence": self.max_confidence,
            "quarantine_required": self.quarantine_required,
            "observed_at": self.observed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "metadata": dict(self.metadata),
        }


class LasuchGuardianAdapter:
    def to_guardian_claim(self, packets: Iterable[ThreatPacket]) -> GuardianClaimInput:
        packet_list = list(packets)
        if not packet_list:
            raise ValueError("LasuchGuardianAdapter requires at least one ThreatPacket")

        primary = self._select_primary(packet_list)
        evidence_refs = sorted({ref for packet in packet_list for ref in packet.evidence_refs})
        packet_types = sorted({packet.pattern_type for packet in packet_list})
        max_severity = max(packet.severity for packet in packet_list)
        max_confidence = max(packet.confidence for packet in packet_list)
        risk_score = self._risk_score(packet_list)

        return GuardianClaimInput(
            claim_id=primary.threat_id,
            claim_category=_CATEGORY_MAP.get(primary.pattern_type, "threat.unknown"),
            risk_score=risk_score,
            summary=self._build_summary(packet_list, primary, risk_score),
            evidence_refs=evidence_refs,
            source_hash=primary.source_hash,
            packet_ids=[packet.threat_id for packet in packet_list],
            packet_types=packet_types,
            packet_count=len(packet_list),
            max_severity=max_severity,
            max_confidence=max_confidence,
            quarantine_required=True,
            observed_at=min(packet.observed_at for packet in packet_list),
            metadata={
                "source_type": primary.source_type.value,
                "language_hint": primary.language_hint,
                "quarantine_states": sorted({packet.quarantine_state.value for packet in packet_list}),
            },
        )

    def _select_primary(self, packets: list[ThreatPacket]) -> ThreatPacket:
        return sorted(
            packets,
            key=lambda packet: (-packet.severity, -packet.confidence, packet.observed_at.timestamp()),
        )[0]

    def _risk_score(self, packets: list[ThreatPacket]) -> float:
        max_severity = max(packet.severity for packet in packets) / 10.0
        max_confidence = max(packet.confidence for packet in packets)
        multiplicity = min(1.0, len(packets) / 5.0)
        score = (0.5 * max_severity) + (0.35 * max_confidence) + (0.15 * multiplicity)
        return round(min(1.0, score), 3)

    def _build_summary(
        self,
        packets: list[ThreatPacket],
        primary: ThreatPacket,
        risk_score: float,
    ) -> str:
        if len(packets) == 1:
            return (
                f"Lasuch detected {primary.pattern_type} "
                f"(severity={primary.severity}, confidence={primary.confidence:.3f}, risk={risk_score:.3f})."
            )

        packet_types = ", ".join(sorted({packet.pattern_type for packet in packets}))
        return (
            f"Lasuch detected {len(packets)} threats across {packet_types}; "
            f"primary={primary.pattern_type}, max_severity={max(packet.severity for packet in packets)}, "
            f"max_confidence={max(packet.confidence for packet in packets):.3f}, risk={risk_score:.3f}."
        )
