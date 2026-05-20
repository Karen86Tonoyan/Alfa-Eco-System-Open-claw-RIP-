from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from alfa.guard.lasuch.adapters.guardian_input import GuardianClaimInput

from .types import ClaimStatus, EvidenceEntry, EvidenceGateConfig, EvidenceVerdict


class EvidenceGate:
    def __init__(self, config: EvidenceGateConfig | None = None) -> None:
        self._config = config or EvidenceGateConfig()
        self._entries_by_source: dict[str, list[EvidenceEntry]] = {}
        self._audit_log: list[dict[str, object]] = []

    def consume(self, claim: GuardianClaimInput) -> EvidenceVerdict:
        observed_at = claim.observed_at.astimezone(UTC)
        entry = EvidenceEntry(
            claim_id=claim.claim_id,
            source_hash=claim.source_hash,
            category=claim.claim_category,
            risk_score=claim.risk_score,
            confidence_score=claim.max_confidence,
            severity_score=round(claim.max_severity / 10.0, 3),
            evidence_refs=list(claim.evidence_refs),
            packet_ids=list(claim.packet_ids),
            observed_at=observed_at,
            metadata=dict(claim.metadata),
        )

        history = self._entries_by_source.setdefault(claim.source_hash, [])
        history.append(entry)
        relevant_entries = self._recent_entries(history, observed_at)
        accumulated_entries = len(relevant_entries)

        confidence_score = self._accumulated_confidence(relevant_entries)
        effective_risk = self._effective_risk(entry, accumulated_entries)
        status, reason = self._decide(entry, effective_risk, confidence_score, accumulated_entries)

        audit_event = {
            "ts": observed_at.isoformat().replace("+00:00", "Z"),
            "claim_id": claim.claim_id,
            "source_hash": claim.source_hash,
            "category": claim.claim_category,
            "status": status.value,
            "effective_risk": effective_risk,
            "confidence_score": confidence_score,
            "accumulated_entries": accumulated_entries,
            "reason": reason,
        }
        self._audit_log.append(audit_event)

        return EvidenceVerdict(
            status=status,
            claim_id=claim.claim_id,
            risk_score=effective_risk,
            confidence_score=confidence_score,
            accumulated_entries=accumulated_entries,
            reason=reason,
            evidence_refs=list(claim.evidence_refs),
            decided_at=observed_at,
            audit_trail=[dict(item) for item in self._audit_log if item["source_hash"] == claim.source_hash],
        )

    def get_entries(self, source_hash: str) -> list[EvidenceEntry]:
        return list(self._entries_by_source.get(source_hash, []))

    def get_audit_log(self) -> list[dict[str, object]]:
        return [dict(item) for item in self._audit_log]

    def _recent_entries(self, entries: list[EvidenceEntry], now: datetime) -> list[EvidenceEntry]:
        window = self._config.confidence_decay_window()
        return [entry for entry in entries if now - entry.observed_at <= window]

    def _accumulated_confidence(self, entries: list[EvidenceEntry]) -> float:
        max_confidence = max(entry.confidence_score for entry in entries)
        boost = max(0, len(entries) - 1) * self._config.confidence_boost_per_repeat
        return round(min(1.0, max_confidence + boost), 3)

    def _effective_risk(self, entry: EvidenceEntry, accumulated_entries: int) -> float:
        repeat_boost = min(0.2, max(0, accumulated_entries - 1) * 0.05)
        severity_weight = 0.55 * entry.severity_score
        confidence_weight = 0.35 * entry.confidence_score
        repeat_weight = 0.10 * repeat_boost / 0.2 if repeat_boost else 0.0
        raw = severity_weight + confidence_weight + repeat_weight
        return round(min(1.0, max(entry.risk_score, raw)), 3)

    def _decide(
        self,
        entry: EvidenceEntry,
        effective_risk: float,
        confidence_score: float,
        accumulated_entries: int,
    ) -> tuple[ClaimStatus, str]:
        category = entry.category
        if category in {"threat.sql_injection", "threat.prompt_injection"} and effective_risk >= self._config.hold_threshold:
            if confidence_score >= 0.9 or accumulated_entries >= 2:
                return ClaimStatus.DENY, f"{category} reached deny threshold with corroborated evidence."
            return ClaimStatus.HOLD, f"{category} requires human review due to elevated risk."

        if effective_risk >= self._config.deny_threshold:
            return ClaimStatus.DENY, "Accumulated evidence crossed deterministic deny threshold."
        if effective_risk >= self._config.hold_threshold:
            return ClaimStatus.HOLD, "Accumulated evidence requires containment and review."
        if effective_risk <= self._config.allow_threshold:
            return ClaimStatus.ALLOW, "Evidence risk remains below allow threshold."
        return ClaimStatus.HOLD, "Evidence is inconclusive; hold until more context arrives."
