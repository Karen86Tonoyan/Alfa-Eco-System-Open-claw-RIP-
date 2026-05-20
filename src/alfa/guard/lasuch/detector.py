from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Iterable
from uuid import uuid4

from .patterns import InjectionPattern, get_patterns
from .threat_validator import validate_packet
from .types import QuarantineState, SourceType, ThreatPacket, compute_source_hash

_WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class DetectionSummary:
    total_matches: int
    max_severity: int
    max_confidence: float
    pattern_types: tuple[str, ...]


class InjectionDetector:
    def __init__(self, patterns: Iterable[InjectionPattern] | None = None):
        self._patterns = tuple(patterns or get_patterns())

    def detect(
        self,
        text: str,
        *,
        source_type: SourceType | str,
        language_hint: str | None = None,
    ) -> list[ThreatPacket]:
        if isinstance(source_type, str):
            source_type = SourceType(source_type)

        source_hash = compute_source_hash(text)
        packets: list[ThreatPacket] = []

        for pattern in self._patterns:
            if not pattern.applies_to(source_type=source_type, language_hint=language_hint):
                continue

            for match in pattern.regex.finditer(text):
                packet = ThreatPacket(
                    threat_id=str(uuid4()),
                    pattern_type=pattern.pattern_type,
                    severity=pattern.severity_base,
                    confidence=self._score_confidence(pattern, match.group(0)),
                    matched_text=match.group(0),
                    normalized_text=self._normalize(match.group(0)),
                    source_type=source_type,
                    language_hint=language_hint,
                    span_start=match.start(),
                    span_end=match.end(),
                    quarantine_state=QuarantineState.ISOLATED,
                    evidence_refs=self._build_evidence_refs(pattern, source_hash),
                    source_hash=source_hash,
                    observed_at=datetime.now(tz=UTC),
                )
                packets.append(validate_packet(packet))

        return self._deduplicate(packets)

    def summarize(self, packets: Iterable[ThreatPacket]) -> DetectionSummary:
        packet_list = list(packets)
        if not packet_list:
            return DetectionSummary(
                total_matches=0,
                max_severity=0,
                max_confidence=0.0,
                pattern_types=(),
            )

        return DetectionSummary(
            total_matches=len(packet_list),
            max_severity=max(packet.severity for packet in packet_list),
            max_confidence=max(packet.confidence for packet in packet_list),
            pattern_types=tuple(sorted({packet.pattern_type for packet in packet_list})),
        )

    def _normalize(self, text: str) -> str:
        normalized = unicodedata.normalize("NFKC", text)
        normalized = _WHITESPACE.sub(" ", normalized).strip().lower()
        return normalized

    def _score_confidence(self, pattern: InjectionPattern, matched_text: str) -> float:
        score = pattern.confidence_base
        lowered = matched_text.lower()

        if "\n" in matched_text or "\r" in matched_text:
            score += 0.02
        if any(token in lowered for token in ("admin", "operator", "system prompt", "union", "sleep(", "verified")):
            score += 0.03
        if len(matched_text) > 80:
            score -= 0.02

        return max(0.0, min(1.0, round(score, 3)))

    def _build_evidence_refs(self, pattern: InjectionPattern, source_hash: str) -> list[str]:
        return [
            f"lasuch://pattern/{pattern.name}",
            f"lasuch://source/{source_hash}",
        ]

    def _deduplicate(self, packets: list[ThreatPacket]) -> list[ThreatPacket]:
        seen: set[tuple[str, int | None, int | None, str]] = set()
        unique: list[ThreatPacket] = []

        for packet in packets:
            key = (
                packet.pattern_type,
                packet.span_start,
                packet.span_end,
                packet.normalized_text,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(packet)

        unique.sort(key=lambda packet: (-packet.severity, -packet.confidence, packet.span_start or 0))
        return unique
