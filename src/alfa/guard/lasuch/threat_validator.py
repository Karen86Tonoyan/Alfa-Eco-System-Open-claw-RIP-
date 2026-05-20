from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from uuid import UUID

from .types import QuarantineState, SourceType, ThreatPacket

_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_UPPER_SNAKE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_SCHEMA_PATH = Path(__file__).with_name("threat_packet.json")


@dataclass(frozen=True, slots=True)
class ThreatPacketValidationError(ValueError):
    issues: tuple[str, ...]

    def __str__(self) -> str:
        return "ThreatPacket validation failed: " + "; ".join(self.issues)


def load_threat_packet_schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_packet_dict(payload: Mapping[str, Any]) -> ThreatPacket:
    packet = ThreatPacket.from_dict(dict(payload))
    validate_packet(packet)
    return packet


def validate_packet(packet: ThreatPacket) -> ThreatPacket:
    issues: list[str] = []

    try:
        UUID(packet.threat_id)
    except ValueError:
        issues.append("threat_id must be a valid UUID")

    if not _UPPER_SNAKE.match(packet.pattern_type):
        issues.append("pattern_type must be uppercase snake case")

    if packet.severity < 1 or packet.severity > 10:
        issues.append("severity must be in range 1..10")

    if packet.confidence < 0.0 or packet.confidence > 1.0:
        issues.append("confidence must be in range 0.0..1.0")

    if not packet.matched_text.strip():
        issues.append("matched_text must not be blank")

    if not packet.normalized_text.strip():
        issues.append("normalized_text must not be blank")

    if packet.language_hint is not None and not packet.language_hint.strip():
        issues.append("language_hint must not be empty when provided")

    if (packet.span_start is None) != (packet.span_end is None):
        issues.append("span_start and span_end must be set together")
    elif packet.span_start is not None and packet.span_end is not None:
        if packet.span_start < 0 or packet.span_end < 0:
            issues.append("span positions must be non-negative")
        if packet.span_end < packet.span_start:
            issues.append("span_end must be greater than or equal to span_start")

    if not isinstance(packet.source_type, SourceType):
        issues.append("source_type must be a valid SourceType")

    if not isinstance(packet.quarantine_state, QuarantineState):
        issues.append("quarantine_state must be a valid QuarantineState")

    if any(not ref.strip() for ref in packet.evidence_refs):
        issues.append("evidence_refs must not contain empty values")

    if not _HEX_64.match(packet.source_hash):
        issues.append("source_hash must be a lowercase SHA256 hex digest")

    if not isinstance(packet.observed_at, datetime):
        issues.append("observed_at must be a datetime instance")

    if issues:
        raise ThreatPacketValidationError(tuple(issues))

    return packet
