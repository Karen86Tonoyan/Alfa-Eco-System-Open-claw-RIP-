from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.guard.lasuch import (  # noqa: E402
    QuarantineState,
    SourceType,
    ThreatPacket,
    ThreatPacketValidationError,
    compute_source_hash,
    load_threat_packet_schema,
    validate_packet,
    validate_packet_dict,
)


def test_threat_packet_roundtrip_and_validation_passes():
    packet = ThreatPacket(
        threat_id="f2ae35cf-bb13-4b12-9f63-cf0bdb7ff4c3",
        pattern_type="PROMPT_INJECTION",
        severity=8,
        confidence=0.92,
        matched_text="ignore previous instructions",
        normalized_text="ignore previous instructions",
        source_type=SourceType.PROMPT,
        language_hint="markdown",
        span_start=17,
        span_end=45,
        quarantine_state=QuarantineState.ISOLATED,
        evidence_refs=["brain://evidence/01"],
        source_hash=compute_source_hash("prefix ignore previous instructions suffix"),
        observed_at=datetime(2026, 5, 20, 3, 45, tzinfo=UTC),
    )

    validate_packet(packet)
    roundtrip = validate_packet_dict(packet.to_dict())

    assert roundtrip == packet


def test_threat_packet_schema_declares_frozen_contract_keys():
    schema = load_threat_packet_schema()

    assert schema["title"] == "ThreatPacket"
    assert schema["additionalProperties"] is False
    assert "source_type" in schema["required"]
    assert "quarantine_state" in schema["required"]
    assert "observed_at" in schema["required"]


def test_invalid_threat_packet_is_rejected():
    payload = {
        "threat_id": "not-a-uuid",
        "pattern_type": "badCase",
        "severity": 11,
        "confidence": 1.2,
        "matched_text": " ",
        "normalized_text": "",
        "source_type": "prompt",
        "language_hint": " ",
        "span_start": 20,
        "span_end": 5,
        "quarantine_state": "ISOLATED",
        "evidence_refs": ["brain://ok", ""],
        "source_hash": "abc123",
        "observed_at": datetime.now(tz=UTC).isoformat(),
    }

    with pytest.raises(ThreatPacketValidationError) as exc:
        validate_packet_dict(payload)

    message = str(exc.value)
    assert "threat_id must be a valid UUID" in message
    assert "pattern_type must be uppercase snake case" in message
    assert "severity must be in range 1..10" in message
