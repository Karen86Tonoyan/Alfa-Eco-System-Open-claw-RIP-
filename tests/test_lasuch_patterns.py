from __future__ import annotations

import sys
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.guard.lasuch.detector import InjectionDetector  # noqa: E402
from alfa.guard.lasuch.patterns import get_patterns  # noqa: E402
from alfa.guard.lasuch.types import SourceType  # noqa: E402

from .adversarial_payloads import (  # noqa: E402
    FMI_PAYLOADS,
    NEGATIVE_CASES,
    PROMPT_INJECTION_PAYLOADS,
    REP_PAYLOADS,
    SQL_INJECTION_PAYLOADS,
    UNICODE_OBFUSCATION_PAYLOADS,
)


def _detector() -> InjectionDetector:
    return InjectionDetector(get_patterns())


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sql_injection_payloads_are_detected(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.CODE, language_hint="sql")
    assert any(packet.pattern_type == "SQL_INJECTION" for packet in packets)


@pytest.mark.parametrize("payload", PROMPT_INJECTION_PAYLOADS)
def test_prompt_injection_payloads_are_detected(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.PROMPT, language_hint="markdown")
    assert any(packet.pattern_type == "PROMPT_INJECTION" for packet in packets)


@pytest.mark.parametrize("payload", REP_PAYLOADS)
def test_rep_payloads_are_detected(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.MESSAGE, language_hint="markdown")
    assert any(packet.pattern_type == "REP" for packet in packets)


@pytest.mark.parametrize("payload", FMI_PAYLOADS)
def test_fmi_payloads_are_detected(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.MESSAGE, language_hint="markdown")
    assert any(packet.pattern_type == "FMI" for packet in packets)


@pytest.mark.parametrize("payload", UNICODE_OBFUSCATION_PAYLOADS)
def test_unicode_obfuscation_payloads_are_detected(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.PROMPT, language_hint="markdown")
    assert any(packet.pattern_type == "UNICODE_OBFUSCATION" for packet in packets)


@pytest.mark.parametrize("payload", NEGATIVE_CASES)
def test_negative_cases_do_not_trigger_false_alarms(payload: str):
    packets = _detector().detect(payload, source_type=SourceType.MESSAGE, language_hint="markdown")
    assert packets == []
