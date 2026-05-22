from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern

from .types import SourceType


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True, slots=True)
class InjectionPattern:
    name: str
    pattern_type: str
    regex: Pattern[str]
    severity_base: int
    confidence_base: float
    source_types: tuple[SourceType, ...]
    language_scope: tuple[str, ...] = ()
    description: str = ""

    def applies_to(self, *, source_type: SourceType, language_hint: str | None) -> bool:
        if self.source_types and source_type not in self.source_types:
            return False
        if self.language_scope and language_hint:
            return language_hint.lower() in {item.lower() for item in self.language_scope}
        return not self.language_scope or language_hint is None


PATTERN_REGISTRY: tuple[InjectionPattern, ...] = (
    InjectionPattern(
        name="sql_union_select",
        pattern_type="SQL_INJECTION",
        regex=_compile(r"\bunion\b\s+(?:all\s+)?select\b"),
        severity_base=9,
        confidence_base=0.93,
        source_types=(SourceType.CODE, SourceType.PROMPT, SourceType.FILE, SourceType.MESSAGE),
        language_scope=("sql", "python", "javascript", "typescript", "php"),
        description="Classic UNION-based SQL injection payload.",
    ),
    InjectionPattern(
        name="sql_boolean_tautology",
        pattern_type="SQL_INJECTION",
        regex=_compile(r"(?:'|\"|`)?\s*(?:or|and)\s+1\s*=\s*1\b"),
        severity_base=8,
        confidence_base=0.88,
        source_types=(SourceType.CODE, SourceType.PROMPT, SourceType.FILE, SourceType.MESSAGE),
        language_scope=("sql", "python", "javascript", "typescript", "php"),
        description="Boolean-tautology probe often used in login bypass attempts.",
    ),
    InjectionPattern(
        name="sql_time_delay",
        pattern_type="SQL_INJECTION",
        regex=_compile(r"\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay|pg_sleep\s*\(\s*\d+\s*\))"),
        severity_base=8,
        confidence_base=0.86,
        source_types=(SourceType.CODE, SourceType.PROMPT, SourceType.FILE, SourceType.MESSAGE),
        language_scope=("sql", "python", "javascript", "typescript", "php"),
        description="Time-delay probe for blind SQL injection.",
    ),
    InjectionPattern(
        name="prompt_ignore_override",
        pattern_type="PROMPT_INJECTION",
        regex=_compile(r"\b(?:ignore|disregard|forget)\b.{0,40}\b(?:previous|prior|above)\b.{0,40}\b(?:instruction|prompt|message)s?\b"),
        severity_base=9,
        confidence_base=0.94,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE, SourceType.FILE),
        description="Direct attempt to override prior instructions.",
    ),
    InjectionPattern(
        name="prompt_system_prompt_exfil",
        pattern_type="PROMPT_INJECTION",
        regex=_compile(r"\b(?:reveal|print|show|dump|expose)\b.{0,40}\b(?:system prompt|developer message|hidden instructions?)\b"),
        severity_base=9,
        confidence_base=0.91,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE, SourceType.FILE),
        description="Extraction attempt targeting hidden instructions or system prompt.",
    ),
    InjectionPattern(
        name="rep_role_escalation",
        pattern_type="REP",
        regex=_compile(r"\b(?:you are now|act as|assume you are|treat me as)\b.{0,40}\b(?:admin(?:istrator)?|operator|root|system)\b"),
        severity_base=8,
        confidence_base=0.87,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE),
        description="Role or authority hijack attempt.",
    ),
    InjectionPattern(
        name="rep_gate_bypass",
        pattern_type="REP",
        regex=_compile(r"\b(?:bypass|disable|skip|override)\b.{0,40}\b(?:approval|permission|policy|gate|guardrail)s?\b"),
        severity_base=8,
        confidence_base=0.84,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE),
        description="Permission or guardrail bypass instruction.",
    ),
    InjectionPattern(
        name="fmi_memory_write",
        pattern_type="FMI",
        regex=_compile(r"\b(?:remember|store|save|record|persist)\b.{0,60}\b(?:this|that)\b.{0,60}\b(?:as fact|as true|as verified|in memory)\b"),
        severity_base=7,
        confidence_base=0.82,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE),
        description="False-memory planting attempt.",
    ),
    InjectionPattern(
        name="fmi_fabricated_evidence",
        pattern_type="FMI",
        regex=_compile(r"\b(?:treat|mark|label)\b.{0,40}\b(?:fabricated|fake|invented|unverified)\b.{0,40}\b(?:evidence|memory|note|claim)\b.{0,40}\b(?:as verified|as trusted|as true)\b"),
        severity_base=8,
        confidence_base=0.9,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE),
        description="Explicit attempt to bless fabricated evidence.",
    ),
    InjectionPattern(
        name="unicode_zero_width_obfuscation",
        pattern_type="UNICODE_OBFUSCATION",
        regex=_compile(
            r"[\u200b-\u200f"      # ZWSP, ZWNJ, ZWJ, LRM, RLM
            r"\u2028\u2029"        # LINE/PARAGRAPH SEPARATOR
            r"\u202a-\u202e"       # LRE, RLE, PDF, LRO, RLO (bidi override)
            r"\u2060"              # WORD JOINER
            r"\u2066-\u2069"       # LRI, RLI, FSI, PDI (bidi isolates)
            r"\ufeff]+"            # BOM / ZERO WIDTH NO-BREAK SPACE
        ),
        severity_base=6,
        confidence_base=0.8,
        source_types=(SourceType.PROMPT, SourceType.MESSAGE, SourceType.TEMPLATE, SourceType.FILE, SourceType.CODE),
        description=(
            "Invisible and bidi-control Unicode characters used to split payloads, "
            "visually reverse text, or evade pattern filters. Covers: zero-width chars, "
            "bidi overrides (LRO/RLO), bidi embeddings (LRE/RLE), bidi isolates (LRI/RLI/FSI/PDI), "
            "line/paragraph separators, BOM."
        ),
    ),
)


def get_patterns() -> tuple[InjectionPattern, ...]:
    return PATTERN_REGISTRY
