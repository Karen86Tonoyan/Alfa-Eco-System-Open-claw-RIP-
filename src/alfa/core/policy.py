from __future__ import annotations

import re

from alfa.shared.schemas import (
    FilterOutcome,
    Intent,
    PolicyDecision,
    RequestEnvelope,
    ResponseMode,
    RiskLevel,
)


class PolicyEngine:
    """
    Public preview of the ALFA filter pipeline.

    This implementation is intentionally simplified. It demonstrates how
    empathy, ambiguity, intent, and execution safety become structured signals,
    while the production policy set and private heuristics remain outside
    this repository.
    """

    ambiguity_patterns = (
        r"\bzrob to\b",
        r"\bnapraw to\b",
        r"\bogarnij\b",
        r"\bjak zwykle\b",
    )

    source_keywords = (
        "latest",
        "najnowsz",
        "dzis",
        "today",
        "source",
        "zrodl",
        "link",
        "verify",
        "sprawdz",
        "kurs",
        "news",
        "law",
        "prawo",
    )

    tool_keywords = (
        "uruchom",
        "run",
        "execute",
        "search",
        "open",
        "zapisz",
        "wczytaj",
        "notat",
        "script",
        "shell",
        "skrypt",
    )

    manipulation_keywords = (
        "bypass",
        "exploit",
        "ukryj",
        "oszuk",
        "wykrad",
        "haslo",
        "token",
        "malware",
        "payload",
        "omini",
        "credentials",
        "phishing",
    )

    high_impact_keywords = (
        "usun",
        "delete",
        "format",
        "shutdown",
        "publish",
        "deploy",
        "wipe",
        "drop",
        "kill",
        "wylacz",
        "skrypt",
        "shell",
    )

    def analyze(self, request: RequestEnvelope) -> PolicyDecision:
        text = self._normalize(request.text)
        filters: list[FilterOutcome] = []
        signal_score = 0.0

        clarity_ok = self._clarity_ok(text)
        filters.append(
            FilterOutcome(
                "clarity",
                clarity_ok,
                "Input is specific enough." if clarity_ok else "Input should be clarified.",
                0.0 if clarity_ok else 0.2,
            )
        )
        if not clarity_ok:
            signal_score += 0.2

        intent = self._detect_intent(text, request.requested_plugin)
        filters.append(FilterOutcome("intent", True, f"Detected intent: {intent.value}."))

        recommended_plugin = self._recommended_plugin(text, request.requested_plugin)
        if recommended_plugin:
            filters.append(
                FilterOutcome(
                    "plugin_selection",
                    True,
                    f"Recommended plugin: {recommended_plugin}.",
                )
            )

        high_impact = self._is_high_impact(text, recommended_plugin)
        source_conflict = self._source_conflict(request, text, high_impact)
        needs_verification = self._needs_verification(text, intent, request, high_impact)

        if intent is Intent.MANIPULATION:
            signal_score += 0.6
        elif high_impact:
            signal_score += 0.3
        elif intent is Intent.TOOL_EXECUTION:
            signal_score += 0.2

        if source_conflict:
            signal_score += 0.3

        if needs_verification:
            signal_score += 0.2

        risk = self._risk_from_signals(
            intent=intent,
            high_impact=high_impact,
            source_conflict=source_conflict,
            needs_verification=needs_verification,
            clarity_ok=clarity_ok,
        )
        filters.append(
            FilterOutcome(
                "risk",
                risk is not RiskLevel.BLOCK,
                f"Risk level: {risk.value}.",
                round(min(signal_score, 1.0), 2),
            )
        )

        filters.append(
            FilterOutcome(
                "truth_sources",
                not needs_verification,
                "Verification required." if needs_verification else "No source check required.",
                0.2 if needs_verification else 0.0,
            )
        )

        response_mode = self._response_mode(
            clarity_ok=clarity_ok,
            intent=intent,
            risk=risk,
            needs_verification=needs_verification,
            source_conflict=source_conflict,
        )
        filters.append(
            FilterOutcome(
                "response_mode",
                True,
                f"Response mode: {response_mode.value}.",
            )
        )

        return PolicyDecision(
            intent=intent,
            risk=risk,
            response_mode=response_mode,
            needs_verification=needs_verification,
            recommended_plugin=recommended_plugin,
            high_impact=high_impact,
            source_conflict=source_conflict,
            total_score=min(round(signal_score, 2), 1.0),
            filters=filters,
        )

    def _normalize(self, text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    def _clarity_ok(self, text: str) -> bool:
        if len(text.split()) < 3:
            return False
        return not any(re.search(pattern, text) for pattern in self.ambiguity_patterns)

    def _detect_intent(self, text: str, requested_plugin: str | None) -> Intent:
        if any(keyword in text for keyword in self.manipulation_keywords):
            return Intent.MANIPULATION
        if requested_plugin or any(keyword in text for keyword in self.tool_keywords):
            return Intent.TOOL_EXECUTION
        if any(keyword in text for keyword in self.source_keywords):
            return Intent.SOURCE_REQUIRED
        if not self._clarity_ok(text):
            return Intent.AMBIGUOUS
        return Intent.INFORMATION

    def _recommended_plugin(self, text: str, requested_plugin: str | None) -> str | None:
        if requested_plugin:
            return requested_plugin
        if any(keyword in text for keyword in self.source_keywords):
            return "web_lookup"
        if "notat" in text or "note" in text:
            return "notes_lookup"
        if "shell" in text or "script" in text or "skrypt" in text:
            return "script_runner"
        return None

    def _is_high_impact(self, text: str, plugin: str | None) -> bool:
        if any(keyword in text for keyword in self.high_impact_keywords):
            return True
        return plugin == "script_runner"

    def _source_conflict(
        self,
        request: RequestEnvelope,
        text: str,
        high_impact: bool,
    ) -> bool:
        if high_impact and request.source_trust not in {"verified", "operator"}:
            return True
        if request.active_task and any(
            keyword in text for keyword in ("przerwij", "replace mission", "zmien zadanie")
        ):
            return True
        return False

    def _needs_verification(
        self,
        text: str,
        intent: Intent,
        request: RequestEnvelope,
        high_impact: bool,
    ) -> bool:
        if intent is Intent.SOURCE_REQUIRED:
            return True
        if any(keyword in text for keyword in self.source_keywords):
            return True
        return high_impact and request.source_trust not in {"verified", "operator"}

    def _risk_from_signals(
        self,
        *,
        intent: Intent,
        high_impact: bool,
        source_conflict: bool,
        needs_verification: bool,
        clarity_ok: bool,
    ) -> RiskLevel:
        if intent is Intent.MANIPULATION:
            return RiskLevel.BLOCK
        if source_conflict:
            return RiskLevel.HIGH
        if high_impact and not clarity_ok:
            return RiskLevel.HIGH
        if high_impact or needs_verification or intent is Intent.AMBIGUOUS:
            return RiskLevel.REVIEW
        return RiskLevel.SAFE

    def _response_mode(
        self,
        *,
        clarity_ok: bool,
        intent: Intent,
        risk: RiskLevel,
        needs_verification: bool,
        source_conflict: bool,
    ) -> ResponseMode:
        if not clarity_ok:
            return ResponseMode.CLARIFY
        if risk is RiskLevel.BLOCK:
            return ResponseMode.REFUSE
        if source_conflict or risk is RiskLevel.HIGH:
            return ResponseMode.ESCALATE
        if needs_verification:
            return ResponseMode.VERIFY
        if intent is Intent.TOOL_EXECUTION:
            return ResponseMode.EXECUTE
        return ResponseMode.ANSWER
