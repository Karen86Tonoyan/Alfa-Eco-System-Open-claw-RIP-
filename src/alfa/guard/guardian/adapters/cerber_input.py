from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from alfa.guard.epistemic_gate import EpistemicVerdict
from alfa.guard.guardian.evidence_gate import EvidenceGate
from alfa.guard.guardian.types import ClaimStatus, EvidenceVerdict
from alfa.guard.lasuch.adapters.guardian_input import GuardianClaimInput, LasuchGuardianAdapter
from alfa.guard.lasuch.detector import InjectionDetector
from alfa.guard.lasuch.types import SourceType


@dataclass(frozen=True, slots=True)
class CerberEvidenceEnvelope:
    verdict: EpistemicVerdict
    evidence_refs: list[str]
    audit_trail: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "granted": self.verdict.granted,
            "risk_score": self.verdict.risk_score,
            "reason": self.verdict.reason,
            "claim_id": self.verdict.claim_id,
            "evidence_refs": list(self.evidence_refs),
            "audit_trail": [dict(item) for item in self.audit_trail],
        }


class EvidenceVerdictToCerber:
    def convert(self, verdict: EvidenceVerdict) -> CerberEvidenceEnvelope:
        if verdict.status is ClaimStatus.ALLOW:
            epistemic = EpistemicVerdict.allow(
                risk_score=verdict.risk_score,
                reason=verdict.reason,
                claim_id=verdict.claim_id,
            )
        else:
            epistemic = EpistemicVerdict.deny(
                risk_score=verdict.risk_score,
                reason=verdict.reason,
                claim_id=verdict.claim_id,
            )

        return CerberEvidenceEnvelope(
            verdict=epistemic,
            evidence_refs=list(verdict.evidence_refs),
            audit_trail=[dict(item) for item in verdict.audit_trail],
        )


class GuardianEpistemicGate:
    """
    Thin EpistemicGate implementation that closes the first live line:
    request_text -> Lasuch -> Guardian -> Cerber-compatible EpistemicVerdict.
    """

    def __init__(
        self,
        *,
        detector: InjectionDetector | None = None,
        claim_adapter: LasuchGuardianAdapter | None = None,
        evidence_gate: EvidenceGate | None = None,
        verdict_adapter: EvidenceVerdictToCerber | None = None,
    ) -> None:
        self._detector = detector or InjectionDetector()
        self._claim_adapter = claim_adapter or LasuchGuardianAdapter()
        self._evidence_gate = evidence_gate or EvidenceGate()
        self._verdict_adapter = verdict_adapter or EvidenceVerdictToCerber()
        self.last_envelope: CerberEvidenceEnvelope | None = None
        self.last_claim: GuardianClaimInput | None = None
        self.last_evidence_verdict: EvidenceVerdict | None = None

    def evaluate(
        self,
        *,
        request_text: str,
        plugin_name: str | None,
        cerber_risk_score: float,
        context: dict[str, Any] | None = None,
    ) -> EpistemicVerdict:
        context = context or {}
        source_type = self._infer_source_type(
            request_text=request_text,
            plugin_name=plugin_name,
            context=context,
        )
        language_hint = self._infer_language_hint(
            request_text=request_text,
            plugin_name=plugin_name,
            context=context,
        )

        packets = self._detector.detect(
            request_text,
            source_type=source_type,
            language_hint=language_hint,
        )
        if not packets:
            self.last_claim = None
            self.last_evidence_verdict = None
            self.last_envelope = CerberEvidenceEnvelope(
                verdict=EpistemicVerdict.allow(
                    risk_score=cerber_risk_score,
                    reason="Guardian found no quarantined threat evidence.",
                ),
                evidence_refs=[],
                audit_trail=[],
            )
            return self.last_envelope.verdict

        claim = self._claim_adapter.to_guardian_claim(packets)
        evidence_verdict = self._evidence_gate.consume(claim)
        self.last_claim = claim
        self.last_evidence_verdict = evidence_verdict
        envelope = self._verdict_adapter.convert(evidence_verdict)

        bridged_risk = max(cerber_risk_score, envelope.verdict.risk_score)
        if envelope.verdict.granted:
            final_verdict = EpistemicVerdict.allow(
                risk_score=bridged_risk,
                reason=envelope.verdict.reason,
                claim_id=envelope.verdict.claim_id,
            )
        else:
            final_verdict = EpistemicVerdict.deny(
                risk_score=bridged_risk,
                reason=envelope.verdict.reason,
                claim_id=envelope.verdict.claim_id,
            )

        self.last_envelope = CerberEvidenceEnvelope(
            verdict=final_verdict,
            evidence_refs=envelope.evidence_refs,
            audit_trail=envelope.audit_trail,
        )
        return final_verdict

    def _infer_source_type(
        self,
        *,
        request_text: str,
        plugin_name: str | None,
        context: dict[str, Any],
    ) -> SourceType:
        explicit = context.get("source_type")
        if isinstance(explicit, str):
            return SourceType(explicit)
        if plugin_name == "script_runner" and self._looks_like_code(request_text):
            return SourceType.CODE
        return SourceType.PROMPT

    def _infer_language_hint(
        self,
        *,
        request_text: str,
        plugin_name: str | None,
        context: dict[str, Any],
    ) -> str | None:
        explicit = context.get("language_hint")
        if isinstance(explicit, str):
            return explicit
        if plugin_name == "script_runner" and self._looks_like_code(request_text):
            return "python"
        return "markdown"

    def _looks_like_code(self, text: str) -> bool:
        code_markers = (
            "def ",
            "class ",
            "import ",
            "from ",
            "SELECT ",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "{",
            "};",
            "```",
            "function ",
            "const ",
            "let ",
            "var ",
            "=>",
        )
        lowered = text.lower()
        return any(marker.lower() in lowered for marker in code_markers)
