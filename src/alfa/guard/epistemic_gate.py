from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class EpistemicVerdict:
    """
    Result returned by any EpistemicGate implementation.

    granted    — True if the epistemic layer approves execution.
    risk_score — float [0.0, 1.0]; 0.0 = no risk, 1.0 = fully blocked.
    reason     — human-readable explanation (logged by Cerber).
    claim_id   — opaque identifier assigned by the epistemic backend (optional).
    """

    granted: bool
    risk_score: float
    reason: str
    claim_id: str | None = None

    @classmethod
    def allow(cls, *, risk_score: float = 0.0, reason: str = "Epistemic gate approved.", claim_id: str | None = None) -> "EpistemicVerdict":
        return cls(granted=True, risk_score=risk_score, reason=reason, claim_id=claim_id)

    @classmethod
    def deny(cls, *, risk_score: float = 1.0, reason: str, claim_id: str | None = None) -> "EpistemicVerdict":
        return cls(granted=False, risk_score=risk_score, reason=reason, claim_id=claim_id)


@runtime_checkable
class EpistemicGate(Protocol):
    """
    Protocol for any epistemic execution gate plugged into CerberGuard.

    Implementations live outside ALFA-Eco-System (e.g. the AlfaEOS adapter
    in PyGPT).  CerberGuard depends only on this interface — never on a
    concrete backend.

    Contract:
    - evaluate() MUST be pure with respect to ALFA state; side effects belong
      to the implementing backend.
    - A missing or unavailable backend SHOULD return EpistemicVerdict.allow()
      with a non-zero risk_score rather than raise — Cerber decides what to do
      with elevated risk.
    """

    def evaluate(
        self,
        *,
        request_text: str,
        plugin_name: str | None,
        cerber_risk_score: float,
        context: dict[str, Any] | None = None,
    ) -> EpistemicVerdict:
        """
        Evaluate whether execution is epistemically sound.

        Parameters
        ----------
        request_text     : the original user/operator request text
        plugin_name      : plugin targeted for execution (None if non-exec path)
        cerber_risk_score: risk score already assigned by CerberGuard pattern layer
        context          : arbitrary extra context (session_id, user_id, etc.)
        """
        ...


class PassthroughEpistemicGate:
    """
    No-op implementation.  Always grants, passes Cerber risk through.
    Used as default when no epistemic backend is wired in.
    """

    def evaluate(
        self,
        *,
        request_text: str,
        plugin_name: str | None,
        cerber_risk_score: float,
        context: dict[str, Any] | None = None,
    ) -> EpistemicVerdict:
        return EpistemicVerdict.allow(
            risk_score=cerber_risk_score,
            reason="No epistemic backend configured — passthrough.",
        )
