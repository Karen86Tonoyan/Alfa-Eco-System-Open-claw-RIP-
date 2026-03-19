from __future__ import annotations

import re

from alfa.shared.schemas import RequestEnvelope


class VoiceGateway:
    """Voice is interface, not command center."""

    wake_words = ("alfa", "alpha")

    def normalize_transcript(self, transcript: str) -> str:
        text = transcript.strip()
        lowered = text.lower()
        for wake_word in self.wake_words:
            pattern = rf"^\s*{wake_word}[\s,.:;-]*"
            lowered = re.sub(pattern, "", lowered, flags=re.IGNORECASE)
        return re.sub(r"\s+", " ", lowered).strip()

    def to_request(
        self,
        transcript: str,
        *,
        session_id: str = "voice-session",
        user_id: str = "voice-user",
        source_trust: str = "primary",
    ) -> RequestEnvelope:
        normalized = self.normalize_transcript(transcript)
        return RequestEnvelope(
            text=normalized,
            session_id=session_id,
            user_id=user_id,
            source_id="voice",
            source_trust=source_trust,
            metadata={"interface": "voice"},
        )

