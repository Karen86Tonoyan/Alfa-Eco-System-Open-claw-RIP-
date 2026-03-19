from __future__ import annotations

from typing import Any

from alfa.shared.schemas import RiskLevel, ToolPermission

from .base import PluginSpec


class WebLookupPlugin:
    spec = PluginSpec(
        name="web_lookup",
        description="Public verification stub for source-aware tasks.",
        permissions=(ToolPermission.READ, ToolPermission.NETWORK),
        base_risk=RiskLevel.REVIEW,
        metadata={"visibility": "public_preview"},
    )

    def execute(self, text: str, *, session_id: str, user_id: str, memory: Any) -> dict[str, Any]:
        return {
            "plugin": self.spec.name,
            "query": text,
            "status": "verification_stub",
            "message": "Verified web retrieval is available in the private operational stack.",
        }


class NotesLookupPlugin:
    spec = PluginSpec(
        name="notes_lookup",
        description="Reads user notes from memory context.",
        permissions=(ToolPermission.READ,),
        base_risk=RiskLevel.SAFE,
        metadata={"visibility": "public_preview"},
    )

    def execute(self, text: str, *, session_id: str, user_id: str, memory: Any) -> dict[str, Any]:
        notes = memory.get_user_value(user_id, "notes", [])
        return {
            "plugin": self.spec.name,
            "query": text,
            "notes_count": len(notes),
            "notes": list(notes),
        }


class ScriptRunnerPlugin:
    spec = PluginSpec(
        name="script_runner",
        description="Execution stub gated behind explicit approval.",
        permissions=(ToolPermission.READ, ToolPermission.WRITE, ToolPermission.EXECUTE),
        base_risk=RiskLevel.HIGH,
        requires_confirmation=True,
        metadata={"visibility": "public_preview"},
    )

    def execute(self, text: str, *, session_id: str, user_id: str, memory: Any) -> dict[str, Any]:
        return {
            "plugin": self.spec.name,
            "status": "execution_stub",
            "command_request": text,
            "message": "Real execution is delegated to private controlled runners.",
        }

