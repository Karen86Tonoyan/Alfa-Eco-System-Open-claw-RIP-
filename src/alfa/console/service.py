from __future__ import annotations

from typing import Any

from alfa.core.brain import ALFACoreBrain
from alfa.guard.cerber import CerberGuard
from alfa.memory.layer import MemoryLayer
from alfa.plugins.registry import PluginRegistry
from alfa.shared.events import AuditEventType
from alfa.shared.schemas import RequestEnvelope, ResponseMode


class ALFAConsole:
    """Console shows state and orchestrates the ecosystem."""

    def __init__(
        self,
        *,
        core: ALFACoreBrain,
        guard: CerberGuard,
        plugins: PluginRegistry,
        memory: MemoryLayer,
    ):
        self.core = core
        self.guard = guard
        self.plugins = plugins
        self.memory = memory

    def handle(self, request: RequestEnvelope) -> dict[str, Any]:
        self.memory.append_audit(
            AuditEventType.TASK_RECEIVED,
            session_id=request.session_id,
            user_id=request.user_id,
            source_id=request.source_id,
            detail={"text": request.text},
        )

        decision = self.core.decide(request)
        self.memory.append_audit(
            AuditEventType.POLICY_DECIDED,
            session_id=request.session_id,
            user_id=request.user_id,
            source_id=request.source_id,
            detail=decision.policy.to_dict(),
        )
        self.memory.append_audit(
            AuditEventType.ROUTE_SELECTED,
            session_id=request.session_id,
            user_id=request.user_id,
            source_id=request.source_id,
            detail=decision.route.to_dict(),
        )

        plugin_spec = self.plugins.spec(decision.route.target_plugin)
        guard = self.guard.authorize(request, decision, plugin_spec)
        self.memory.append_audit(
            AuditEventType.GUARD_APPROVED if guard.allowed else AuditEventType.GUARD_BLOCKED,
            session_id=request.session_id,
            user_id=request.user_id,
            source_id=request.source_id,
            detail=guard.to_dict(),
        )

        execution_result: dict[str, Any] | None = None
        if guard.allowed and guard.approved_plugin and guard.mode in {
            ResponseMode.VERIFY,
            ResponseMode.EXECUTE,
        }:
            cache_key = f"{guard.approved_plugin}:{request.user_id}:{request.text}"
            cached = self.memory.get_tool_result(cache_key)
            if cached is None:
                execution_result = self.plugins.execute(
                    guard.approved_plugin,
                    request.text,
                    session_id=request.session_id,
                    user_id=request.user_id,
                    memory=self.memory,
                )
                self.memory.cache_tool_result(cache_key, execution_result)
            else:
                execution_result = {"plugin": guard.approved_plugin, "cached": True, "result": cached}

            self.memory.append_audit(
                AuditEventType.PLUGIN_EXECUTED,
                session_id=request.session_id,
                user_id=request.user_id,
                source_id=request.source_id,
                detail=execution_result,
            )

        response_message = self._response_message(guard)
        self.memory.remember_session(request.session_id, "last_request", request.text)
        self.memory.remember_session(request.session_id, "last_state", decision.state.value)
        self.memory.append_audit(
            AuditEventType.RESPONSE_READY,
            session_id=request.session_id,
            user_id=request.user_id,
            source_id=request.source_id,
            detail={"message": response_message},
        )

        return {
            "decision": decision.to_dict(),
            "guard": guard.to_dict(),
            "execution": execution_result,
            "response": response_message,
            "plugins": self.plugins.list_specs(),
            "audit_events": [event.to_dict() for event in self.memory.audit_log[-5:]],
        }

    def _response_message(self, guard: Any) -> str:
        if not guard.allowed and guard.mode is ResponseMode.ESCALATE:
            return "Cerber zatrzymal akcje. Wymagana eskalacja lub potwierdzenie operatora."
        if not guard.allowed and guard.mode is ResponseMode.REFUSE:
            return "Cerber zablokowal zadanie jako niebezpieczne."
        if guard.mode is ResponseMode.CLARIFY:
            return "Najpierw doprecyzuj zadanie."
        if guard.mode is ResponseMode.VERIFY:
            return "Zapytanie przechodzi przez warstwe weryfikacji zrodel."
        if guard.mode is ResponseMode.EXECUTE:
            return "Akcja zostala dopuszczona do wykonania przez plugin."
        return "Zapytanie moze trafic do glownego modelu."
