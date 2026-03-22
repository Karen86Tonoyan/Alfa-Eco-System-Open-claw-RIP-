from unittest.mock import MagicMock

from alfa.core.core_lock_logger import CoreLockLogger
from alfa.core.filter_contract import FilterAction, FilterResult
from alfa.core.filter_orchestrator import Orchestrator


class DummyFilter:
    def __init__(self, filter_id: str, result: FilterResult) -> None:
        self.filter_id = filter_id
        self._result = result

    def process(self, request):
        return self._result


class MemoryLogger(CoreLockLogger):
    def __init__(self) -> None:
        self.entries = []

    def log(self, request, score: float, correlation_id: str) -> str:
        self.entries.append((request, score, correlation_id))
        return "logged"


def test_process_validation_error_returns_block() -> None:
    orchestrator = Orchestrator([], [], [], logger=MemoryLogger())
    result = orchestrator.process({"query": ""})
    assert result.action == FilterAction.BLOCK
    assert result.reason is not None and result.reason.startswith("validation_error")
    assert result.correlation_id


def test_process_tier1_proceed() -> None:
    orchestrator = Orchestrator([], [], [], logger=MemoryLogger())
    orchestrator._run_tier = MagicMock(return_value=[])
    orchestrator._aggregate_results = MagicMock(side_effect=[
        {"aggregated_score": 0.2, "confidence": 0.9, "hard_block": False, "timed_out_filters": []}
    ])
    result = orchestrator.process(
        {
            "query": "safe",
            "user_id": "user1",
            "session_id": "session1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        }
    )
    assert result.action == FilterAction.PROCEED


def test_process_tier3_clarify() -> None:
    orchestrator = Orchestrator([], [], [], logger=MemoryLogger())
    orchestrator._run_tier = MagicMock(return_value=[])
    orchestrator._aggregate_results = MagicMock(side_effect=[
        {"aggregated_score": 0.4, "confidence": 0.8, "hard_block": False, "timed_out_filters": []},
        {"aggregated_score": 0.5, "confidence": 0.8, "hard_block": False, "timed_out_filters": []},
        {"aggregated_score": 0.4, "confidence": 0.8, "hard_block": False, "timed_out_filters": []},
    ])
    result = orchestrator.process(
        {
            "query": "medium_risk",
            "user_id": "user1",
            "session_id": "session1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        }
    )
    assert result.action == FilterAction.CLARIFY


def test_process_tier3_escalate() -> None:
    orchestrator = Orchestrator([], [], [], logger=MemoryLogger())
    orchestrator._run_tier = MagicMock(return_value=[])
    orchestrator._aggregate_results = MagicMock(side_effect=[
        {"aggregated_score": 0.5, "confidence": 0.8, "hard_block": False, "timed_out_filters": []},
        {"aggregated_score": 0.6, "confidence": 0.8, "hard_block": False, "timed_out_filters": []},
    ])
    result = orchestrator.process(
        {
            "query": "high_risk",
            "user_id": "user1",
            "session_id": "session1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        }
    )
    assert result.action == FilterAction.ESCALATE


def test_process_tier3_hard_block_logs_core_lock() -> None:
    logger = MemoryLogger()
    orchestrator = Orchestrator([], [], [], logger=logger)
    orchestrator._run_tier = MagicMock(return_value=[])
    orchestrator._aggregate_results = MagicMock(side_effect=[
        {"aggregated_score": 0.7, "confidence": 0.9, "hard_block": False, "timed_out_filters": []},
        {"aggregated_score": 0.8, "confidence": 0.9, "hard_block": True, "timed_out_filters": []},
    ])
    result = orchestrator.process(
        {
            "query": "critical_risk",
            "user_id": "user1",
            "session_id": "session1",
            "timestamp": "2026-03-21T12:00:00+00:00",
        }
    )
    assert result.action == FilterAction.BLOCK
    assert result.reason == "core_lock"
    assert len(logger.entries) == 1
