from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Protocol
from uuid import uuid4

from .core_lock_logger import CoreLockLogger
from .filter_contract import DecisionResult, FilterAction, FilterRequestModel, FilterResult


class FilterProtocol(Protocol):
    filter_id: str

    def process(self, request: FilterRequestModel) -> FilterResult:
        ...


class Orchestrator:
    def __init__(
        self,
        tier1_filters: list[FilterProtocol],
        tier2_filters: list[FilterProtocol],
        tier3_filters: list[FilterProtocol],
        logger: CoreLockLogger | None = None,
    ) -> None:
        self.tier1_filters = tier1_filters
        self.tier2_filters = tier2_filters
        self.tier3_filters = tier3_filters
        self.logger = logger or CoreLockLogger()

    def _run_tier(
        self,
        filters: list[FilterProtocol],
        request: FilterRequestModel,
        timeout_ms: int | None,
    ) -> list[FilterResult]:
        if not filters:
            return []

        results: list[FilterResult] = []
        with ThreadPoolExecutor(max_workers=max(1, len(filters))) as executor:
            future_to_filter = {
                executor.submit(filter_obj.process, request): filter_obj
                for filter_obj in filters
            }
            done, not_done = wait(
                future_to_filter.keys(),
                timeout=None if timeout_ms is None else timeout_ms / 1000,
            )

            for future in done:
                filter_obj = future_to_filter[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 - surfaced as filter result
                    results.append(
                        FilterResult(
                            filter_id=filter_obj.filter_id,
                            risk_score=0.5,
                            confidence=0.1,
                            flags=["exception", type(exc).__name__],
                            action=FilterAction.ESCALATE,
                            context={},
                            timed_out=False,
                        )
                    )

            for future in not_done:
                filter_obj = future_to_filter[future]
                results.append(
                    FilterResult(
                        filter_id=filter_obj.filter_id,
                        risk_score=0.5,
                        confidence=0.1,
                        flags=["timeout"],
                        action=FilterAction.ESCALATE,
                        context={},
                        timed_out=True,
                    )
                )
        return results

    def _aggregate_results(self, results: list[FilterResult]) -> dict[str, Any]:
        if not results:
            return {
                "aggregated_score": 0.0,
                "confidence": 0.0,
                "hard_block": False,
                "timed_out_filters": [],
            }

        weights = {result.filter_id: 1.0 for result in results}
        weights.update({"Cerber": 1.5, "Guardian": 1.2})

        weighted_score = sum(
            result.risk_score * result.confidence * weights.get(result.filter_id, 1.0)
            for result in results
        )
        total_weight = sum(
            result.confidence * weights.get(result.filter_id, 1.0)
            for result in results
        )
        aggregated_score = weighted_score / total_weight if total_weight > 0 else 0.0
        confidence = sum(result.confidence for result in results) / len(results)

        return {
            "aggregated_score": aggregated_score,
            "confidence": confidence,
            "hard_block": any(
                result.action == FilterAction.BLOCK and result.confidence > 0.8
                for result in results
            ),
            "timed_out_filters": [result.filter_id for result in results if result.timed_out],
        }

    def process(self, request: dict[str, Any]) -> DecisionResult:
        fallback_correlation_id = (
            request.get("correlation_id")
            if isinstance(request, dict) and request.get("correlation_id")
            else str(uuid4())
        )

        try:
            validated_request = FilterRequestModel.from_dict(request)
        except Exception as exc:  # noqa: BLE001 - normalized into decision result
            return DecisionResult(
                action=FilterAction.BLOCK,
                score=1.0,
                confidence=1.0,
                reason=f"validation_error: {exc}",
                correlation_id=fallback_correlation_id,
            )

        tier1_results = self._run_tier(self.tier1_filters, validated_request, timeout_ms=50)
        tier1_agg = self._aggregate_results(tier1_results)

        if tier1_agg["aggregated_score"] < 0.3:
            return DecisionResult(
                action=FilterAction.PROCEED,
                score=tier1_agg["aggregated_score"],
                confidence=tier1_agg["confidence"],
                correlation_id=validated_request.correlation_id,
            )

        if tier1_agg["aggregated_score"] < 0.6:
            tier2_results = self._run_tier(self.tier2_filters, validated_request, timeout_ms=200)
            tier2_agg = self._aggregate_results(tier2_results)

            if tier2_agg["aggregated_score"] < 0.4:
                return DecisionResult(
                    action=FilterAction.PROCEED,
                    score=tier2_agg["aggregated_score"],
                    confidence=tier2_agg["confidence"],
                    warning="soft",
                    correlation_id=validated_request.correlation_id,
                )

        tier3_results = self._run_tier(self.tier3_filters, validated_request, timeout_ms=None)
        tier3_agg = self._aggregate_results(tier3_results)

        if tier3_agg["hard_block"]:
            self.logger.log(
                request=validated_request,
                score=tier3_agg["aggregated_score"],
                correlation_id=validated_request.correlation_id,
            )
            return DecisionResult(
                action=FilterAction.BLOCK,
                score=tier3_agg["aggregated_score"],
                confidence=tier3_agg["confidence"],
                reason="core_lock",
                filter_results=tier3_results,
                timed_out_filters=tier3_agg["timed_out_filters"],
                correlation_id=validated_request.correlation_id,
            )
        if tier3_agg["aggregated_score"] < 0.3:
            return DecisionResult(
                action=FilterAction.PROCEED,
                score=tier3_agg["aggregated_score"],
                confidence=tier3_agg["confidence"],
                filter_results=tier3_results,
                timed_out_filters=tier3_agg["timed_out_filters"],
                correlation_id=validated_request.correlation_id,
            )
        if tier3_agg["aggregated_score"] < 0.5:
            return DecisionResult(
                action=FilterAction.CLARIFY,
                score=tier3_agg["aggregated_score"],
                confidence=tier3_agg["confidence"],
                message="Decision requires clarification.",
                filter_results=tier3_results,
                timed_out_filters=tier3_agg["timed_out_filters"],
                correlation_id=validated_request.correlation_id,
            )
        return DecisionResult(
            action=FilterAction.ESCALATE,
            score=tier3_agg["aggregated_score"],
            confidence=tier3_agg["confidence"],
            message="Decision requires human approval.",
            filter_results=tier3_results,
            timed_out_filters=tier3_agg["timed_out_filters"],
            correlation_id=validated_request.correlation_id,
        )
