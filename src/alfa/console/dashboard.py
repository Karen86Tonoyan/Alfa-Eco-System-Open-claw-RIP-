from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from alfa.guard.guardian import AuditStore
from alfa.memory.layer import MemoryLayer


# ---------------------------------------------------------------------------
# Snapshot types — immutable read-only views
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ThreatSummary:
    total_verdicts: int
    unique_threat_ids: int
    unique_sources: int
    pattern_breakdown: dict[str, int]   # pattern_type -> count
    top_threat_id: str | None           # most-seen threat_id


@dataclass(frozen=True, slots=True)
class DecisionSummary:
    allow_count: int
    deny_count: int
    hold_count: int
    total: int
    deny_rate: float        # 0.0–1.0
    avg_risk_score: float


@dataclass(frozen=True, slots=True)
class BrainSummary:
    total_bundles: int
    total_evidence_nodes: int
    total_verdict_nodes: int


@dataclass(frozen=True, slots=True)
class AuditEventSummary:
    total_events: int
    last_5: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    threats: ThreatSummary
    decisions: DecisionSummary
    brain: BrainSummary
    audit: AuditEventSummary

    def to_dict(self) -> dict[str, Any]:
        return {
            "threats": {
                "total_verdicts":    self.threats.total_verdicts,
                "unique_threat_ids": self.threats.unique_threat_ids,
                "unique_sources":    self.threats.unique_sources,
                "pattern_breakdown": self.threats.pattern_breakdown,
                "top_threat_id":     self.threats.top_threat_id,
            },
            "decisions": {
                "allow":      self.decisions.allow_count,
                "deny":       self.decisions.deny_count,
                "hold":       self.decisions.hold_count,
                "total":      self.decisions.total,
                "deny_rate":  round(self.decisions.deny_rate, 4),
                "avg_risk":   round(self.decisions.avg_risk_score, 4),
            },
            "brain": {
                "bundles":         self.brain.total_bundles,
                "evidence_nodes":  self.brain.total_evidence_nodes,
                "verdict_nodes":   self.brain.total_verdict_nodes,
            },
            "audit": {
                "total_events": self.audit.total_events,
                "last_5":       self.audit.last_5,
            },
        }


# ---------------------------------------------------------------------------
# Dashboard builder
# ---------------------------------------------------------------------------

class ALFADashboard:
    """
    Read-only view over AuditStore + MemoryLayer.
    Call snapshot() to get a point-in-time DashboardSnapshot.
    No side effects — safe to call repeatedly.
    """

    def __init__(self, audit_store: AuditStore, memory: MemoryLayer) -> None:
        self._store  = audit_store
        self._memory = memory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def snapshot(self) -> DashboardSnapshot:
        return DashboardSnapshot(
            threats=self._threat_summary(),
            decisions=self._decision_summary(),
            brain=self._brain_summary(),
            audit=self._audit_summary(),
        )

    def render_text(self) -> str:
        """Simple ASCII report — usable in CLI / pytest output."""
        s = self.snapshot()
        lines = [
            "=" * 56,
            "  ALFA DASHBOARD",
            "=" * 56,
            f"  Threats   total={s.threats.total_verdicts}  unique_ids={s.threats.unique_threat_ids}  sources={s.threats.unique_sources}",
            f"  Decisions allow={s.decisions.allow_count}  deny={s.decisions.deny_count}  hold={s.decisions.hold_count}  deny_rate={s.decisions.deny_rate:.0%}",
            f"  Risk      avg={s.decisions.avg_risk_score:.3f}",
            f"  Brain     bundles={s.brain.total_bundles}  evidence={s.brain.total_evidence_nodes}  verdicts={s.brain.total_verdict_nodes}",
            f"  Audit     total_events={s.audit.total_events}",
        ]
        if s.threats.pattern_breakdown:
            lines.append("  Patterns  " + "  ".join(
                f"{k}={v}" for k, v in sorted(s.threats.pattern_breakdown.items(), key=lambda x: -x[1])
            ))
        if s.threats.top_threat_id:
            lines.append(f"  Top threat {s.threats.top_threat_id[:16]}...")
        lines.append("=" * 56)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private builders
    # ------------------------------------------------------------------

    def _threat_summary(self) -> ThreatSummary:
        records = self._store.all_records()

        pattern_counts: dict[str, int] = {}
        threat_id_counts: dict[str, int] = {}
        source_set: set[str] = set()

        for rec in records:
            threat_id_counts[rec.threat_id] = threat_id_counts.get(rec.threat_id, 0) + 1
            source_set.add(rec.source_hash)
            for pt in rec.pattern_types:
                pattern_counts[pt] = pattern_counts.get(pt, 0) + 1

        top_threat_id = max(threat_id_counts, key=threat_id_counts.__getitem__) if threat_id_counts else None

        return ThreatSummary(
            total_verdicts=len(records),
            unique_threat_ids=len(threat_id_counts),
            unique_sources=len(source_set),
            pattern_breakdown=pattern_counts,
            top_threat_id=top_threat_id,
        )

    def _decision_summary(self) -> DecisionSummary:
        records = self._store.all_records()
        if not records:
            return DecisionSummary(0, 0, 0, 0, 0.0, 0.0)

        allow = deny = hold = 0
        risk_total = 0.0

        for rec in records:
            status = rec.verdict.status.value
            if status == "ALLOW":
                allow += 1
            elif status == "HOLD":
                hold += 1
            else:
                deny += 1
            risk_total += rec.verdict.risk_score

        total = len(records)
        return DecisionSummary(
            allow_count=allow,
            deny_count=deny,
            hold_count=hold,
            total=total,
            deny_rate=deny / total,
            avg_risk_score=risk_total / total,
        )

    def _brain_summary(self) -> BrainSummary:
        bundles = self._memory.system_memory.get("guardian.brain.bundles", [])
        evidence_nodes = 0
        verdict_nodes = 0

        for bundle in bundles:
            nodes = bundle.get("nodes")
            if isinstance(nodes, list):
                evidence_nodes += sum(1 for node in nodes if node.get("node_type") == "evidence")
                verdict_nodes += sum(1 for node in nodes if node.get("node_type") == "verdict")
                continue

            # Backward-compatible fallback for older hand-rolled snapshots.
            evidence_nodes += len(bundle.get("evidence_nodes", []))
            verdict_nodes += len(bundle.get("verdict_nodes", []))

        return BrainSummary(
            total_bundles=len(bundles),
            total_evidence_nodes=evidence_nodes,
            total_verdict_nodes=verdict_nodes,
        )

    def _audit_summary(self) -> AuditEventSummary:
        log = self._memory.audit_log
        last_5 = [e.to_dict() for e in log[-5:]]
        return AuditEventSummary(total_events=len(log), last_5=last_5)
