"""
BrainCompactor — non-destructive compaction layer for guardian.brain.bundles.

Memory layout:
  guardian.brain.bundles                 live, append-only (frozen contract)
  guardian.brain.compaction.snapshots    list of timestamped snapshots
  guardian.brain.compacted               last compacted graph (optional)

Public API:
  compactor = BrainCompactor(memory)
  report    = compactor.analyse()            # read-only
  snap_key  = compactor.snapshot()           # writes snapshot only
  report    = compactor.compact()            # dry_run=True (safe default)
  report    = compactor.compact(dry_run=False)  # writes compacted graph
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class CompactionReport:
    """Result of analyse() or compact() — always non-destructive to read."""

    total_bundles: int
    unique_evidence_ids: int
    duplicate_bundle_count: int  # bundles that share evidence with another
    savings_potential_pct: float  # 0.0-100.0 — how much could be saved
    snapshot_key: str | None  # set when a snapshot was taken during compact()
    dry_run: bool

    # Per-evidence-id: list of threat_ids that reference it
    evidence_groups: dict[str, list[str]] = field(default_factory=dict)

    def __str__(self) -> str:
        lines = [
            "--- CompactionReport ---",
            f"  total_bundles        : {self.total_bundles}",
            f"  unique_evidence_ids  : {self.unique_evidence_ids}",
            f"  duplicate_bundles    : {self.duplicate_bundle_count}",
            f"  savings_potential    : {self.savings_potential_pct:.1f}%",
            f"  dry_run              : {self.dry_run}",
            f"  snapshot_key         : {self.snapshot_key or '(none)'}",
        ]
        return "\n".join(lines)


@dataclass(frozen=True)
class CompactionSnapshot:
    """A timestamped freeze of guardian.brain.bundles."""

    key: str          # guardian.brain.compaction.snapshots/<iso-ts>
    timestamp: str    # ISO-8601 UTC
    bundle_count: int
    bundles: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "timestamp": self.timestamp,
            "bundle_count": self.bundle_count,
            "bundles": list(self.bundles),
        }


class BrainCompactor:
    """
    Non-destructive compaction layer.

    Does NOT modify guardian.brain.bundles (the live append-only store).
    Writes only to:
      guardian.brain.compaction.snapshots  (via snapshot() or compact())
      guardian.brain.compacted             (only when compact(dry_run=False))
    """

    _LIVE_KEY = "guardian.brain.bundles"
    _SNAPSHOTS_KEY = "guardian.brain.compaction.snapshots"
    _COMPACTED_KEY = "guardian.brain.compacted"

    def __init__(self, memory: Any) -> None:
        # Accepts MemoryLayer (uses .system_memory dict and .set_system_value())
        self._memory = memory

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self) -> CompactionReport:
        """Read-only analysis. Zero writes to memory."""
        bundles = self._load_bundles()
        return self._build_report(bundles, snapshot_key=None, dry_run=True)

    def snapshot(self) -> str:
        """
        Freeze current guardian.brain.bundles into compaction.snapshots.
        Returns the snapshot key (ISO timestamp).
        """
        bundles = self._load_bundles()
        snap = self._write_snapshot(bundles)
        return snap.key

    def compact(self, *, dry_run: bool = True) -> CompactionReport:
        """
        dry_run=True  (default): snapshot + analyse, no changes to live store.
        dry_run=False           : snapshot + analyse + write compacted graph.

        In both modes guardian.brain.bundles is never modified.
        """
        bundles = self._load_bundles()
        snap = self._write_snapshot(bundles)
        report = self._build_report(bundles, snapshot_key=snap.key, dry_run=dry_run)

        if not dry_run:
            compacted = self._build_compacted_graph(bundles)
            self._memory.set_system_value(self._COMPACTED_KEY, compacted)

        return report

    # ------------------------------------------------------------------
    # Inspection helpers
    # ------------------------------------------------------------------

    def list_snapshots(self) -> list[dict[str, Any]]:
        """Return metadata for all stored snapshots (without bundle payloads)."""
        raw = self._memory.system_memory.get(self._SNAPSHOTS_KEY, [])
        return [
            {"key": s["key"], "timestamp": s["timestamp"], "bundle_count": s["bundle_count"]}
            for s in raw
        ]

    def get_compacted(self) -> dict[str, Any] | None:
        """Return the last compacted graph, or None if compact(dry_run=False) was never run."""
        return self._memory.system_memory.get(self._COMPACTED_KEY)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_bundles(self) -> list[dict[str, Any]]:
        return list(self._memory.system_memory.get(self._LIVE_KEY, []))

    def _write_snapshot(self, bundles: list[dict[str, Any]]) -> CompactionSnapshot:
        ts = datetime.now(tz=timezone.utc).isoformat()
        key = f"guardian.brain.compaction.snapshots/{ts}"
        snap = CompactionSnapshot(
            key=key,
            timestamp=ts,
            bundle_count=len(bundles),
            bundles=bundles,
        )
        existing = list(self._memory.system_memory.get(self._SNAPSHOTS_KEY, []))
        existing.append(snap.to_dict())
        self._memory.set_system_value(self._SNAPSHOTS_KEY, existing)
        return snap

    def _build_report(
        self,
        bundles: list[dict[str, Any]],
        *,
        snapshot_key: str | None,
        dry_run: bool,
    ) -> CompactionReport:
        # Group bundles by evidence node id
        evidence_groups: dict[str, list[str]] = {}
        for bundle in bundles:
            ev_id = self._extract_evidence_id(bundle)
            threat_id = self._extract_threat_id(bundle)
            evidence_groups.setdefault(ev_id, []).append(threat_id)

        total = len(bundles)
        unique_ev = len(evidence_groups)
        # bundles that share evidence with at least one other bundle
        duplicate_count = sum(len(v) - 1 for v in evidence_groups.values() if len(v) > 1)
        savings_pct = (duplicate_count / total * 100.0) if total > 0 else 0.0

        return CompactionReport(
            total_bundles=total,
            unique_evidence_ids=unique_ev,
            duplicate_bundle_count=duplicate_count,
            savings_potential_pct=savings_pct,
            snapshot_key=snapshot_key,
            dry_run=dry_run,
            evidence_groups=evidence_groups,
        )

    def _build_compacted_graph(
        self, bundles: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Build a compacted graph representation.

        For each unique evidence_id, emit:
          - 1 evidence node
          - N threat nodes   (one per referencing bundle)
          - N verdict nodes  (one per referencing bundle)
          - N supported_by edges
          - N produced edges

        This does NOT replace guardian.brain.bundles.
        Written to guardian.brain.compacted only.
        """
        nodes: dict[str, dict[str, Any]] = {}  # node_id -> node dict
        edges: list[dict[str, Any]] = []

        for bundle in bundles:
            for node in bundle.get("nodes", []):
                nodes[node["node_id"]] = node
            for edge in bundle.get("edges", []):
                edges.append(edge)

        # Deduplicate edges by edge_id
        seen_edges: dict[str, dict[str, Any]] = {}
        for edge in edges:
            seen_edges[edge["edge_id"]] = edge

        # Build a fingerprint for audit
        content = "|".join(sorted(nodes.keys()))
        graph_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        return {
            "compacted_at": datetime.now(tz=timezone.utc).isoformat(),
            "source_bundle_count": len(bundles),
            "node_count": len(nodes),
            "edge_count": len(seen_edges),
            "graph_hash": graph_hash,
            "nodes": list(nodes.values()),
            "edges": list(seen_edges.values()),
        }

    @staticmethod
    def _extract_evidence_id(bundle: dict[str, Any]) -> str:
        for node in bundle.get("nodes", []):
            if node.get("node_type") == "evidence":
                return node["node_id"]
        # Fallback: hash the full bundle if structure is unexpected
        return hashlib.md5(str(bundle).encode()).hexdigest()[:16]

    @staticmethod
    def _extract_threat_id(bundle: dict[str, Any]) -> str:
        for node in bundle.get("nodes", []):
            if node.get("node_type") == "threat":
                payload = node.get("payload", {})
                return payload.get("threat_id", node["node_id"])
        return "(unknown)"
