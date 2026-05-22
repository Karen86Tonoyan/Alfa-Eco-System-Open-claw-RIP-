"""
Tests for BrainCompactor — guardian.brain.compaction layer.

Test classes:
  TestAnalyse         — read-only analysis, zero writes
  TestSnapshot        — snapshot writes, structure, accumulation
  TestCompactDryRun   — compact(dry_run=True): snapshot + report, no compacted key
  TestCompactLive     — compact(dry_run=False): writes guardian.brain.compacted
  TestDuplicateDetection — dedup logic when multiple bundles share evidence node
  TestEmptyStore      — all operations on empty memory are safe
  TestContractPreservation — live guardian.brain.bundles is NEVER modified
"""
from __future__ import annotations

import pytest

from alfa.guard.guardian.evidence_gate import EvidenceGate
from alfa.guard.guardian.services.audit_store import AuditStore
from alfa.guard.guardian.services.brain_compactor import BrainCompactor, CompactionReport
from alfa.guard.guardian.services.brain_linker import BrainLinker
from alfa.guard.lasuch import InjectionDetector, LasuchGuardianAdapter, SourceType
from alfa.memory.layer import MemoryLayer
from tests.adversarial_payloads import PROMPT_INJECTION_PAYLOADS, SQL_INJECTION_PAYLOADS


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _source_for(text: str) -> SourceType:
    lower = text.lower()
    return SourceType.CODE if ("union" in lower or "sleep(" in lower) else SourceType.PROMPT


def _build_memory_with_bundles(n: int = 6) -> MemoryLayer:
    """Run n real payloads through the full pipeline, populate brain.bundles."""
    memory = MemoryLayer()
    store = AuditStore(memory)
    detector = InjectionDetector()
    adapter = LasuchGuardianAdapter()
    gate = EvidenceGate()
    linker = BrainLinker()

    payloads = (
        list(SQL_INJECTION_PAYLOADS[: n // 2]) + list(PROMPT_INJECTION_PAYLOADS[: n - n // 2])
    )

    for text in payloads[:n]:
        source = _source_for(text)
        hint = "sql" if source is SourceType.CODE else "markdown"
        packets = detector.detect(text, source_type=source, language_hint=hint)
        if not packets:
            continue
        claim = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        record = store.persist_verdict(
            verdict, source_hash=claim.source_hash, pattern_types=claim.packet_types
        )
        bundles = list(memory.system_memory.get("guardian.brain.bundles", []))
        bundles.append(linker.build_bundle(record).to_dict())
        memory.set_system_value("guardian.brain.bundles", bundles)

    return memory


def _build_memory_with_duplicate_evidence() -> MemoryLayer:
    """
    Inject two bundles that share the same evidence_node_id
    (same source_hash prefix), so compaction has actual duplicates to find.
    """
    memory = MemoryLayer()
    identical_text = "' UNION SELECT username, password FROM users --"
    store = AuditStore(memory)
    detector = InjectionDetector()
    adapter = LasuchGuardianAdapter()
    gate = EvidenceGate()
    linker = BrainLinker()

    # Process the same payload twice — same content = same source_hash[:16]
    for _ in range(2):
        packets = detector.detect(identical_text, source_type=SourceType.CODE, language_hint="sql")
        claim = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        record = store.persist_verdict(
            verdict, source_hash=claim.source_hash, pattern_types=claim.packet_types
        )
        bundles = list(memory.system_memory.get("guardian.brain.bundles", []))
        bundles.append(linker.build_bundle(record).to_dict())
        memory.set_system_value("guardian.brain.bundles", bundles)

    return memory


# ---------------------------------------------------------------------------
# TestAnalyse
# ---------------------------------------------------------------------------

class TestAnalyse:
    def setup_method(self):
        self.memory = _build_memory_with_bundles(6)
        self.compactor = BrainCompactor(self.memory)

    def test_returns_compaction_report(self):
        report = self.compactor.analyse()
        assert isinstance(report, CompactionReport)

    def test_total_bundles_matches_live_store(self):
        live_count = len(self.memory.system_memory.get("guardian.brain.bundles", []))
        report = self.compactor.analyse()
        assert report.total_bundles == live_count

    def test_unique_evidence_ids_lte_total(self):
        report = self.compactor.analyse()
        assert report.unique_evidence_ids <= report.total_bundles

    def test_savings_potential_in_range(self):
        report = self.compactor.analyse()
        assert 0.0 <= report.savings_potential_pct <= 100.0

    def test_analyse_does_not_write_snapshots(self):
        before = list(self.memory.system_memory.get("guardian.brain.compaction.snapshots", []))
        self.compactor.analyse()
        after = list(self.memory.system_memory.get("guardian.brain.compaction.snapshots", []))
        assert len(after) == len(before)

    def test_analyse_does_not_write_compacted(self):
        self.compactor.analyse()
        assert "guardian.brain.compacted" not in self.memory.system_memory

    def test_dry_run_flag_is_true(self):
        report = self.compactor.analyse()
        assert report.dry_run is True

    def test_snapshot_key_is_none(self):
        report = self.compactor.analyse()
        assert report.snapshot_key is None

    def test_evidence_groups_keys_are_strings(self):
        report = self.compactor.analyse()
        for key in report.evidence_groups:
            assert isinstance(key, str)

    def test_evidence_groups_values_are_lists(self):
        report = self.compactor.analyse()
        for v in report.evidence_groups.values():
            assert isinstance(v, list)


# ---------------------------------------------------------------------------
# TestSnapshot
# ---------------------------------------------------------------------------

class TestSnapshot:
    def setup_method(self):
        self.memory = _build_memory_with_bundles(4)
        self.compactor = BrainCompactor(self.memory)

    def test_snapshot_returns_string_key(self):
        key = self.compactor.snapshot()
        assert isinstance(key, str)

    def test_snapshot_key_contains_prefix(self):
        key = self.compactor.snapshot()
        assert "guardian.brain.compaction.snapshots/" in key

    def test_snapshot_written_to_memory(self):
        self.compactor.snapshot()
        snaps = self.memory.system_memory.get("guardian.brain.compaction.snapshots", [])
        assert len(snaps) == 1

    def test_snapshot_accumulates_on_multiple_calls(self):
        self.compactor.snapshot()
        self.compactor.snapshot()
        self.compactor.snapshot()
        snaps = self.memory.system_memory.get("guardian.brain.compaction.snapshots", [])
        assert len(snaps) == 3

    def test_snapshot_bundle_count_matches_live(self):
        live_count = len(self.memory.system_memory.get("guardian.brain.bundles", []))
        self.compactor.snapshot()
        snaps = self.memory.system_memory.get("guardian.brain.compaction.snapshots", [])
        assert snaps[0]["bundle_count"] == live_count

    def test_snapshot_has_required_fields(self):
        self.compactor.snapshot()
        snap = self.memory.system_memory["guardian.brain.compaction.snapshots"][0]
        for field in ("key", "timestamp", "bundle_count", "bundles"):
            assert field in snap

    def test_snapshot_does_not_modify_live_bundles(self):
        before = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        self.compactor.snapshot()
        after = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        assert len(before) == len(after)

    def test_list_snapshots_returns_metadata_only(self):
        self.compactor.snapshot()
        snaps = self.compactor.list_snapshots()
        assert len(snaps) == 1
        assert "bundles" not in snaps[0]  # payload excluded from metadata list
        for key in ("key", "timestamp", "bundle_count"):
            assert key in snaps[0]


# ---------------------------------------------------------------------------
# TestCompactDryRun
# ---------------------------------------------------------------------------

class TestCompactDryRun:
    def setup_method(self):
        self.memory = _build_memory_with_bundles(6)
        self.compactor = BrainCompactor(self.memory)

    def test_returns_compaction_report(self):
        report = self.compactor.compact()
        assert isinstance(report, CompactionReport)

    def test_dry_run_flag_is_true_by_default(self):
        report = self.compactor.compact()
        assert report.dry_run is True

    def test_snapshot_key_is_set(self):
        report = self.compactor.compact()
        assert report.snapshot_key is not None

    def test_snapshot_written_to_memory(self):
        self.compactor.compact()
        snaps = self.memory.system_memory.get("guardian.brain.compaction.snapshots", [])
        assert len(snaps) == 1

    def test_compacted_key_not_written_in_dry_run(self):
        self.compactor.compact(dry_run=True)
        assert "guardian.brain.compacted" not in self.memory.system_memory

    def test_live_bundles_unchanged(self):
        before = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        self.compactor.compact()
        after = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        assert len(before) == len(after)


# ---------------------------------------------------------------------------
# TestCompactLive
# ---------------------------------------------------------------------------

class TestCompactLive:
    def setup_method(self):
        self.memory = _build_memory_with_bundles(6)
        self.compactor = BrainCompactor(self.memory)

    def test_returns_compaction_report(self):
        report = self.compactor.compact(dry_run=False)
        assert isinstance(report, CompactionReport)

    def test_dry_run_flag_is_false(self):
        report = self.compactor.compact(dry_run=False)
        assert report.dry_run is False

    def test_compacted_key_written(self):
        self.compactor.compact(dry_run=False)
        assert "guardian.brain.compacted" in self.memory.system_memory

    def test_compacted_has_required_fields(self):
        self.compactor.compact(dry_run=False)
        compacted = self.memory.system_memory["guardian.brain.compacted"]
        for key in ("compacted_at", "source_bundle_count", "node_count", "edge_count",
                    "graph_hash", "nodes", "edges"):
            assert key in compacted

    def test_compacted_source_bundle_count_matches(self):
        live_count = len(self.memory.system_memory.get("guardian.brain.bundles", []))
        self.compactor.compact(dry_run=False)
        compacted = self.memory.system_memory["guardian.brain.compacted"]
        assert compacted["source_bundle_count"] == live_count

    def test_compacted_node_count_gte_3(self):
        self.compactor.compact(dry_run=False)
        compacted = self.memory.system_memory["guardian.brain.compacted"]
        assert compacted["node_count"] >= 3

    def test_compacted_graph_hash_is_hex_string(self):
        self.compactor.compact(dry_run=False)
        compacted = self.memory.system_memory["guardian.brain.compacted"]
        h = compacted["graph_hash"]
        assert isinstance(h, str)
        int(h, 16)  # must be valid hex

    def test_get_compacted_returns_dict(self):
        self.compactor.compact(dry_run=False)
        result = self.compactor.get_compacted()
        assert isinstance(result, dict)

    def test_get_compacted_before_live_compact_returns_none(self):
        fresh_compactor = BrainCompactor(MemoryLayer())
        assert fresh_compactor.get_compacted() is None

    def test_live_bundles_still_unchanged(self):
        before = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        self.compactor.compact(dry_run=False)
        after = list(self.memory.system_memory.get("guardian.brain.bundles", []))
        assert len(before) == len(after)


# ---------------------------------------------------------------------------
# TestDuplicateDetection
# ---------------------------------------------------------------------------

class TestDuplicateDetection:
    def setup_method(self):
        self.memory = _build_memory_with_duplicate_evidence()
        self.compactor = BrainCompactor(self.memory)

    def test_detects_shared_evidence_node(self):
        report = self.compactor.analyse()
        # Two bundles from the same payload share the same evidence node id
        assert report.unique_evidence_ids < report.total_bundles

    def test_duplicate_bundle_count_positive(self):
        report = self.compactor.analyse()
        assert report.duplicate_bundle_count >= 1

    def test_savings_potential_positive(self):
        report = self.compactor.analyse()
        assert report.savings_potential_pct > 0.0

    def test_compact_deduplicates_evidence_nodes(self):
        self.compactor.compact(dry_run=False)
        compacted = self.compactor.get_compacted()
        # Compacted graph should have fewer nodes than 3*bundle_count
        assert compacted["node_count"] < compacted["source_bundle_count"] * 3


# ---------------------------------------------------------------------------
# TestEmptyStore
# ---------------------------------------------------------------------------

class TestEmptyStore:
    def setup_method(self):
        self.compactor = BrainCompactor(MemoryLayer())

    def test_analyse_on_empty_memory(self):
        report = self.compactor.analyse()
        assert report.total_bundles == 0
        assert report.unique_evidence_ids == 0
        assert report.savings_potential_pct == 0.0

    def test_snapshot_on_empty_memory(self):
        key = self.compactor.snapshot()
        assert isinstance(key, str)

    def test_compact_dry_run_on_empty_memory(self):
        report = self.compactor.compact()
        assert report.total_bundles == 0

    def test_compact_live_on_empty_memory(self):
        report = self.compactor.compact(dry_run=False)
        compacted = self.compactor.get_compacted()
        assert compacted is not None
        assert compacted["node_count"] == 0


# ---------------------------------------------------------------------------
# TestContractPreservation
# ---------------------------------------------------------------------------

class TestContractPreservation:
    """
    Verify the frozen v1.0 contract is not broken by compaction:
      len(guardian.brain.bundles) == len(guardian.audit.timeline)
    """

    def test_live_bundles_equal_timeline_after_compact_dry_run(self):
        memory = _build_memory_with_bundles(6)
        compactor = BrainCompactor(memory)
        compactor.compact(dry_run=True)

        bundles = memory.system_memory.get("guardian.brain.bundles", [])
        timeline = memory.system_memory.get("guardian.audit.timeline", [])
        assert len(bundles) == len(timeline)

    def test_live_bundles_equal_timeline_after_compact_live(self):
        memory = _build_memory_with_bundles(6)
        compactor = BrainCompactor(memory)
        compactor.compact(dry_run=False)

        bundles = memory.system_memory.get("guardian.brain.bundles", [])
        timeline = memory.system_memory.get("guardian.audit.timeline", [])
        assert len(bundles) == len(timeline)

    def test_snapshot_does_not_inflate_timeline(self):
        memory = _build_memory_with_bundles(4)
        before_timeline = len(memory.system_memory.get("guardian.audit.timeline", []))
        BrainCompactor(memory).snapshot()
        after_timeline = len(memory.system_memory.get("guardian.audit.timeline", []))
        assert before_timeline == after_timeline
