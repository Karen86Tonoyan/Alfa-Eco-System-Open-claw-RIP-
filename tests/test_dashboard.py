from __future__ import annotations

import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from alfa.console.dashboard import ALFADashboard
from alfa.guard.guardian import AuditStore, EvidenceGate
from alfa.guard.lasuch import InjectionDetector, LasuchGuardianAdapter, SourceType
from alfa.memory.layer import MemoryLayer

from tests.adversarial_payloads import PROMPT_INJECTION_PAYLOADS, SQL_INJECTION_PAYLOADS


def _populate(store: AuditStore, memory: MemoryLayer, *, n: int = 10) -> None:
    """Push n verdicts through the real pipeline into store."""
    detector = InjectionDetector()
    adapter  = LasuchGuardianAdapter()
    gate     = EvidenceGate()

    payloads = list(SQL_INJECTION_PAYLOADS[:n // 2]) + list(PROMPT_INJECTION_PAYLOADS[:n // 2])
    for text in payloads:
        source = SourceType.CODE if "union" in text.lower() or "sleep(" in text.lower() else SourceType.PROMPT
        packets = detector.detect(text, source_type=source, language_hint="sql" if source is SourceType.CODE else "markdown")
        if not packets:
            continue
        claim   = adapter.to_guardian_claim(packets)
        verdict = gate.consume(claim)
        store.persist_verdict(verdict, source_hash=claim.source_hash, pattern_types=claim.packet_types)

        # Simulate brain bundle in memory
        bundles = list(memory.system_memory.get("guardian.brain.bundles", []))
        bundles.append({
            "threat_id":      verdict.claim_id,
            "evidence_nodes": [{"id": e} for e in verdict.evidence_refs],
            "verdict_nodes":  [{"status": verdict.status.value}],
        })
        memory.set_system_value("guardian.brain.bundles", bundles)


# ---------------------------------------------------------------------------
# Snapshot structure
# ---------------------------------------------------------------------------

class TestDashboardSnapshot:
    def test_snapshot_returns_all_sections(self):
        store  = AuditStore()
        memory = MemoryLayer()
        db     = ALFADashboard(store, memory)

        snap = db.snapshot()
        assert snap.threats   is not None
        assert snap.decisions is not None
        assert snap.brain     is not None
        assert snap.audit     is not None

    def test_empty_store_gives_zero_counts(self):
        db   = ALFADashboard(AuditStore(), MemoryLayer())
        snap = db.snapshot()

        assert snap.threats.total_verdicts    == 0
        assert snap.decisions.total           == 0
        assert snap.brain.total_bundles       == 0
        assert snap.audit.total_events        == 0

    def test_to_dict_has_expected_keys(self):
        db   = ALFADashboard(AuditStore(), MemoryLayer())
        d    = db.snapshot().to_dict()

        assert set(d) == {"threats", "decisions", "brain", "audit"}
        assert "deny_rate" in d["decisions"]
        assert "avg_risk"  in d["decisions"]


# ---------------------------------------------------------------------------
# After population
# ---------------------------------------------------------------------------

class TestDashboardWithData:
    def setup_method(self):
        self.store  = AuditStore()
        self.memory = MemoryLayer()
        _populate(self.store, self.memory, n=10)
        self.db = ALFADashboard(self.store, self.memory)

    def test_threats_counts_match_store(self):
        snap = self.db.snapshot()
        assert snap.threats.total_verdicts == len(self.store.all_records())
        assert snap.threats.unique_threat_ids > 0
        assert snap.threats.unique_sources    > 0

    def test_decisions_total_matches_verdicts(self):
        snap = self.db.snapshot()
        assert snap.decisions.total == snap.threats.total_verdicts
        assert snap.decisions.allow_count + snap.decisions.deny_count + snap.decisions.hold_count == snap.decisions.total

    def test_deny_rate_between_0_and_1(self):
        snap = self.db.snapshot()
        assert 0.0 <= snap.decisions.deny_rate <= 1.0

    def test_avg_risk_between_0_and_1(self):
        snap = self.db.snapshot()
        assert 0.0 <= snap.decisions.avg_risk_score <= 1.0

    def test_pattern_breakdown_is_populated(self):
        snap = self.db.snapshot()
        assert len(snap.threats.pattern_breakdown) > 0

    def test_brain_bundles_counted(self):
        snap = self.db.snapshot()
        assert snap.brain.total_bundles > 0
        assert snap.brain.total_evidence_nodes >= 0
        assert snap.brain.total_verdict_nodes  >= 0

    def test_top_threat_id_present(self):
        snap = self.db.snapshot()
        assert snap.threats.top_threat_id is not None


# ---------------------------------------------------------------------------
# Text render
# ---------------------------------------------------------------------------

class TestDashboardRenderText:
    def test_render_contains_section_headers(self):
        store  = AuditStore()
        memory = MemoryLayer()
        _populate(store, memory, n=6)
        text = ALFADashboard(store, memory).render_text()

        assert "ALFA DASHBOARD" in text
        assert "Threats"   in text
        assert "Decisions" in text
        assert "Brain"     in text
        assert "Audit"     in text

    def test_render_deny_rate_formatted_as_percent(self):
        store  = AuditStore()
        memory = MemoryLayer()
        _populate(store, memory, n=6)
        text = ALFADashboard(store, memory).render_text()

        assert "%" in text
