from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from alfa.guard.guardian.types import EvidenceVerdict
from alfa.memory.layer import MemoryLayer


@dataclass(frozen=True, slots=True)
class StoredVerdictRecord:
    threat_id: str
    source_hash: str
    pattern_types: tuple[str, ...]
    verdict: EvidenceVerdict
    evidence_refs: tuple[str, ...]
    audit_trail: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "source_hash": self.source_hash,
            "pattern_types": list(self.pattern_types),
            "verdict": self.verdict.to_dict(),
            "evidence_refs": list(self.evidence_refs),
            "audit_trail": [dict(item) for item in self.audit_trail],
        }


class AuditStore:
    def __init__(self, memory: MemoryLayer | None = None) -> None:
        self._memory = memory or MemoryLayer()
        self._records: list[StoredVerdictRecord] = []

    @property
    def memory(self) -> MemoryLayer:
        return self._memory

    def persist_verdict(
        self,
        verdict: EvidenceVerdict,
        *,
        source_hash: str,
        pattern_types: list[str] | tuple[str, ...],
    ) -> StoredVerdictRecord:
        record = StoredVerdictRecord(
            threat_id=verdict.claim_id,
            source_hash=source_hash,
            pattern_types=tuple(pattern_types),
            verdict=verdict,
            evidence_refs=tuple(verdict.evidence_refs),
            audit_trail=tuple(dict(item) for item in verdict.audit_trail),
        )
        self._records.append(record)
        self._remember_record(record)
        return record

    def query_by_threat_id(self, threat_id: str) -> list[StoredVerdictRecord]:
        return [record for record in self._records if record.threat_id == threat_id]

    def query_by_source_hash(self, source_hash: str) -> list[StoredVerdictRecord]:
        return [record for record in self._records if record.source_hash == source_hash]

    def query_by_pattern_type(self, pattern_type: str) -> list[StoredVerdictRecord]:
        return [
            record
            for record in self._records
            if pattern_type in record.pattern_types
        ]

    def all_records(self) -> list[StoredVerdictRecord]:
        return list(self._records)

    def _remember_record(self, record: StoredVerdictRecord) -> None:
        timeline = list(self._memory.system_memory.get("guardian.audit.timeline", []))
        timeline.append(record.to_dict())
        self._memory.set_system_value("guardian.audit.timeline", timeline)

        by_threat = dict(self._memory.system_memory.get("guardian.audit.by_threat_id", {}))
        by_threat.setdefault(record.threat_id, []).append(record.to_dict())
        self._memory.set_system_value("guardian.audit.by_threat_id", by_threat)

        by_source = dict(self._memory.system_memory.get("guardian.audit.by_source_hash", {}))
        by_source.setdefault(record.source_hash, []).append(record.to_dict())
        self._memory.set_system_value("guardian.audit.by_source_hash", by_source)
