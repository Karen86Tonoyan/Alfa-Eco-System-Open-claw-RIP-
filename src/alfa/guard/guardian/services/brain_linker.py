from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit_store import StoredVerdictRecord


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    node_type: str
    label: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    edge_id: str
    source_id: str
    target_id: str
    relation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
        }


@dataclass(frozen=True, slots=True)
class BrainEvidenceBundle:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }


class BrainLinker:
    def build_bundle(self, record: StoredVerdictRecord) -> BrainEvidenceBundle:
        threat_node_id = f"threat:{record.threat_id}"
        evidence_node_id = f"evidence:{record.source_hash[:16]}"
        verdict_node_id = f"verdict:{record.threat_id}"

        threat_node = GraphNode(
            node_id=threat_node_id,
            node_type="threat",
            label="Threat Claim",
            payload={
                "threat_id": record.threat_id,
                "pattern_types": list(record.pattern_types),
                "source_hash": record.source_hash,
            },
        )
        evidence_node = GraphNode(
            node_id=evidence_node_id,
            node_type="evidence",
            label="Evidence Packet",
            payload={
                "evidence_refs": list(record.evidence_refs),
                "audit_count": len(record.audit_trail),
            },
        )
        verdict_node = GraphNode(
            node_id=verdict_node_id,
            node_type="verdict",
            label="Guardian Verdict",
            payload=record.verdict.to_dict(),
        )

        edges = (
            GraphEdge(
                edge_id=f"{threat_node_id}->{evidence_node_id}",
                source_id=threat_node_id,
                target_id=evidence_node_id,
                relation="supported_by",
            ),
            GraphEdge(
                edge_id=f"{evidence_node_id}->{verdict_node_id}",
                source_id=evidence_node_id,
                target_id=verdict_node_id,
                relation="produced",
            ),
        )

        return BrainEvidenceBundle(
            nodes=(threat_node, evidence_node, verdict_node),
            edges=edges,
        )
