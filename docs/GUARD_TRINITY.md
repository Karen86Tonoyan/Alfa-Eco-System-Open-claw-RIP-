# ALFA Guard Trinity — Architecture & Runtime Contracts

## What this document is

A proof document written at `v1.0-stable` (171 tests passing, contracts frozen).
It describes what the system guarantees, how those guarantees are verified,
and how to inspect the live runtime state.

---

## Pipeline overview

```
User request
    |
    v
InjectionDetector (Lasuch)
    |  detects: PROMPT_INJECTION, SQL_INJECTION, REP, FMI, UNICODE_OBFUSCATION
    v
LasuchGuardianAdapter
    |  converts detector packets -> GuardianClaimInput
    v
EvidenceGate (Guardian)
    |  accumulates evidence, issues EpistemicVerdict: ALLOW / HOLD / DENY
    v
CerberGuard
    |  authorizes or blocks the action
    v
_archive_guardian_evidence()   [ALFAConsole.handle()]
    |
    +-> AuditStore.persist_verdict()
    |       writes to:
    |         guardian.audit.timeline        (ordered log)
    |         guardian.audit.by_threat_id    (lookup index)
    |         guardian.audit.by_source_hash  (dedup index)
    |
    +-> BrainLinker.build_bundle()
            writes to:
              guardian.brain.bundles         (graph snapshots)
```

---

## Frozen runtime contracts

These are verified by `tests/test_e2e_scenario.py` on every run.
Any change that breaks them is detectable immediately.

### Bundle structure (BrainLinker contract)

Every call to `BrainLinker.build_bundle()` produces exactly:

```
nodes: 3
  - node_type: "threat"    node_id: "threat:<claim_id>"
  - node_type: "evidence"  node_id: "evidence:<source_hash[:16]>"
  - node_type: "verdict"   node_id: "verdict:<claim_id>"

edges: 2
  - relation: "supported_by"  threat -> evidence
  - relation: "produced"      evidence -> verdict
```

Verified by: `TestBundleStructureContract` (6 tests)

### Index coherence

```
len(guardian.audit.timeline) == len(guardian.brain.bundles)
len(guardian.audit.timeline) == len(AuditStore.all_records())
timeline[i]["threat_id"] == all_records()[i].threat_id   (order preserved)
by_threat_id[id][-1]["threat_id"] == id                  (cross-ref valid)
by_source_hash[hash][-1]["source_hash"] == hash          (cross-ref valid)
```

Verified by: `TestIndexCoherence` (3 tests), `TestDeterministicSingleRequest` (17 tests)

### Dashboard sync

```
ALFADashboard.snapshot().threats.total_verdicts
  == len(AuditStore.all_records())

ALFADashboard.snapshot().brain.total_evidence_nodes
  == ALFADashboard.snapshot().brain.total_bundles

ALFADashboard.snapshot().brain.total_verdict_nodes
  == ALFADashboard.snapshot().brain.total_bundles
```

Dashboard reads `node_type` from `bundle["nodes"]` — the real
`BrainEvidenceBundle` format. Legacy `evidence_nodes`/`verdict_nodes` keys
are handled via backward-compat fallback in `_brain_summary()`.

Verified by: `TestDeterministicSingleRequest.test_dashboard_*` (5 tests)

### Decision accounting

```
deny_count + allow_count + hold_count == total
0.0 <= deny_rate <= 1.0
0.0 <= avg_risk_score <= 1.0
```

Malicious-heavy load produces `deny_count > allow_count`.

Verified by: `TestMixedLoad` (11 tests)

---

## Memory layout

Three indices are written for every persisted verdict.
This is a conscious trade-off: debuggability over RAM at this stage.

```
guardian.audit.timeline        list[dict]   ordered log, canonical source
guardian.audit.by_threat_id    dict[str, list[dict]]   fast lookup by threat
guardian.audit.by_source_hash  dict[str, list[dict]]   dedup by content hash
guardian.brain.bundles         list[dict]   graph snapshots (nodes + edges)
```

Future evolution path:
```
timeline    -> append-only canonical log  (keep)
by_threat_id, by_source_hash -> ephemeral views rebuildable from timeline
guardian.brain.bundles -> compaction layer with snapshot/merge
```

Compaction is not implemented. It is deferred by design — the audit trail
is currently more valuable as a flat, inspectable log than as an optimised
structure.

---

## Public API

### ALFADashboard

```python
from alfa.bootstrap import build_public_ecosystem
from alfa.console.dashboard import ALFADashboard

eco  = build_public_ecosystem()
db   = ALFADashboard(eco.console.audit_store, eco.memory)
snap = db.snapshot()

snap.threats.total_verdicts      # int
snap.threats.unique_threat_ids   # int
snap.threats.unique_sources      # int
snap.threats.pattern_breakdown   # dict[str, int]
snap.threats.top_threat_id       # str | None

snap.decisions.deny_count        # int
snap.decisions.deny_rate         # float 0.0-1.0
snap.decisions.avg_risk_score    # float 0.0-1.0

snap.brain.total_bundles         # int
snap.brain.total_evidence_nodes  # int  (== total_bundles)
snap.brain.total_verdict_nodes   # int  (== total_bundles)

snap.audit.total_events          # int
snap.audit.last_5                # list[dict]

db.render_text()                 # ASCII report string
```

### dump_trinity (inspection API)

```python
from alfa.console.debug_guard_trinity import dump_trinity

report = dump_trinity(
    memory,
    timeline=True,
    bundles=True,
    indexes=False,
    max_entries=10,
)
# returns str, ASCII-safe, assertable in tests
```

### CLI

```
cd C:\Users\PC\ALFA_WORKSPACE\ecosystem
PYTHONPATH=src python -m alfa.console.debug_guard_trinity --timeline --bundles
PYTHONPATH=src python -m alfa.console.debug_guard_trinity --all
PYTHONPATH=src python -m alfa.console.debug_guard_trinity --timeline --max 5
```

Sample output:

```
============================================================
  ALFA GUARD TRINITY - INSPECTION REPORT
  timeline=4  bundles=4
============================================================
  TIMELINE  (4 entries total, showing 4)
============================================================
  [0] threat_id  : 99adaee3-00c6-418d-8c15-c5488007
      source_hash: 2ca26547d1b5177c698dae8fff24926d
      patterns   : ['PROMPT_INJECTION']
      verdict    : DENY  risk=0.849
  ...
============================================================
  BUNDLES  (4 total, showing 4)
============================================================
  [0] nodes : threat(99adaee3-00c)  evidence(2ca26547d1b5)  verdict(99adaee3-00c)
       edge  : 99adaee3-0 -[supported_by]-> 2ca26547d1
       edge  : 2ca26547d1 -[produced]-> 99adaee3-0
  ...
============================================================
```

---

## Test suite

```
tests/test_e2e_scenario.py        41 tests — canonical proof artifact
tests/test_debug_guard_trinity.py 11 tests — inspection API
tests/test_dashboard.py           12 tests — snapshot + render
tests/test_guardian_load.py       13 tests — burst, accumulation, latency
tests/test_console_service.py      1 test  — end-to-end wiring smoke
                                  --------
                         total:   171 passed (v1.0-stable)
```

### Running

```bash
cd C:\Users\PC\ALFA_WORKSPACE\ecosystem
py -m pytest -q
py -m pytest tests/test_e2e_scenario.py -v
py -m pytest tests/test_e2e_scenario.py::TestDeterministicSingleRequest -v
```

---

## Design decisions recorded

| Decision | Reason |
|---|---|
| Dashboard as frozen dataclass snapshot, not HTTP server | Runtime not finalized; zero new dependencies; fully testable |
| Triple-indexing (timeline + 2 lookup indices) | Debuggability and audit compliance over RAM efficiency |
| Test helpers call real `BrainLinker.build_bundle()` | Eliminates fake-green tests caused by hand-rolled approximations |
| `dump_trinity()` pure function (takes MemoryLayer, returns str) | Importable in tests without CLI side effects |
| ASCII-only output in CLI | Windows cp1250 console compatibility |
| Compaction deferred | Append-only log is more valuable for debugging than optimized structure at this stage |

---

## Workspace layout

```
C:\Users\PC\ALFA_WORKSPACE\
  ecosystem\   this repo — Alfa-Eco-System (src/, tests/, docs/)
  gui\         py-gpt GUI application
  router\      alfa_router.ps1, provider_scoring_engine.ps1
  memory\      history.jsonl, alfa_router.log
```

Tags: `v1.0-rc1` (160 passed, contracts frozen) — `v1.0-stable` (171 passed, migrated)
