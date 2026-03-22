# Public Filter Orchestrator Contract

This document describes the public, source-available proof contract for ALFA's filter orchestration layer.

## Scope

This contract is intentionally limited to the public proof repository. It demonstrates:

- normalized request handling,
- filter result aggregation,
- tiered orchestration,
- CORE_LOCK audit logging,
- and deterministic decision outcomes.

It does **not** expose production thresholds, private enforcement policies, or operational connector internals.

## Public Request Model

A request entering the filter orchestrator contains:

- `query`
- `user_id`
- `session_id`
- `timestamp`
- optional `metadata`
- generated or supplied `correlation_id`

Timestamps are normalized to ISO-8601 compatible strings with timezone support.

## Decision Actions

The public contract supports four explicit actions:

- `PROCEED`
- `CLARIFY`
- `ESCALATE`
- `BLOCK`

## Tier Flow

```text
Tier 1 (fast)
  ├─ score < 0.3 -> PROCEED
  └─ else -> deeper analysis

Tier 2 (medium)
  ├─ score < 0.4 -> PROCEED (soft warning)
  └─ else -> Tier 3

Tier 3 (deep)
  ├─ hard_block -> BLOCK + CORE_LOCK log
  ├─ score < 0.3 -> PROCEED
  ├─ score < 0.5 -> CLARIFY
  └─ else -> ESCALATE
```

## Audit Trail

The public logger uses a simple hash chain:

- each entry includes `prev_hash`
- each canonicalized JSON entry produces `entry_hash`
- writes are flushed and fsynced

This is a proof-grade implementation. Production deployments should use append-only or immutable storage.
