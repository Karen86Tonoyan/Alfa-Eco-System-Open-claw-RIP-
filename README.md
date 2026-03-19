# ALFA Proof Repo

`ALFA` is a control layer that sits on top of existing LLMs. It adds routing, risk evaluation, guarded execution, auditability, and a clear separation between voice, decision, memory, and execution.

This repository is a **public proof repo**. It shows how the public control plane works and proves that the filters, execution gate, and demo scenarios are real. It does **not** publish the full operational core.

## What This Repo Proves

- `Filtry Tonoyana` can be expressed as a decision pipeline, not just as narrative.
- `Voice -> Brain -> Filters -> Cerber -> Plugin/Response` works as a coherent flow.
- The system is designed to operate across `local (Ollama)` and `cloud` channels.
- Guarded orchestration can approve, block, clarify, or escalate before action.

## Public Positioning

`ALFA is a ready control layer that can be placed over existing LLMs.`

This repo is intentionally selective:

- Public: architecture, proof code, public wrappers, demo flow, tests.
- Private / B2B: production policy sets, operational execution logic, connector internals, fallback chains, and sensitive enforcement mechanisms.

The goal is credibility without giving away the full execution core.

## Architecture

```text
VOICE
  ->
BRAIN
  ->
FILTERS
  ->
CERBER
  ->
PLUGIN / RESPONSE
  ->
MEMORY + AUDIT
```

High-level roles:

- `Voice` handles transcripts and wake-word normalization.
- `Brain` handles intent, risk, routing, and state.
- `Filters` translate empathy, ambiguity, and intent into structured decisions.
- `Cerber` is the execution gate before any plugin acts.
- `Plugins` are constrained tools, not autonomous agents.
- `Memory` separates session, user, system, audit, and cache state.
- `Backends` expose local and cloud readiness without leaking private orchestration.

## Supported Deployment Modes

- `Ollama` as a local model channel preview.
- `Cloud` as a managed model channel preview.

This public repo exposes capability boundaries and interface stubs only. Production routing and operational connectors are intentionally withheld.

## Quick Start

Run the demo:

```powershell
python .\alfa_demo.py
```

Run the tests:

```powershell
python -m pytest .\tests -q
```

## Repo Layout

```text
ALFA_PROOF_REPO/
├── src/alfa/
├── docs/
├── tests/
├── alfa_demo.py
├── README.md
├── LICENSE
├── NOTICE
├── CONTRIBUTING.md
└── SECURITY.md
```

## IP and Access Model

This repository is `source-available / B2B-first`.

- The public code is provided for review, evaluation, and demonstration.
- Copyright, trademarks, and core operational know-how remain protected.
- Selected deeper modules are available only through partner access or commercial collaboration.

See:

- [IP_AND_ACCESS_MODEL](docs/IP_AND_ACCESS_MODEL.md)
- [SECURITY_DISCLOSURE_BOUNDARY](docs/SECURITY_DISCLOSURE_BOUNDARY.md)
- [ARCHITECTURE](docs/ARCHITECTURE.md)
- [ALFA_WOW_DEMO](docs/ALFA_WOW_DEMO.md)
- [VALIDATED_LINEAGE](docs/VALIDATED_LINEAGE.md)
- [README_PL](docs/README_PL.md)
- [BIELIK_PARTNERSHIP](docs/BIELIK_PARTNERSHIP.md)

## Why The Repo Is Selective

This repo is meant to show:

- the filters,
- the decision layer,
- the execution gate,
- the local + cloud deployment shape,
- and that the system really works.

It is not meant to publish:

- production connector internals,
- operational security thresholds,
- anti-loop internals,
- full execution policy logic,
- or private commercial integrations.

`Security, IP, and real operational control come before publicity.`
