# Security Disclosure Boundary

This repository is designed to reveal outcomes and architecture, not sensitive internals.

## Publicly shown

- decision flow,
- state changes,
- guard approval or block behavior,
- plugin contracts and safe stubs,
- public deployment shape for local and cloud modes.

## Intentionally withheld

- exact operational heuristics,
- private execution channels,
- production connector logic,
- policy thresholds used in protected environments,
- sensitive fallback and anti-abuse internals.

## Why this boundary exists

Security, IP protection, and operational integrity matter more than maximal disclosure.
The public repo should make the system credible without making the protected core trivial to replicate or bypass.

