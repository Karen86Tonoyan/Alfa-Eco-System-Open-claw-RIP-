# Security Policy

## Scope of this repository

This is a **public proof-of-concept** repository. It demonstrates the decision flow, filter chain, and guard behavior of the ALFA control layer. It intentionally omits private execution internals, production connectors, and operational security thresholds.

See [`docs/SECURITY_DISCLOSURE_BOUNDARY.md`](docs/SECURITY_DISCLOSURE_BOUNDARY.md) for a full list of what is and is not disclosed.

---

## Trust model

ALFA distinguishes two request origins. Trust is assigned by the **system layer**, not by the caller.

### Public input (`from_public_input`)

Used for all requests arriving from end users or untrusted external sources.

- `source_trust` is fixed at `"primary"`.
- Any `confirmed` flag in caller-supplied metadata is **stripped automatically**.
- `trust_origin` is set to `"public_input"` by the constructor.

A public caller cannot elevate their own trust level by adding fields to the request payload.

### Operator approval (`from_operator_approval`)

Used only when a verified operator channel has already authenticated and authorized the request outside this layer.

- `source_trust` is fixed at `"operator"`.
- `confirmed = True` is injected by the constructor, not by the caller.
- `trust_origin` is set to `"operator_approval"`.

The separation means that approval is a **system-level decision**, not a JSON field that can be forged.

### Why this matters for a public repo

This repository is intentionally public. Without enforced constructors, a reader could copy the pattern and build a system where users declare their own trust level in the request body. The named constructors (`from_public_input`, `from_operator_approval`) make that mistake architecturally impossible in correct usage.

---

## What this repo does NOT protect

- There is no authentication layer in this proof repo. `user_id` and `session_id` are not verified.
- The `operator` path here is structural, not cryptographic. Production deployments require a separate auth layer before calling `from_operator_approval`.
- Filter thresholds and Cerber policy details are illustrative, not hardened for production.

---

## Reporting security issues

If you identify:

- a security issue in the public proof code,
- accidental exposure of credentials or private endpoints,
- a pattern that could mislead downstream implementers,
- or a disclosure that should not be public,

report it privately before publishing. Do not post exploit details or proof-of-concept attacks publicly before coordinated review.

Contact: use the business or security channel listed in the project profile, or open a private advisory via GitHub Security Advisories.

