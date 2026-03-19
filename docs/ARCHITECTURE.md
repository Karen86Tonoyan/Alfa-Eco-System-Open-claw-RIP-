# ALFA Public Proof Architecture

## Core Rule

Brain thinks.  
Filters structure intent and risk.  
Cerber evaluates execution.  
Plugin acts only after approval.  
Voice is an interface, not the command center.  
Memory remembers and audits.

## Public Flow

```text
Voice / Text Input
  ->
Brain
  ->
Filters
  ->
Cerber
  ->
Plugin or Response
  ->
Memory + Audit
```

## Public Modules

- `core`
  Intent detection, risk framing, routing, and state changes.
- `voice`
  Wake-word normalization and transcript-to-request conversion.
- `plugins`
  Safe contracts and public stubs for lookup and gated execution.
- `guard`
  Public preview of the Cerber execution gate.
- `memory`
  Session, user, system, cache, and audit stores.
- `backends`
  Public preview layer for local and cloud deployment readiness.
- `console`
  CLI-facing orchestration and proof demo output.

## What This Repo Does Not Include

- private connector internals,
- production routing logic between model providers,
- exact operational thresholds and enforcement variants,
- full execution runners,
- fallback chains and protected partner modules.

This is deliberate. The repo proves the control plane without exporting the private operational core.

