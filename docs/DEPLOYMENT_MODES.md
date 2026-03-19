# Deployment Modes

ALFA is designed to sit over existing model channels instead of pretending to be a single monolithic model.

## Local

- public preview name: `ollama_preview`
- role: local runtime channel
- purpose: show that ALFA can govern local model execution paths

## Cloud

- public preview name: `cloud_preview`
- role: managed model endpoint channel
- purpose: show that ALFA can govern remote model execution paths

## Public repo policy

This repository exposes deployment shape and interface boundaries.
It does not expose the production routing logic or private connector internals used behind these channels.

