# ALFA WOW Demo

## Goal

The demo shows one thing clearly: the model does not act first. ALFA decides first, and Cerber controls execution.

## Run

```powershell
python .\alfa_demo.py
```

Variants:

```powershell
python .\alfa_demo.py --scene hook --scene block --scene approve
python .\alfa_demo.py --pause 1.2
python .\alfa_demo.py --json
```

## What the demo proves

1. `hook`
   A baseline model would answer too quickly.
2. `block`
   ALFA analyzes the request and Cerber blocks execution.
3. `approve`
   Once trust and confirmation are present, the same path can proceed.
4. `notes`
   The system also supports low-risk helpful tasks.

## Video narration

1. "Most AI systems answer first. ALFA decides first."
2. "The request goes through Brain, Filters, and Cerber."
3. "Execution is blocked until the system has enough trust."
4. "When the operator confirms, the workflow can continue."
5. "This repo shows the control layer, not the private orchestration core."

