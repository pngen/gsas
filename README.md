# Governance Substrate for Autonomous Systems (GSAS)

A deterministic, composable governance substrate that enforces institutional constraints on autonomous systems without duplicating or overriding existing governance logic.

## Overview

GSAS is an infrastructure layer that binds autonomous systems to institutional reality by enforcing governance invariants. It does not execute, interpret, or orchestrate; it composes and enforces existing governance primitives.

GSAS operates below applications and agents but above infrastructure, ensuring all execution adheres to institutional constraints without being intrusive.

## Architecture

<pre>
┌─────────────────────────────────────┐
│        Autonomous System            │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│     GSAS Governance Substrate       │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Governance  │  │ Primitive   │   │
│  │ Engine      │  │ Composer    │   │
│  └─────────────┘  └─────────────┘   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │Deterministic│  │ Proof       │   │
│  │ Context     │  │ Generator   │   │
│  └─────────────┘  └─────────────┘   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Compliance  │  │ Determinism │   │
│  │ Checker     │  │ Enforcer    │   │
│  └─────────────┘  └─────────────┘   │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│   External Governance Primitives    │
│      (User-provided via API)        │
└─────────────────────────────────────┘
</pre>

## Components

### Governance Evaluation Engine  
Evaluates all governance primitives in strict sequence. Integrated into autonomous systems as a mandatory pre-execution gate. If all constraints pass, execution proceeds; otherwise, it fails closed with a structured proof.

### Composite Proof Generator  
Produces structured, tamper-evident proof envelopes for every evaluation. Embedded signal and context snapshots allow envelope integrity to be checked without access to the original runtime. These SHA-256 commitments do not authenticate an issuer or independently prove that an external primitive's implementation was trustworthy.

### Composition Operators  
Compose multiple governance primitives with explicit semantics. Primitive contracts are type-safe and validated at registration time. Versioned contracts support long-term compatibility.

### Determinism Enforcer  
Uses immutable, losslessly copied execution contexts, context logical time, repeat-evaluation checks, and conservative source validation when a primitive exposes source. GSAS does not sandbox already-compiled in-process Go code: callers must treat unsourced primitive implementations as trusted code and isolate untrusted policies outside this process.

### Compliance Checker  
Validates non-empty deployments, primitive identity, result schema, static composition configuration, and repeatability. Registration runs the same checks, while evaluation rechecks version/source identity and fails closed on drift, panic, malformed output, or non-repeatable output.

### Failure Handler  
Enforces fail-closed behavior on empty policy sets, nil or invalid contexts, missing or violated signals, and proof-generation failures. Emits structured failures with committed context for downstream analysis. No partial compliance.

## Build

```bash
go build ./...
```

## Test

```bash
go get -t gsas/tests

go test ./tests/... -v
```

## Run

```bash
go build ./...
./gsas # Linux/macOS
.\gsas.exe # Windows
```

`cmd/gsas` is the supervised AIGOS layer process: it emits the canonical startup line and remains alive until the supervisor terminates it.

## Runtime model

Integrate `core.GovernanceEngine` as a mandatory in-process pre-execution gate in hosts that need governance enforcement. The standalone layer process provides the AIGOSD-supervised runtime presence.

## Design Principles

1. **Compositional** - Integrates existing primitives without weakening semantics.
2. **Deterministic** - Contexts and proof envelopes are reproducible; primitives are checked for repeatability and unsourced compiled code remains a documented trust boundary.
3. **Fail-Closed** - No partial compliance. All governance signals must be satisfied.
4. **Auditable** - Proof envelope integrity is independently recomputable from its embedded snapshots.
5. **Non-Interfering** - Does not mutate or assume ownership of underlying systems.
6. **Type-Safe** - Strong typing ensures contract compliance at registration time.

## Requirements

- Go 1.21+
