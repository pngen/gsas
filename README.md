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
│         GSAS Governance Substrate   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Determinist │  │ Authority   │   │
│  │ Execution   │  │ Realization │   │
│  └─────────────┘  └─────────────┘   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Jurisdiction│  │ Capital     │   │
│  │ Enforcement │  │ Accounting  │   │
│  └─────────────┘  └─────────────┘   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Containment │  │ Evaluation  │   │
│  │ & Safety    │  │ Engine      │   │
│  └─────────────┘  └─────────────┘   │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│     Governance Primitives Layer     │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Execution   │  │ Authority   │   │
│  │ Engine      │  │ System      │   │
│  └─────────────┘  └─────────────┘   │
│                                     │
│  ┌─────────────┐  ┌─────────────┐   │
│  │ Jurisdiction│  │ Capital     │   │
│  │ System      │  │ Accounting  │   │
│  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────┘
</pre>

## Components

### Governance Evaluation Engine  
Evaluates all governance primitives in strict sequence. Integrated into autonomous systems as a mandatory pre-execution gate. If all constraints pass, execution proceeds; otherwise, it fails closed with a structured proof.

### Composite Proof Generator  
Produces structured, cryptographically verifiable proofs for every evaluation. Proofs are reconstructable without runtime access using SHA-256 commitment properties.

### Composition Operators  
Compose multiple governance primitives with explicit semantics. Primitive contracts are type-safe and validated at registration time. Versioned contracts support long-term compatibility.

### Determinism Enforcer  
Ensures all primitives are deterministic and reproducible. Immutable execution contexts with no mutable state across calls, no system time reads, no filesystem or network access, and no unseeded randomness.

### Compliance Checker  
Validates that primitives and deployments satisfy their contracts. Detects violations at registration time rather than at runtime.

### Failure Handler  
Enforces fail-closed behavior on any missing or violated governance signal. Emits structured failures with full context for downstream analysis. No partial compliance.

## Build
```bash
go build -o gsas ./cmd/gsas/
```

On Windows:
```bash
go build -o gsas.exe ./cmd/gsas/
```

## Test
```bash
go get -t gsas/tests
go test ./tests/...
```

## Run
```bash
./gsas
```

On Windows:
```bash
.\gsas.exe
```

## Design Principles
1. **Compositional** - Integrates existing primitives without weakening semantics.
2. **Deterministic** - All evaluations are deterministic, reproducible, and explainable.
3. **Fail-Closed** - No partial compliance. All governance signals must be satisfied.
4. **Auditable** - Proofs are reconstructable without runtime access.
5. **Non-Interfering** - Does not mutate or assume ownership of underlying systems.
6. **Type-Safe** - Strong typing ensures contract compliance at registration time.

## Requirements
- Go 1.21+
- All governance primitives enforced in strict sequence
- Structured proofs emitted for every evaluation
- Primitive semantics never reinterpreted or overridden