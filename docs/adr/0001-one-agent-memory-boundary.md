# ADR 0001: One Agent Behind a Deterministic Memory Boundary

- Status: Accepted
- Date: 2026-08-15

## Context

Gluevenir Bio must demonstrate useful persistent memory without making a model
the authority for memory access. A relevant memory may still be ineligible for
the caller's tenant, program, purpose, audience, destination, approval, or
lifecycle state. The architecture therefore needs one enforceable boundary
before memory can be stored, recalled, used, shared, revoked, or forgotten.

The shipped application is a single-agent demonstration. A second autonomous
"guard" agent would add another probabilistic decision-maker, tool surface, and
failure mode without creating a stronger authorization boundary.

## Decision

Gluevenir Bio runs one runtime/demo agent. Every supported public SDK memory
operation constructs a typed action envelope and enters the same deterministic
Memory Action Gateway before any storage access, model-context assembly, or
external use. The gateway evaluates bounded intent and prior-action context and
returns exactly one decision: `ALLOW`, `DENY`, `MODIFY`, `STEP_UP`, or `DEFER`.

Storage and model adapters are internal implementation ports, not public
bypasses. Policies, human approvals, database access, MCP and other tools,
detectors, and receipt-signature verification are controls or tools around the
single agent; they are not additional agents. The model may explain evidence or
draft a proposed derivative, but deterministic code controls authorization and
only a human may approve the exact derivative.

The boundary fails closed. Missing or invalid policy or context, unavailable
evaluation, invalid signatures, unresolved decisions, timeouts, and model or
tool failures cannot broaden access. `STEP_UP` and `DEFER` have no side effects
before resolution and time out to `DENY`. `MODIFY` may substitute only an exact,
active, hash-verified human-approved Safe Derivative.

Each evaluated supported memory action produces a content-safe, canonical,
per-agent Ed25519-signed Recall Receipt. The supported claim is that receipts
are signed, content-bound, and independently verifiable within the documented
development-key trust model.

## Consequences

- One gateway provides a testable interception point for every supported public
  memory operation and keeps authorization separate from vector relevance.
- The framework must test that public methods cannot reach storage or model
  adapters without gateway evaluation and that failures have no unauthorized
  side effects.
- Pending approval and missing-context flows require explicit resolution state,
  timeout handling, and separate resolution receipts.
- Build-time sub-agents may help develop the repository under its coordination
  rules, but they do not change the shipped one-agent architecture.

## Rejected alternative: a guard agent

A separate guard agent was rejected because an LLM cannot be the authority that
weakens policy or approves its own derivative. Adding one would increase cost,
latency, orchestration complexity, prompt-injection exposure, and ambiguity over
which agent owns a decision. Deterministic policy plus explicit human approval
is smaller, fail-closed, and directly testable.

## Claim boundary

Gluevenir is **AARM-inspired** and maps evidence only for supported
memory-mediated SDK actions. This decision does not establish universal agent
interception, AARM conformance or certification, AIUC-1 readiness, HIPAA
compliance, clinical validation, legal classification, or guaranteed sensitive-
data detection. The demo uses synthetic data, and automated detection is
imperfect. Signature integrity does not protect against an administrator who
controls both storage and the signing key.
