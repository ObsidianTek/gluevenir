# Honest limitations and failure notes

Status: current pre-release disclosure for the synthetic demonstration.

- **Synthetic-only public endpoint.** The public scenarios use server-mapped,
  fixed synthetic identities. They are not an authentication or authorization
  design for production customers.
- **Imperfect detection.** Deterministic checks and a Bedrock Guardrail reduce
  risk but do not guarantee detection of PII, PHI, confidential information,
  MNPI, or prompt injection. Project labels are policy candidates, not legal
  classifications.
- **Imperfect layered detection.** Microsoft Presidio Analyzer with a pinned
  English spaCy model is integrated alongside deterministic checks in the
  revised runtime image. Offline packaging and fail-closed adapter tests pass;
  the revised live deployment smoke remains pending. Neither layer guarantees
  detection or a legal classification.
- **No ephemeral demo writes.** The public interface exercises governed recall
  against pre-populated synthetic memory. Session-bound user memory with a TTL
  is not implemented; adding it safely requires a server-issued session
  capability and a session predicate in recall.
- **Development signing trust.** Receipts are signed and independently
  verifiable within the development-key trust model. An administrator who
  controls both receipt storage and the signing key remains inside the trust
  boundary.
- **POC rate limiting.** Strict request, scenario, body, model-turn, tool-call,
  and timeout bounds are enforced. The account's Lambda concurrency quota did
  not permit a function-level reservation while retaining AWS's required
  unreserved pool, and Function URLs do not provide a full client rate limiter.
- **MCP is inspection, not enforcement.** CockroachDB Cloud Managed MCP performs
  a bounded read-only inspection of content-safe receipt metadata. It is not a
  guard agent, policy engine, or approval authority.
- **Offline benchmark scope.** Published benchmark JSON measures deterministic
  gateway/signing/verification paths with fake adapters. It excludes model,
  network, database, image cold-start, and browser latency.
- **Administrative trust boundary.** Forced RLS and a non-owner runtime role
  protect normal application access. They do not defend against a CockroachDB
  cluster administrator.
- **Deployment recovery.** The Lambda initially failed CockroachDB TLS
  verification because the image's libpq connection did not receive an explicit
  CA path. The runtime now binds `verify-full` to the image's exact system CA
  bundle and rejects weaker or caller-overridden settings.
