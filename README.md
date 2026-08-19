# Gluevenir

**Useful memory. Controlled recall.**

Gluevenir is an importable Python framework for useful, governed persistent
memory. Gluevenir Bio is its single-agent, synthetic biotech demonstration for
the CockroachDB × AWS Build with Agentic Memory Hackathon.

- Live demo: <https://gluevenir.obsidiantek.io>
- Amplify fallback: <https://production.d2v1tx01e3zvx8.amplifyapp.com>

HelixCure and HX-17 are wholly fictional. The demo contains no real molecule,
trial, sponsor, participant, company program, customer, or clinical result.

## Why it exists

Persistent memory makes an agent more useful, but relevance alone is not
authorization. Gluevenir places one deterministic Memory Action Gateway before
every supported public memory action. The gateway binds server-owned identity,
tenant, program, purpose, audience, destination, lifecycle, approval, and prior
receipt context before retrieval or model use.

Every evaluation returns exactly one decision:

| Decision | Effect |
|---|---|
| `ALLOW` | Authorized memory may support the request. |
| `DENY` | The action stops before retrieval or model invocation. |
| `MODIFY` | Restricted source memory is replaced only by an exact, active, human-approved Safe Derivative. |
| `STEP_UP` | An authorized human must resolve the exact proposed use; no side effect occurs first. |
| `DEFER` | Trusted context is missing; the action pauses with zero side effects and times out to deny. |

Each evaluated action produces a canonical, content-safe Ed25519-signed Recall
Receipt. Receipts bind IDs, hashes, counts, decision and reason codes, policy,
and signing-key identity without recording prompts, answers, restricted text,
detector matches, credentials, or excluded memory IDs.

## Architecture

The shipped demonstration uses one runtime agent:

1. The Amplify-hosted static interface sends a bounded synthetic prompt plus a
   server-known persona and business-journey identifier to an AWS Lambda
   Function URL. It progressively presents validated governance and answer
   events from one bounded response; it does not claim token-transport streaming.
2. Lambda maps the persona and journey to trusted synthetic identity and context; a
   browser-supplied tenant identifier is never accepted as authority.
3. Every recall enters the same deterministic Memory Action Gateway.
4. CockroachDB Cloud provides the sole persistent and vector memory store with
   a non-owner runtime role, forced row-level security, transaction-scoped
   tenant context, and tenant/program-scoped vector recall.
5. Amazon Bedrock supplies Titan Text Embeddings v2, Nova Lite generation, and
   a Bedrock Guardrail. Restricted source text never enters the external model
   prompt in the `MODIFY` path.
6. The response contains a bounded public view plus a signed, independently
   verifiable Recall Receipt under the documented development-key trust model.

AWS infrastructure is defined with Python CDK and deploys an AMD64 Lambda image,
least-privilege role, bounded log group, Function URL permissions, and two AWS
Secrets Manager resources. Amplify Hosting and Cloudflare DNS remain outside
the runtime stack.

## Sponsor technology

### CockroachDB

- **Distributed Vector Indexing:** a prefix-scoped 256-dimensional cosine vector
  index is created before fixtures. Recall uses index-eligible tenant/program
  equality constraints, cosine ordering, and explicit room, purpose, audience,
  state, approval, validity, and lifecycle predicates. On the nine-row deployed
  release-baseline fixture, CockroachDB's cost-based optimizer rationally selects
  an exact index scan; a disposable 512-row synthetic proof produced the
  vector-search operator with both authorization prefixes and was then removed.
  Expanded persona fixtures require fresh live verification before replacing
  that baseline evidence.
- **CockroachDB Cloud Managed MCP:** the official single-cluster endpoint was
  initialized, its expected tools were discovered, and a bounded read inspected
  only content-safe receipt metadata from the live demo. MCP is not a guard
  agent and cannot approve or weaken policy.
- Retry-safe transactions use the maintained CockroachDB SQLAlchemy transaction
  helper. Security-relevant writes do not silently collapse through unsafe
  conflict handling.

### AWS

- **Lambda and Function URLs:** public synthetic demo runtime.
- **Amazon Bedrock:** Titan Text Embeddings v2, Nova Lite, and Guardrails.
- **AWS Secrets Manager:** dedicated non-owner Cockroach runtime URL and Ed25519
  signing private key, loaded at cold start and never placed in source or CDK
  context.
- **Amazon ECR:** private Lambda image asset.
- **AWS Amplify Hosting:** exclusive static frontend host.
- **AWS CDK:** repeatable Python infrastructure definition and offline template
  assertions.

## Verified pre-release state

- All five decision paths pass offline and against the public AWS endpoint.
- Live public receipts report a decision matching the response and an
  API-verified signature.
- Cross-tenant, policy-outage, pending-timeout, approval, lifecycle,
  injection-as-data, retry, signature-mutation, and safe-utility paths have
  deterministic offline coverage.
- The live CockroachDB role, forced RLS, composite tenant/program constraints,
  vector index, scoped recall, lifecycle, and exact Safe Derivative binding were
  checked using synthetic fixtures.
- The branded and generated Amplify URLs serve byte-identical HTML over HTTPS.
- Bounded CloudWatch checks found no recent prompt, credential-field, or runtime
  error events after the final interactive deployment.

Machine-readable synthetic evaluation and benchmark artifacts live in
[`evidence/`](evidence/). Offline benchmark values exclude model, network,
database, and cold-start latency.

### Official CockroachDB Agent Skills review

Fourteen relevant official Agent Skills, pinned to one upstream commit, were
applied as build-time review checklists after the core implementation. They
improved vector-plan evidence, confirmed statistics/job/privilege health, and
produced a bounded CI, migration, and production-hardening backlog. The review
is recorded in
[`evidence/cockroachdb-skills-review.json`](evidence/cockroachdb-skills-review.json).

The skills were not copied into this repository and are not runtime agents or a
third sponsor integration. Gluevenir's demonstrated CockroachDB tools remain
Distributed Vector Indexing and CockroachDB Cloud Managed MCP.

## Develop locally

Python 3.12 and [uv](https://docs.astral.sh/uv/) are required.

```console
git clone https://github.com/ObsidianTek/gluevenir.git
cd gluevenir
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run pytest
uv run python scripts/verify_repository.py
uv build
```

The offline suite requires no database, model, MCP, or cloud credentials.
Generate a disposable JSON-first evidence bundle with:

```console
uv run python scripts/generate_evidence.py /tmp/gluevenir-evidence --samples 200
```

At a release gate, regenerate the tracked 1,000-sample bundle and bind its
manifest to the verified source commit with a disposable fresh-clone check:

```console
uv run python scripts/generate_evidence.py evidence --samples 1000
uv run python scripts/generate_release_provenance.py
```

The provenance command runs the locked install, offline suite, repository
verification, package build/import, and CDK synthesis in a temporary local
clone before rewriting `evidence/fresh-clone.json` and
`evidence/manifest.json`.

For the live schema workflow, use only a dedicated synthetic development
database and keep its URL outside the repository:

```console
uv run python scripts/check_live_migration_state.py --expect clean
uv run alembic upgrade head
uv run python scripts/check_live_migration_state.py --expect current
uv run python scripts/load_synthetic_fixtures.py
uv run python scripts/embed_synthetic_fixtures.py
uv run python scripts/generate_demo_catalog.py
uv run python scripts/verify_live_memory_core.py
```

The preflight checks the expected table set, Alembic revision, and application
role presence; the live verifier checks detailed RLS, policy, privilege,
constraint, and index behavior. The fixture loader accepts only checked-in
synthetic records and fails instead of silently overwriting different rows.
Embedding generation calls Titan only for active fixture rows still missing a
vector, outside CockroachDB transactions, then applies a short guarded and
retry-safe update without logging memory content.

Deployment ownership, secret boundaries, synthesis, and stack ordering are
documented in [`infra/README.md`](infra/README.md). Never put secret values in
CDK context, CloudFormation parameters, source, evidence, or logs.

## Safety and claim boundary

- Use synthetic data only. Automated detection is imperfect.
- `PHI_CANDIDATE` and `MNPI_CANDIDATE` are project-defined policy candidates,
  not legal determinations.
- Gluevenir is **AARM-inspired** for supported memory-mediated actions only. It
  does not claim AARM conformance, certification, community verification, or
  universal interception.
- The prototype shows evidence relevant to selected AIUC-1 controls. It is not
  AIUC-1 certified, conformant, assessed, ready, or audit-ready.
- It is not HIPAA compliant, clinically validated, legal advice, or a guarantee
  of sensitive-data detection.
- Recall Receipts are signed, content-bound, and independently verifiable within
  the documented development-key trust model. They are not described as
  immutable, tamper-proof, non-repudiable, or cryptographically attested.
- The receipt trust boundary does not protect against an administrator who
  controls both storage and the signing key.

See [`evidence/claim-boundary.md`](evidence/claim-boundary.md), the
[AARM mapping](evidence/aarm-alignment.json), and the selected
[AIUC-1 mapping](evidence/aiuc1-alignment.json).

## Roadmap

1. **Authenticated human review for `STEP_UP`:** add a reviewer workspace that
   presents the exact bounded proposal, authorized evidence, requested scopes,
   expiry, and policy reason; records approve or reject with trusted reviewer
   identity; creates a signed resolution receipt; and resumes execution only
   after a fresh policy evaluation. Pending actions keep zero side effects and
   time out to `DENY`.
2. **Anomalous retry detection:** identify bounded attempts to evade a prior
   `DENY` without storing raw prompts or treating ordinary retries as attacks.
3. **Production trust hardening:** rotate signing keys, register verification
   keys, and move observability from bounded demonstration retention to an
   operationally managed deployment.

## License and disclosures

[MIT](LICENSE). Third-party and pre-existing-work disclosures are maintained in
[`evidence/third-party-notices.md`](evidence/third-party-notices.md).
