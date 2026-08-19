# Local, hybrid, and cloud-aligned development modes

These Compose modes reproduce the Gluevenir demo boundary for development and
workshops. They do not replace the submitted AWS Lambda, Amazon Bedrock,
CockroachDB Cloud, and AWS Amplify architecture.

The local database is a pinned, single-node CockroachDB `v26.2.5` process in
insecure mode. It is suitable only for local application development. It is not
highly available, does not provide a host security boundary, and is not evidence
of a secure or production CockroachDB deployment. Cockroach Labs likewise warns
that [`start-single-node` is not for production or performance testing](https://www.cockroachlabs.com/docs/stable/cockroach-start-single-node).

All published host ports bind to `127.0.0.1`. The application still uses the
same server-owned persona mapping, Memory Action Gateway, CockroachDB-backed
runtime, Bedrock adapters, and Lambda HTTP contract as the hosted demo.

Local, hybrid, and ephemeral modes also start a pinned local observability
stack. The application sends only its already-bounded OpenTelemetry spans to a
task-internal Collector. The Collector forwards traces to Jaeger and derives
Prometheus-compatible metrics for Grafana. Prometheus and Collector ports are
not published to the host. Grafana is an anonymous, read-only viewer and every
dashboard is prominently labeled **Synthetic telemetry only**.

The telemetry allowlist includes bounded stage, status, decision, operation,
persona category, reason code, counts, model-invoked state, receipt-verification
state, and duration. It excludes prompts, answers, memory content or IDs,
detector matches, tenant/program/customer identifiers, credentials, and model or
Guardrail bodies. Local exporter failure does not change a gateway decision or
receipt.

## Prepare the mounted secret files

Copy `.env.example` to `.env`, set the non-secret Bedrock Guardrail ID, and keep
the default secret paths unless you have a reason to move them:

```sh
cp .env.example .env
mkdir -p .private/compose
chmod 700 .private/compose
install -m 600 /dev/null .private/compose/bedrock_api_key
```

Open `.private/compose/bedrock_api_key` in your editor and place the dedicated
Bedrock development API key on one line. Compose mounts that ignored file at
`/run/secrets/bedrock_api_key`. The key is never placed in an environment
variable, image layer, command line, browser response, application log, or
trace. No AWS profile, access-key pair, or home-directory mount is used.

The key must authorize the pinned Titan embedding model, Nova Lite generation
model, and the Guardrail selected in `.env`. Automated detection is imperfect;
use only the checked-in synthetic demo data.

## Persistent local mode

```sh
docker compose up --build
```

Open <http://localhost:8765>. The local CockroachDB console is available only on
<http://127.0.0.1:8080>, and SQL is available only on `127.0.0.1:26257`.
The local aggregate Grafana viewer is
<http://127.0.0.1:3000/d/gluevenir-local-telemetry>, the persona detail is
<http://127.0.0.1:3000/d/gluevenir-persona-governance>, and the Jaeger trace
viewer is <http://127.0.0.1:16686>. There is no login; all interfaces are
loopback-only and contain synthetic demo telemetry.

The one-shot setup service:

1. creates the local `gluevenir` database;
2. refuses a partial or drifted migration state;
3. applies the existing Alembic migrations when the database is clean;
4. uses the existing retry-safe, drift-detecting fixture loader;
5. prepares missing embeddings outside transactions and writes them through the
   existing guarded retry-safe loader;
6. provisions the non-owner `gluevenir_runtime` principal; and
7. verifies its membership, lack of schema/database creation privileges, and
   forced row-level security before the application starts.

The final `verify` service runs one `ALLOW` and one `MODIFY` journey and checks
their signed public receipts without printing prompts, answers, tokens, keys, or
database credentials. It then polls the internal Prometheus API for at least two
`gluevenir.request` span metrics and the internal Jaeger API for a bounded
request trace. Its output remains a synthetic pass/fail summary.

Stop containers while preserving the named database and local signing-key
volumes:

```sh
docker compose down
```

Delete only this explicitly named Compose project's local database, signing
key, Prometheus metrics, and Grafana state after reviewing the target:

```sh
docker compose down -v
```

`down -v` is destructive. It removes the `gluevenir-local` named volumes, so the
next start creates a fresh database, a different development receipt key, and
empty local dashboards/traces. It does not delete the host-mounted Bedrock token
file. Jaeger uses bounded in-memory storage, so its traces are also cleared by a
normal stop.

## Ephemeral workshop mode

```sh
docker compose -f compose.ephemeral.yaml up --build
```

Open <http://localhost:9765>. Grafana is available on
<http://127.0.0.1:13000/d/gluevenir-local-telemetry> with persona detail at
<http://127.0.0.1:13000/d/gluevenir-persona-governance>, and Jaeger is on
<http://127.0.0.1:17686>. CockroachDB, receipt-signing, Prometheus, Grafana, and
Jaeger state live in container memory or `tmpfs` mounts. They disappear when the
composition stops; no database, key, metrics, or dashboard volume is retained.

```sh
docker compose -f compose.ephemeral.yaml down
```

This mode intentionally uses different host ports (`36257`, `9080`, `9765`,
`13000`, and `17686`) so it cannot silently attach to persistent local-mode
state.

## Hybrid mode: local app, CockroachDB Cloud, and Bedrock

Hybrid mode never runs migrations or loads fixtures into the cloud cluster. Use
the existing credentialed URL for the non-owner `gluevenir_runtime` principal,
with `sslmode=verify-full`, and place it on one line in the ignored file:

```text
.private/compose/cockroach_runtime_url
```

The setup service performs read-only migration, principal, privilege, and forced
RLS checks. It fails closed if the cluster is partial, the role is overpowered,
TLS verification is weakened, or the expected schema is absent.

```sh
docker compose -f compose.hybrid.yaml up --build
```

Open <http://localhost:8765>. Grafana and Jaeger use the same loopback URLs as
persistent local mode. Stop while retaining the local receipt key, metrics, and
Grafana state:

```sh
docker compose -f compose.hybrid.yaml down
```

Remove those local-only volumes when they are no longer needed:

```sh
docker compose -f compose.hybrid.yaml down -v
```

## Cloud-aligned viewer

Set `GLUEVENIR_CLOUD_API_URL` to the existing HTTPS AWS API ending in `/v1/demo`
and `GLUEVENIR_CLOUD_SITE_URL` to the existing HTTPS site. Then run:

```sh
docker compose -f compose.cloud.yaml up --build
```

Open <http://localhost:8765>. This composition serves the checked-in static
viewer and sends its same-origin requests through a content-bounded local proxy
to the configured public API, avoiding any need to weaken the hosted API's CORS
policy. The upstream API remains the authoritative hosted gateway. The
composition labels AWS and CockroachDB Cloud as external required dependencies;
it does not create, deploy, emulate, or re-authorize either one. It mounts no
cloud database credential, Bedrock token, AWS profile, or access key.

Cloud-aligned mode deliberately does not claim to mirror hosted telemetry into
the local observability stack. The authoritative runtime and any telemetry
export remain external AWS resources; this composition is only a local viewer
and contract check. Use the hosted observability URL once that separately
reviewed stack is deployed.

```sh
docker compose -f compose.cloud.yaml down
```

## Troubleshooting and safety

- A partial migration state is deliberately not repaired automatically. Remove
  the known local project volume and restart, or inspect a cloud cluster through
  the normal reviewed migration process.
- An existing fixture ID with different content fails closed; the loader does
  not use `ON CONFLICT DO NOTHING` or suppress security-relevant drift.
- Local receipt signatures are independently verifiable only within the local
  development-key trust model. They are not AWS Secrets Manager keys and should
  not be presented as hosted evidence.
- The one-shot `telemetry-ready` service checks Collector, Prometheus, Jaeger,
  and Grafana before the application starts. Inspect its bounded readiness
  result and the affected service logs if startup stops there; those logs should
  contain service health only, never request content.
- Do not enter real personal, health, customer, confidential, or program data.
- The Docker build copies only the package inputs already admitted by the
  deny-by-default `.dockerignore`; migrations, fixtures, scripts, and static
  files are mounted read-only for this developer workflow.
