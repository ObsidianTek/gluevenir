# Wave E fixture database preparation and cutover

Status: **reviewable preparation path; no live cutover has been performed**.

This runbook prepares the frozen 30-memory, three-approval synthetic corpus in a
dedicated blue database while the deployed database remains the green rollback
baseline. The preparer does not create, drop, recreate, rename, select, or swap a
database. It does not read or change AWS Secrets Manager. Live database creation,
secret rotation, Lambda deployment, and traffic verification remain explicit
release-owner actions after the final copy/fixture freeze and user approval.

## Why the target must be isolated

The initial migration creates the cluster-scoped `gluevenir_app` role. A new
database on the already deployed CockroachDB cluster is therefore not an exact
clean migration target: the role exists outside the database even when its public
schema is empty. The preflight correctly classifies that combination as partial
and refuses to migrate over it.

For this pre-release blue/green path, use an isolated CockroachDB target on which:

- the dedicated database already exists and has a reviewed name matching
  `gluevenir_release_YYYYMMDD_suffix`;
- the migration principal can apply the checked-in Alembic history;
- the existing non-owner login is exactly `gluevenir_runtime`; the preparer binds
  it to `gluevenir_app`, enforces `NOBYPASSRLS`, removes any `admin` membership,
  and revokes database/schema creation before verification; and
- no real, customer, participant, or other non-synthetic data is present.

Do not point the preparer at `gluevenir`, `defaultdb`, `postgres`, `system`, a
template database, the deployed green database, or an arbitrary name. Do not
repair a partial migration with `IF NOT EXISTS` or broad role cleanup.

## Inputs and non-disclosure boundary

Create two owner-readable local files outside the repository:

1. a migration-owner CockroachDB URL naming the exact versioned database; and
2. a `gluevenir_runtime` URL naming the same host, port, and database.

The URLs must include the target database rather than relying on an environment
override and must use `sslmode=verify-full`. The script reads them from files so
credentials do not appear in shell history or process arguments. It enables
SQLAlchemy parameter hiding and prints only state, counts, and completion status.
It never prints a URL, username, password, fixture body, embedding input, or
detector match.

## Mutation-free plan review

The `plan` mode parses and validates both URLs but performs no network call and no
mutation:

```console
uv run python -m scripts.prepare_release_database plan \
  --admin-url-file /path/outside/repo/release-admin-url \
  --runtime-url-file /path/outside/repo/release-runtime-url \
  --acknowledge-database gluevenir_release_20260817_abcd
```

Review the emitted sequence before any preparation. The exact acknowledgement is
intentional protection against an inherited default or a mistyped target.

## Preparation gate

Run `prepare` only after the fixture JSON, generated catalog, user-facing copy that
changes fixture text, and hashes are frozen:

```console
uv run python -m scripts.prepare_release_database prepare \
  --admin-url-file /path/outside/repo/release-admin-url \
  --runtime-url-file /path/outside/repo/release-runtime-url \
  --acknowledge-database gluevenir_release_20260817_abcd \
  --aws-region us-east-1
```

The preparer then:

1. classifies the exact schema/role/Alembic state as `clean`, `current`, or
   `partial`;
2. refuses `partial` before fixture or embedding work;
3. applies the existing Alembic history only from `clean`, then requires the exact
   current revision;
4. retry-safely binds and hardens the exact `gluevenir_runtime` principal;
5. requires all operational tables to be empty and the memory/approval pair to be
   either empty or already exactly 30/3;
6. invokes the existing retry-safe fixture loader inside one short CockroachDB
   transaction;
7. regenerates every active fixture embedding with the pinned Bedrock model
   outside the read and write retry callbacks, then writes with
   hash/tenant/program guards;
8. verifies exact counts and every active fixture embedding;
9. reuses the live catalog verifier for the revision, vector index, grants,
   ownership, approval scope, and `ENABLE/FORCE ROW LEVEL SECURITY` checks; and
10. verifies the non-owner runtime principal, exact per-tenant visibility, and
   fail-closed access without transaction-scoped tenant context.

The fixture load is retry-safe and idempotent. Each release-preparation run
intentionally regenerates every active embedding so an old or mismatched non-null
vector cannot satisfy the release gate. Bedrock calls remain outside database
transactions; only the short guarded writes are retried. A migration failure may
leave CockroachDB's non-transactional DDL partial; the next run refuses that state
for diagnosis rather than attempting repair. A failure after preparation does not
affect the deployed green database because this command has no cutover capability.

## Primary-owned cutover checklist

The following actions are deliberately not implemented by the preparer. The
primary release owner performs them only after reviewing the prepared database,
recording the current release SHA, and receiving explicit user approval:

1. Freeze fixtures, generated catalog, copy, and all content hashes. Run the full
   offline suite and repository verifier at the exact candidate SHA.
2. Run the preparation gate above and preserve its content-free result. Run all 20
   scenario journeys directly against the prepared runtime credential, including
   each persona's five outcomes and offline receipt mutation failure.
3. Record, without exposing values, the current Cockroach runtime secret version,
   Lambda image/config revision, and green database target needed for rollback.
4. Confirm the synthesized runtime has no `GLUEVENIR_DATABASE` override. The
   reviewed database named by the non-owner secret URL is the production routing
   authority.
5. Add a new version to the existing Cockroach runtime Secrets Manager resource
   containing only the prepared non-owner runtime URL. Do not create another
   application secret and do not change the signing-key secret.
6. Deploy the already reviewed Lambda image/config with a non-secret secret
   revision bump so cold starts read the new secret version. Do not deploy an
   uncommitted image.
7. Verify the Lambda health endpoint, branded and generated Amplify URLs, exact
   CORS origin, all five decisions, the approved external derivative, receipt
   verification, content-free telemetry, and the Managed MCP bounded receipt read.
8. Keep the green database and previous secret version unchanged until the public
   checks and evidence bundle pass. Record only redacted identifiers and counts.

No traffic cutover is considered verified until those checks run successfully on
the deployed candidate.

## Exact rollback sequence

If any post-cutover health, scenario, receipt, RLS, MCP, telemetry, or content
safety check fails:

1. stop further demo requests and preserve the failing receipt IDs and
   content-free telemetry;
2. move the existing Cockroach runtime secret's current stage back to the recorded
   green version without editing either secret value;
3. restore the recorded green Cockroach secret version and non-secret runtime
   revision, then redeploy the previously verified green image/configuration;
4. force a new Lambda execution environment and verify that health and the five
   baseline scenarios use the green database;
5. verify the generated Amplify URL and branded hostname from a logged-out browser;
6. leave the blue database intact and unreachable by the demo for diagnosis; do
   not drop, truncate, repair, or reuse it during rollback; and
7. record the rollback outcome and remaining uncertainty before another attempt.

Rollback is a routing/configuration reversal, not a destructive database action.

## Remaining live uncertainties

- A new isolated CockroachDB target and both bounded credentials must exist before
  the production preparer can be verified live.
- The migration role is cluster-scoped; a same-cluster versioned database remains
  intentionally rejected by the current migration contract.
- CDK synthesis and the deployed Lambda configuration must both prove that no
  database-name override supersedes the reviewed secret URL.
- Bedrock embedding availability, exact active embedding count, non-owner RLS,
  20-journey behavior, MCP receipt inspection, and public URLs must be reverified
  against the prepared target. None is implied by offline tests.
