# AWS deployment

This Python AWS CDK app owns three stacks:

- `GluevenirAssets` creates only a private S3 asset bucket and private ECR asset
  repository. Its asset-free legacy synthesis passes the small template directly
  with the current CLI credentials and creates no IAM roles.
- `GluevenirBioPoc` owns the Lambda runtime, its least-privilege execution role,
  log group, public Function URL permissions, and two empty Secrets Manager
  resources. It publishes through CDK's CLI-credentials synthesizer.
- `GluevenirObservability` owns a deletion-friendly, synthetic-only public
  observability plane: one Application Load Balancer and one five-container
  Fargate task. Only its reverse-proxy port is reachable. Collector, Prometheus,
  Grafana, and Jaeger-compatible ports remain task-local.

Amplify Hosting, Cloudflare DNS, CockroachDB, and the existing Bedrock Guardrail
remain external inputs. The deployment uses AMD64 for broad Lambda and CI
compatibility.

Secret values never belong in CDK context, CloudFormation parameters, source,
or deployment logs. Populate the two retained secrets only after a reviewed
stack deployment, using an explicitly approved out-of-band operation. The
runtime expects exact JSON objects:

- Cockroach secret: `{"runtime_database_url":"<non-owner URL>"}`
- Signing secret: `{"private_key_b64":"<raw Ed25519 key as base64>"}`

The Cockroach secret URL must name the exact reviewed database. Production does
not apply a separate database-name override, so a secret rotation cannot silently
route the runtime back to an older database. Local/bootstrap tooling may still
use an explicit `GLUEVENIR_DATABASE` override for its fixed development database.

After an approved secret population or rotation, increment the non-secret
`RuntimeRevision` stack parameter. This makes CloudFormation recycle warm Lambda
environments so the runtime loads the new `AWSCURRENT` values at cold start.
The Lambda binds CockroachDB's required `verify-full` mode to the exact system
CA bundle shipped in the image; it rejects a downgraded mode or caller-supplied
certificate path.

Install the locked Python and CDK CLI dependencies, then synthesize locally:

```console
uv sync --locked --all-groups
npm ci
npm run synth -- --context account="$(aws sts get-caller-identity --query Account --output text)" --context region=us-east-1
```

Do not run the default `cdk bootstrap`: AWS documents that its CloudFormation
execution role receives `AdministratorAccess` by default. Deploy the asset stack
first with the current explicitly authenticated CLI session:

```console
npm run cdk -- deploy GluevenirAssets --profile gluevenir --require-approval broadening
```

Then review both stack diffs before either deployment:

```console
npm run diff -- GluevenirObservability ...
npm run diff -- GluevenirBioPoc ...
```

The observability stack requires
only the reviewed public hostname and its existing ACM certificate ARN. CDK
builds five version-pinned AMD64 configuration images from `observability/`;
there are no hand-supplied image URI parameters. Two Grafana view types are
published across five externally shared, stored-query dashboards: one overview
and four fixed-persona views. They are not an anonymous datasource console.
The ALB permits only their exact read and panel-query paths, the read-only trace
view, and bearer-authenticated OTLP/HTTP trace ingestion. Administrative,
arbitrary datasource-query, and OTLP metrics routes fall through to 404.

Supply the runtime stack's non-secret CloudFormation parameters for the
Guardrail ID, application SHA-256, and two exact HTTPS origins. Docker is
required because both stacks publish AMD64 image assets. No external accounts
are trusted, and no standing CDK deployment role is created.

After a reviewed observability deployment, use the
`StaticSiteObservabilityBaseUrl` stack output to create the exact static bundle
for Amplify. The builder accepts only an HTTPS DNS origin, changes only the
empty `gluevenir-observability-url` metadata field, preserves the configured API
URL, and emits files at the ZIP root:

```console
uv run python scripts/build_static_site.py \
  --observability-url "https://observe.example.test" \
  --output-directory build/static-site \
  --archive build/gluevenir-amplify.zip
```

Both output paths must be new and their parent directories must already exist.
Review the staging directory and ZIP hash before manually uploading the ZIP to
the already selected Amplify application. The command does not deploy, read
cloud credentials, or modify `site/`.

The current AWS account is at Lambda's minimum unreserved-concurrency quota, so
this stack cannot set a function-level reservation without violating AWS's
required pool of ten unreserved executions. The public synthetic endpoint keeps
its strict body, scenario, model-turn, tool-call, and browser timeout bounds;
request-rate protection remains a documented POC limitation.
