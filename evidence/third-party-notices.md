# Third-party and pre-existing work

Status: current pre-release dependency and provenance disclosure; update whenever
a dependency or copied/pinned asset is introduced.

Repository source, project-contract text, and interactive demo content are
original work created for this project. No third-party source code, fixture, or
CockroachDB Agent Skill has been copied into the repository.

Fourteen official CockroachDB Agent Skills were installed only in the local
Codex environment, pinned to upstream commit
`e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd`, and used as build-time review
guidance. The upstream repository is Apache-2.0 licensed. This consultation is
recorded in `evidence/cockroachdb-skills-review.json`; it is not a runtime
integration and is not presented as a third eligible CockroachDB tool.

Runtime and development dependencies are declared in `pyproject.toml`, locked
in `uv.lock`, and enumerated in `evidence/dependency-manifest.txt`:

- Psycopg — PostgreSQL-protocol database driver used for CockroachDB access;
- Alembic — schema migration and database revision tracking;
- SQLAlchemy and the CockroachDB SQLAlchemy dialect — CockroachDB runtime and
  migration connectivity, including the dialect's maintained transaction retry;
- cryptography — Ed25519 receipt signing and offline signature verification;
- Boto3 and Botocore — AWS Secrets Manager and Bedrock runtime clients;
- Microsoft Presidio Analyzer — additional PII-candidate detection behind the
  bounded Gluevenir detector adapter; automated detection remains imperfect;
- spaCy and the pinned `en_core_web_sm` model — English NLP support for the
  Presidio Analyzer in the Lambda image;
- OpenTelemetry Python SDK and OTLP/HTTP exporter — content-safe trace export
  through the allowlisted Gluevenir telemetry adapter and Collector boundary;
- AWS CDK, Constructs, and JSII — Python infrastructure synthesis and tests;
- Hatchling — Python build backend;
- build — package build frontend;
- pytest — offline test runner; and
- Ruff — formatter and linter.

Transitive development dependencies are recorded in the generated manifest.
They are tooling dependencies, not bundled source. Their upstream license terms
remain controlling. The GitHub Actions workflow also uses the official
`actions/checkout`, `actions/setup-python`, and `astral-sh/setup-uv` actions.
The AWS CDK Toolkit CLI is pinned through `package-lock.json`; the deployment
also pins the AWS SDK instead of relying on the Lambda base image's bundled copy.

The optional local/hybrid Compose developer workflow pulls pinned upstream
container images rather than redistributing their source in this repository:

- CockroachDB single-node `v26.2.5`, under Cockroach Labs' controlling source
  and binary terms, for local development only;
- OpenTelemetry Collector Contrib `0.123.0`, Apache-2.0;
- Prometheus `v3.2.1`, Apache-2.0;
- Jaeger all-in-one `1.66.0`, Apache-2.0; and
- Grafana OSS `11.6.0`, AGPL-3.0-only by default with the upstream project's
  documented per-directory exceptions.

The AWS observability CDK build creates configuration images from pinned
upstream images: NGINX unprivileged `1.27.4-alpine3.21`, OpenTelemetry Collector
Contrib `0.123.0`, Prometheus `v3.2.1`, Grafana OSS `11.6.0`, Jaeger `2.20.0`,
Python `3.12.11-alpine3.21`, and Alpine `3.21.3`. The Python stage generates
four fixed-persona public dashboards and is not present in the Grafana runtime
image. The Collector and Jaeger images copy the corresponding upstream
executable into a minimal Alpine final stage; other runtime images extend their
upstream base. Upstream binaries, image contents, notices, and license terms
remain controlling.

Their upstream image contents and license notices remain controlling. Gluevenir
adds only its own configuration, bounded wrapper scripts, and provisioned
synthetic-only dashboard artifacts; it does not copy those projects' source into
the repository.

AWS services and CockroachDB Managed MCP are external services, not redistributed
package dependencies. No CockroachDB Agent Skill source is copied into the
repository.
