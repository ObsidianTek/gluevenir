# Public-safe control artifact generation

Gluevenir keeps framework selection separate from implementation. A reviewed
selection document contains control identifiers, bounded contribution categories,
and two Gluevenir-authored interpretations: a project-specific implementation
statement for OSCAL and a generalized public explanation for the static page. The
generator emits a standalone compliance page, minimal OSCAL catalogs, and one
OSCAL component definition without reproducing licensed control titles or text.

This material is implementation evidence only. It does not claim compliance,
certification, conformance, assessment, or audit readiness for Gluevenir or any
organization.

## Selection contract

`control-selection.schema.json` defines a framework-neutral review input:

- `accepted` entries require one or more contribution categories, both
  interpretation layers, evidence references, and an explicit limitation;
- `pending` and `excluded` entries contain an identifier and status only;
- an identifier may appear once per framework, so duplicate and conflicting
  states fail closed;
- `synthetic_data` and `public_safe` must both be `true`; and
- `last_modified` is an explicit UTC timestamp supplied by the reviewer. The
  generator never substitutes the current clock.

The contract deliberately has no field for a source control title, original
control text, or comparison text. Do not copy licensed framework wording into an
interpretation. Interpretations describe only what the Gluevenir runtime does,
the evidence that demonstrates it, and the known limitation.

The four contribution categories are: `provides_evidence`,
`helps_implement_guidance`, `satisfies_deployment_technical_control`, and
`aarm_aiuc_runtime_protection`. They describe the product's bounded contribution,
not framework-wide compliance.

An empty draft (`frameworks: []`) is valid. It produces an honest standalone page
stating that no mappings are published and an empty public-safe OSCAL component
definition. Frameworks with no accepted controls are omitted. Pending and
excluded identifiers do not appear in output content or influence output UUIDs.

## Generate

Run the generator with a reviewed JSON selection and a **new** output directory:

```text
.venv/bin/python scripts/generate_control_artifacts.py \
  path/to/reviewed-selection.json path/to/new-output-directory
```

The output directory must not already exist. This prevents an artifact for a
previously accepted control from surviving after that control is excluded. The
generator validates every input and every in-memory OSCAL document before it
atomically publishes the directory.

Output always contains:

- `compliance.html` — the standalone, alphabetically ordered public page; and
- `gluevenir-component-definition.json` — one software/service component.

For every framework with accepted controls, output also contains:

- `catalog-<framework-id>.json` — a minimal catalog of selected identifiers with
  generated placeholder titles such as `Selected control C.1`; and
The component's implemented requirements contain only the project-specific
interpretation, contribution categories, evidence links, and limitation. The HTML
page uses only the generalized public interpretation and carries one blanket
demo/no-certification disclaimer. Neither output contains source control text.

The release builder can atomically overlay the generated page and include the
validated OSCAL JSON files under `controls/`:

```text
.venv/bin/python scripts/build_static_site.py \
  --source site \
  --control-artifacts-directory path/to/new-output-directory \
  --observability-url https://reviewed-viewer.example \
  --output-directory path/to/new-staging-directory \
  --archive path/to/new-site.zip
```

If no generated artifact directory is supplied, the checked-in compliance page
remains an honest empty draft and no OSCAL files are bundled.

Every document and implemented requirement is marked `public-safe`,
`synthetic-data`, and `implementation-evidence-only` in the Gluevenir property
namespace.

## Determinism and UUID lifecycle

Inputs are normalized by framework, control, and evidence identifier before
generation. Identical reviewed content and `last_modified` values produce
byte-identical JSON and stable UUIDv5 identifiers. Any change to emitted document
content produces a new document UUID. A pending or excluded entry is not emitted,
so reordering or editing those entries does not rotate a public artifact UUID.

The review owner must update `last_modified` whenever accepted public content is
changed. This makes the timestamp stable and reviewable instead of build-time
nondeterminism.

## OSCAL validation boundary

The repository vendors the official NIST OSCAL 1.2.3 JSON schemas used by the
generator:

- [catalog schema](https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_catalog_schema.json)
- [component-definition schema](https://github.com/usnistgov/OSCAL/releases/download/v1.2.3/oscal_component_schema.json)

The offline generator walks all schema features reachable from its narrowly
generated documents and fails on missing, unexpected, mistyped, or malformed
OSCAL fields. It is intentionally not a general-purpose JSON Schema Draft 7
engine. Adding full arbitrary-document validation with a shared `jsonschema`
dependency remains an integration-owner decision; this generator does not modify
the shared dependency lock.

Vendored schema SHA-256 values:

```text
ab95836e9e8dfeb6fde80007f6cc76fa3192f595d427c751a3f3923c3f474fc2  oscal_catalog_schema.json
95e76881151ececd5cb1a93ff0f70ad74b8cc1aa58771626ac8b262bf2c8e001  oscal_component_schema.json
```
