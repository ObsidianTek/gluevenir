#!/usr/bin/env python3
"""Generate public-safe OSCAL artifacts from reviewed control selections.

The input intentionally has no field for a source control title or source control
text. Only accepted identifiers and original Gluevenir implementation material
are emitted. Pending and excluded entries are validated, then discarded.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SELECTION_SCHEMA = ROOT / "controls" / "control-selection.schema.json"
OSCAL_SCHEMA_ROOT = ROOT / "vendor" / "oscal" / "v1.2.3"
CATALOG_SCHEMA = OSCAL_SCHEMA_ROOT / "oscal_catalog_schema.json"
COMPONENT_SCHEMA = OSCAL_SCHEMA_ROOT / "oscal_component_schema.json"
COMPLIANCE_TEMPLATE = ROOT / "site" / "compliance.html"

OSCAL_VERSION = "1.2.3"
SELECTION_SCHEMA_VERSION = "1.0"
PROPERTY_NAMESPACE = "https://obsidiantek.io/ns/gluevenir"
UUID_NAMESPACE = uuid.UUID("448f47d2-07aa-5e9f-9765-7a5f4fcb9c8a")
TOKEN_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9._-]*$")
TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
COMPLIANCE_CONTENT_PATTERN = re.compile(
    r"(?s)(<!-- GLUEVENIR_COMPLIANCE_CONTENT_START -->).*?"
    r"(<!-- GLUEVENIR_COMPLIANCE_CONTENT_END -->)"
)
COMPLIANCE_DISCLAIMER = (
    "Gluevenir is a synthetic demonstration and is not certified, compliant, "
    "conformant, assessed, or audit-ready under any referenced framework."
)
CONTRIBUTION_LABELS = {
    "provides_evidence": "Provides evidence",
    "helps_implement_guidance": "Helps implement guidance",
    "satisfies_deployment_technical_control": (
        "Satisfies a deployment technical control"
    ),
    "aarm_aiuc_runtime_protection": "AARM/AIUC-inspired runtime protection",
}


class ControlArtifactError(ValueError):
    """Raised before output when selection or generated artifacts are unsafe."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _stable_uuid(label: str, value: object) -> str:
    seed = f"{label}:{_canonical_bytes(value).decode('utf-8')}"
    return str(uuid.uuid5(UUID_NAMESPACE, seed))


def _natural_key(value: str) -> tuple[object, ...]:
    return tuple(
        int(part) if part.isdigit() else part.casefold()
        for part in re.split(r"([0-9]+)", value)
    )


def _require_object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControlArtifactError(f"{path} must be an object")
    return value


def _require_exact_keys(
    value: Mapping[str, object], *, required: set[str], path: str
) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unexpected = sorted(actual - required)
    if missing:
        raise ControlArtifactError(f"{path} is missing fields: {', '.join(missing)}")
    if unexpected:
        raise ControlArtifactError(
            f"{path} has unsupported fields: {', '.join(unexpected)}"
        )


def _require_string(value: object, path: str, *, single_line: bool = False) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ControlArtifactError(f"{path} must be a non-empty trimmed string")
    if single_line and ("\n" in value or "\r" in value):
        raise ControlArtifactError(f"{path} must be a single line")
    return value


def _require_token(value: object, path: str) -> str:
    token = _require_string(value, path, single_line=True)
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise ControlArtifactError(f"{path} is not an OSCAL-compatible token")
    return token


def _require_uri(value: object, path: str, *, relative_allowed: bool = False) -> str:
    uri = _require_string(value, path, single_line=True)
    if any(character.isspace() for character in uri):
        raise ControlArtifactError(f"{path} must not contain whitespace")
    parsed = urlparse(uri)
    if relative_allowed:
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            raise ControlArtifactError(
                f"{path} must use HTTP(S) or a relative repository reference"
            )
        if parsed.netloc and not parsed.scheme:
            raise ControlArtifactError(
                f"{path} must not use a scheme-relative external reference"
            )
        if not (parsed.scheme or parsed.path or parsed.fragment):
            raise ControlArtifactError(f"{path} must be a URI reference")
    elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ControlArtifactError(f"{path} must be an absolute HTTP(S) URI")
    return uri


def _validated_timestamp(value: object) -> str:
    timestamp = _require_string(value, "last_modified", single_line=True)
    if TIMESTAMP_PATTERN.fullmatch(timestamp) is None:
        raise ControlArtifactError(
            "last_modified must be an explicit UTC timestamp like 2026-08-17T12:00:00Z"
        )
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControlArtifactError("last_modified is not a valid timestamp") from error
    return timestamp


def validate_selection(document: object) -> dict[str, Any]:
    """Validate and normalize the framework-neutral selection document."""

    try:
        contract = json.loads(SELECTION_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ControlArtifactError(
            f"cannot load control selection schema {SELECTION_SCHEMA}"
        ) from error
    if (
        contract.get("$id")
        != "https://gluevenir.obsidiantek.io/schemas/control-selection.schema.json"
        or contract.get("properties", {}).get("schema_version", {}).get("const")
        != SELECTION_SCHEMA_VERSION
    ):
        raise ControlArtifactError("control selection schema contract is invalid")

    root = _require_object(document, "selection")
    _require_exact_keys(
        root,
        required={
            "schema_version",
            "last_modified",
            "document_version",
            "synthetic_data",
            "public_safe",
            "component",
            "frameworks",
        },
        path="selection",
    )
    if root["schema_version"] != SELECTION_SCHEMA_VERSION:
        raise ControlArtifactError(
            f"schema_version must be {SELECTION_SCHEMA_VERSION!r}"
        )
    if root["synthetic_data"] is not True or root["public_safe"] is not True:
        raise ControlArtifactError("synthetic_data and public_safe must both be true")

    component = _require_object(root["component"], "component")
    _require_exact_keys(
        component,
        required={"title", "type", "description", "claim_boundary"},
        path="component",
    )
    normalized_component = {
        "title": _require_string(
            component["title"], "component.title", single_line=True
        ),
        "type": _require_string(component["type"], "component.type", single_line=True),
        "description": _require_string(
            component["description"], "component.description"
        ),
        "claim_boundary": _require_string(
            component["claim_boundary"], "component.claim_boundary"
        ),
    }
    if normalized_component["type"] not in {"software", "service"}:
        raise ControlArtifactError("component.type must be 'software' or 'service'")

    frameworks = root["frameworks"]
    if not isinstance(frameworks, list):
        raise ControlArtifactError("frameworks must be an array")
    seen_framework_ids: set[str] = set()
    normalized_frameworks: list[dict[str, Any]] = []
    for framework_index, framework_value in enumerate(frameworks):
        path = f"frameworks[{framework_index}]"
        framework = _require_object(framework_value, path)
        _require_exact_keys(
            framework,
            required={"id", "name", "version", "reference", "controls"},
            path=path,
        )
        framework_id = _require_token(framework["id"], f"{path}.id")
        if framework_id in seen_framework_ids:
            raise ControlArtifactError(f"duplicate framework id: {framework_id}")
        seen_framework_ids.add(framework_id)

        controls = framework["controls"]
        if not isinstance(controls, list) or not controls:
            raise ControlArtifactError(f"{path}.controls must be a non-empty array")
        seen_controls: dict[str, str] = {}
        normalized_controls: list[dict[str, Any]] = []
        for control_index, control_value in enumerate(controls):
            control_path = f"{path}.controls[{control_index}]"
            control = _require_object(control_value, control_path)
            if "id" not in control or "status" not in control:
                raise ControlArtifactError(f"{control_path} must include id and status")
            control_id = _require_token(control["id"], f"{control_path}.id")
            status = _require_string(
                control["status"], f"{control_path}.status", single_line=True
            )
            previous_status = seen_controls.get(control_id)
            if previous_status is not None:
                qualifier = "conflicting" if previous_status != status else "duplicate"
                raise ControlArtifactError(
                    f"{qualifier} selection for {framework_id} {control_id}"
                )
            seen_controls[control_id] = status

            if status in {"excluded", "pending"}:
                _require_exact_keys(
                    control,
                    required={"id", "status"},
                    path=control_path,
                )
                normalized_controls.append({"id": control_id, "status": status})
                continue
            if status != "accepted":
                raise ControlArtifactError(
                    f"{control_path}.status must be accepted, excluded, or pending"
                )
            _require_exact_keys(
                control,
                required={
                    "id",
                    "status",
                    "contributions",
                    "project_interpretation",
                    "public_interpretation",
                    "evidence",
                    "limitations",
                },
                path=control_path,
            )
            contributions = control["contributions"]
            if not isinstance(contributions, list) or not contributions:
                raise ControlArtifactError(
                    f"{control_path}.contributions must be a non-empty array"
                )
            normalized_contributions = [
                _require_string(
                    contribution,
                    f"{control_path}.contributions[{index}]",
                    single_line=True,
                )
                for index, contribution in enumerate(contributions)
            ]
            if len(normalized_contributions) != len(set(normalized_contributions)):
                raise ControlArtifactError(
                    f"{control_path}.contributions must not contain duplicates"
                )
            unknown_contributions = sorted(
                set(normalized_contributions) - set(CONTRIBUTION_LABELS)
            )
            if unknown_contributions:
                raise ControlArtifactError(
                    f"{control_path}.contributions contains unsupported values: "
                    f"{', '.join(unknown_contributions)}"
                )
            evidence_items = control["evidence"]
            if not isinstance(evidence_items, list) or not evidence_items:
                raise ControlArtifactError(
                    f"{control_path}.evidence must be a non-empty array"
                )
            seen_evidence_ids: set[str] = set()
            normalized_evidence: list[dict[str, str]] = []
            for evidence_index, evidence_value in enumerate(evidence_items):
                evidence_path = f"{control_path}.evidence[{evidence_index}]"
                evidence = _require_object(evidence_value, evidence_path)
                _require_exact_keys(
                    evidence,
                    required={"id", "description", "href"},
                    path=evidence_path,
                )
                evidence_id = _require_token(evidence["id"], f"{evidence_path}.id")
                if evidence_id in seen_evidence_ids:
                    raise ControlArtifactError(
                        f"duplicate evidence id for {framework_id} {control_id}: "
                        f"{evidence_id}"
                    )
                seen_evidence_ids.add(evidence_id)
                normalized_evidence.append(
                    {
                        "id": evidence_id,
                        "description": _require_string(
                            evidence["description"],
                            f"{evidence_path}.description",
                            single_line=True,
                        ),
                        "href": _require_uri(
                            evidence["href"],
                            f"{evidence_path}.href",
                            relative_allowed=True,
                        ),
                    }
                )
            normalized_controls.append(
                {
                    "id": control_id,
                    "status": status,
                    "contributions": sorted(normalized_contributions),
                    "project_interpretation": _require_string(
                        control["project_interpretation"],
                        f"{control_path}.project_interpretation",
                    ),
                    "public_interpretation": _require_string(
                        control["public_interpretation"],
                        f"{control_path}.public_interpretation",
                    ),
                    "evidence": sorted(
                        normalized_evidence, key=lambda item: item["id"]
                    ),
                    "limitations": _require_string(
                        control["limitations"],
                        f"{control_path}.limitations",
                        single_line=True,
                    ),
                }
            )
        normalized_frameworks.append(
            {
                "id": framework_id,
                "name": _require_string(
                    framework["name"], f"{path}.name", single_line=True
                ),
                "version": _require_string(
                    framework["version"], f"{path}.version", single_line=True
                ),
                "reference": _require_uri(framework["reference"], f"{path}.reference"),
                "controls": sorted(
                    normalized_controls, key=lambda item: _natural_key(item["id"])
                ),
            }
        )
    return {
        "schema_version": SELECTION_SCHEMA_VERSION,
        "last_modified": _validated_timestamp(root["last_modified"]),
        "document_version": _require_string(
            root["document_version"], "document_version", single_line=True
        ),
        "synthetic_data": True,
        "public_safe": True,
        "component": normalized_component,
        "frameworks": sorted(
            normalized_frameworks,
            key=lambda item: (item["name"].casefold(), item["id"]),
        ),
    }


def _marker_props() -> list[dict[str, str]]:
    return [
        {"name": "public-safe", "ns": PROPERTY_NAMESPACE, "value": "true"},
        {"name": "synthetic-data", "ns": PROPERTY_NAMESPACE, "value": "true"},
        {
            "name": "claim-status",
            "ns": PROPERTY_NAMESPACE,
            "value": "implementation-evidence-only",
        },
    ]


def _accepted_controls(framework: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    return [
        control for control in framework["controls"] if control["status"] == "accepted"
    ]


def _catalog_document(
    selection: Mapping[str, Any], framework: Mapping[str, Any]
) -> dict[str, Any]:
    controls = [
        {
            "id": control["id"],
            "title": f"Selected control {control['id']}",
            "props": [
                {
                    "name": "selection-status",
                    "ns": PROPERTY_NAMESPACE,
                    "value": "accepted",
                },
                {
                    "name": "source-framework",
                    "ns": PROPERTY_NAMESPACE,
                    "value": framework["id"],
                },
            ],
        }
        for control in _accepted_controls(framework)
    ]
    catalog_without_uuid = {
        "metadata": {
            "title": f"Gluevenir selected {framework['name']} control identifiers",
            "last-modified": selection["last_modified"],
            "version": selection["document_version"],
            "oscal-version": OSCAL_VERSION,
            "props": _marker_props(),
            "links": [
                {
                    "href": framework["reference"],
                    "rel": "reference",
                    "text": f"Official {framework['name']} reference",
                }
            ],
            "remarks": (
                "This project-authored catalog contains selected identifiers only. "
                "It does not reproduce source control titles or control text and does "
                "not assert compliance, certification, assessment, or audit readiness."
            ),
        },
        "controls": controls,
    }
    catalog = {
        "uuid": _stable_uuid(f"catalog:{framework['id']}", catalog_without_uuid),
        **catalog_without_uuid,
    }
    return {
        "$schema": (
            f"http://csrc.nist.gov/ns/oscal/{OSCAL_VERSION}/oscal-catalog-schema.json"
        ),
        "catalog": catalog,
    }


def _component_document(
    selection: Mapping[str, Any], emitted_frameworks: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    implementation_skeletons: list[dict[str, Any]] = []
    for framework in emitted_frameworks:
        requirements: list[dict[str, Any]] = []
        for control in _accepted_controls(framework):
            evidence_links = [
                {
                    "href": evidence["href"],
                    "rel": "evidence",
                    "text": f"{evidence['id']}: {evidence['description']}",
                }
                for evidence in control["evidence"]
            ]
            requirements.append(
                {
                    "control-id": control["id"],
                    "description": control["project_interpretation"],
                    "props": [
                        *_marker_props(),
                        *[
                            {
                                "name": "contribution-category",
                                "ns": PROPERTY_NAMESPACE,
                                "value": contribution,
                            }
                            for contribution in control["contributions"]
                        ],
                        {
                            "name": "implementation-limitation",
                            "ns": PROPERTY_NAMESPACE,
                            "value": control["limitations"],
                        },
                    ],
                    "links": evidence_links,
                    "remarks": (
                        "Project-specific Gluevenir interpretation. This is not source "
                        "control text and is not a compliance or certification claim."
                    ),
                }
            )
        implementation_skeletons.append(
            {
                "source": f"./catalog-{framework['id']}.json",
                "description": (
                    "Gluevenir-specific implementation interpretations for selected "
                    f"{framework['name']} identifiers."
                ),
                "props": [
                    *_marker_props(),
                    {
                        "name": "source-framework",
                        "ns": PROPERTY_NAMESPACE,
                        "value": framework["id"],
                    },
                ],
                "links": [
                    {
                        "href": framework["reference"],
                        "rel": "reference",
                        "text": f"Official {framework['name']} reference",
                    }
                ],
                "implemented-requirements": requirements,
            }
        )

    component = selection["component"]
    component_skeleton: dict[str, Any] = {
        "type": component["type"],
        "title": component["title"],
        "description": component["description"],
        "props": _marker_props(),
        "remarks": component["claim_boundary"],
    }
    if implementation_skeletons:
        component_skeleton["control-implementations"] = implementation_skeletons
    definition_skeleton = {
        "metadata": {
            "title": f"{component['title']} public-safe control implementation",
            "last-modified": selection["last_modified"],
            "version": selection["document_version"],
            "oscal-version": OSCAL_VERSION,
            "props": _marker_props(),
            "remarks": component["claim_boundary"],
        },
        "components": [component_skeleton],
    }
    document_uuid = _stable_uuid("component-definition", definition_skeleton)
    implementations: list[dict[str, Any]] = []
    for framework, implementation in zip(
        emitted_frameworks, implementation_skeletons, strict=True
    ):
        requirements = [
            {
                "uuid": _stable_uuid(
                    "implemented-requirement",
                    {
                        "root": document_uuid,
                        "framework": framework["id"],
                        "requirement": requirement,
                    },
                ),
                **requirement,
            }
            for requirement in implementation["implemented-requirements"]
        ]
        implementations.append(
            {
                "uuid": _stable_uuid(
                    "control-implementation",
                    {
                        "root": document_uuid,
                        "framework": framework["id"],
                        "implementation": implementation,
                    },
                ),
                **{
                    name: value
                    for name, value in implementation.items()
                    if name != "implemented-requirements"
                },
                "implemented-requirements": requirements,
            }
        )
    component_uuid = _stable_uuid(
        "component", {"root": document_uuid, "component": component_skeleton}
    )
    rendered_component: dict[str, Any] = {
        "uuid": component_uuid,
        **{
            name: value
            for name, value in component_skeleton.items()
            if name != "control-implementations"
        },
    }
    if implementations:
        rendered_component["control-implementations"] = implementations
    return {
        "$schema": (
            f"http://csrc.nist.gov/ns/oscal/{OSCAL_VERSION}/"
            "oscal-component-definition-schema.json"
        ),
        "component-definition": {
            "uuid": document_uuid,
            "metadata": definition_skeleton["metadata"],
            "components": [rendered_component],
        },
    }


def _resolve_pointer(schema_root: Mapping[str, Any], reference: str) -> object:
    if not reference.startswith("#/"):
        raise ControlArtifactError(
            f"unsupported external schema reference: {reference}"
        )
    current: object = schema_root
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or part not in current:
            raise ControlArtifactError(f"invalid schema reference: {reference}")
        current = current[part]
    return current


def _schema_error(path: str, message: str) -> ControlArtifactError:
    return ControlArtifactError(f"generated OSCAL {path}: {message}")


def _validate_schema_subset(
    instance: object,
    schema: object,
    schema_root: Mapping[str, Any],
    path: str,
) -> None:
    """Validate the schema features reachable from generated OSCAL documents.

    This is intentionally not a general-purpose Draft 7 implementation. It makes
    generation fail closed offline while the integration owner decides whether to
    add a full JSON Schema dependency to shared project configuration.
    """

    if not isinstance(schema, Mapping):
        raise _schema_error(path, "schema node is not an object")
    if "$ref" in schema:
        _validate_schema_subset(
            instance,
            _resolve_pointer(schema_root, str(schema["$ref"])),
            schema_root,
            path,
        )
        return
    if "allOf" in schema:
        for child in schema["allOf"]:
            _validate_schema_subset(instance, child, schema_root, path)
    if "anyOf" in schema:
        errors: list[ControlArtifactError] = []
        for child in schema["anyOf"]:
            try:
                _validate_schema_subset(instance, child, schema_root, path)
                break
            except ControlArtifactError as error:
                errors.append(error)
        else:
            raise _schema_error(path, f"did not satisfy anyOf ({errors[0]})")
    if "oneOf" in schema:
        matches = 0
        for child in schema["oneOf"]:
            try:
                _validate_schema_subset(instance, child, schema_root, path)
                matches += 1
            except ControlArtifactError:
                pass
        if matches != 1:
            raise _schema_error(path, f"satisfied {matches} oneOf branches")
    if "const" in schema and instance != schema["const"]:
        raise _schema_error(path, f"must equal {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise _schema_error(path, "is not an allowed enum value")

    expected_type = schema.get("type")
    if expected_type is not None:
        type_checks = {
            "array": lambda value: isinstance(value, list),
            "boolean": lambda value: isinstance(value, bool),
            "integer": lambda value: (
                isinstance(value, int) and not isinstance(value, bool)
            ),
            "null": lambda value: value is None,
            "number": lambda value: (
                isinstance(value, (int, float)) and not isinstance(value, bool)
            ),
            "object": lambda value: isinstance(value, dict),
            "string": lambda value: isinstance(value, str),
        }
        allowed_types = (
            list(expected_type) if isinstance(expected_type, list) else [expected_type]
        )
        if not any(type_checks[str(item)](instance) for item in allowed_types):
            raise _schema_error(path, f"must be of type {expected_type}")

    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = [name for name in required if name not in instance]
        if missing:
            raise _schema_error(path, f"missing properties {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(instance) - set(properties))
            if unexpected:
                raise _schema_error(path, f"unexpected properties {unexpected}")
        for name, value in instance.items():
            if name in properties:
                _validate_schema_subset(
                    value, properties[name], schema_root, f"{path}.{name}"
                )
    elif isinstance(instance, list):
        minimum = schema.get("minItems")
        if minimum is not None and len(instance) < minimum:
            raise _schema_error(path, f"must contain at least {minimum} items")
        maximum = schema.get("maxItems")
        if maximum is not None and len(instance) > maximum:
            raise _schema_error(path, f"must contain at most {maximum} items")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                _validate_schema_subset(
                    item, item_schema, schema_root, f"{path}[{index}]"
                )
    elif isinstance(instance, str):
        minimum = schema.get("minLength")
        if minimum is not None and len(instance) < minimum:
            raise _schema_error(path, f"must contain at least {minimum} characters")
        pattern = schema.get("pattern")
        if pattern:
            if "\\p{L}" in pattern:
                matched = TOKEN_PATTERN.fullmatch(instance) is not None
            else:
                matched = re.search(str(pattern), instance) is not None
            if not matched:
                raise _schema_error(path, "does not match the required pattern")
        value_format = schema.get("format")
        if value_format == "uri":
            parsed = urlparse(instance)
            if not parsed.scheme:
                raise _schema_error(path, "must be a URI")
        elif value_format == "uri-reference":
            if any(character.isspace() for character in instance) or not instance:
                raise _schema_error(path, "must be a URI reference")
            parsed = urlparse(instance)
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                raise _schema_error(path, "must use HTTP(S) or be relative")
            if parsed.netloc and not parsed.scheme:
                raise _schema_error(path, "must not be scheme-relative")
        elif value_format == "date-time":
            try:
                parsed_datetime = datetime.fromisoformat(
                    instance.replace("Z", "+00:00")
                )
            except ValueError as error:
                raise _schema_error(path, "must be a date-time") from error
            if parsed_datetime.tzinfo is None:
                raise _schema_error(path, "date-time must include a timezone")


def validate_generated_document(
    document: Mapping[str, Any], *, schema_path: Path, root_key: str
) -> None:
    """Validate generated output against its vendored official OSCAL schema."""

    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ControlArtifactError(f"cannot load OSCAL schema {schema_path}") from error
    expected_id = (
        f"http://csrc.nist.gov/ns/oscal/{OSCAL_VERSION}/"
        f"oscal-{root_key.replace('_', '-')}-schema.json"
    )
    if schema.get("$id") != expected_id:
        raise ControlArtifactError(
            f"unexpected OSCAL schema id in {schema_path}: {schema.get('$id')!r}"
        )
    _validate_schema_subset(document, schema, schema, root_key)


def generate_control_documents(selection_document: object) -> dict[str, dict[str, Any]]:
    """Build deterministic catalogs and one component definition in memory."""

    selection = validate_selection(selection_document)
    emitted_frameworks = [
        framework
        for framework in selection["frameworks"]
        if _accepted_controls(framework)
    ]
    documents = {
        f"catalog-{framework['id']}.json": _catalog_document(selection, framework)
        for framework in emitted_frameworks
    }
    documents["gluevenir-component-definition.json"] = _component_document(
        selection, emitted_frameworks
    )
    for filename, document in documents.items():
        if filename.startswith("catalog-"):
            validate_generated_document(
                document,
                schema_path=CATALOG_SCHEMA,
                root_key="catalog",
            )
        else:
            validate_generated_document(
                document,
                schema_path=COMPONENT_SCHEMA,
                root_key="component_definition",
            )
    return dict(sorted(documents.items()))


def render_compliance_page(selection_document: object) -> str:
    """Render the standalone public page from public-safe generalized material."""

    selection = validate_selection(selection_document)
    try:
        template = COMPLIANCE_TEMPLATE.read_text(encoding="utf-8")
    except OSError as error:
        raise ControlArtifactError(
            f"cannot load compliance page template {COMPLIANCE_TEMPLATE}"
        ) from error
    if len(COMPLIANCE_CONTENT_PATTERN.findall(template)) != 1:
        raise ControlArtifactError(
            "compliance template must contain exactly one bounded content region"
        )

    accepted_frameworks = [
        framework
        for framework in selection["frameworks"]
        if _accepted_controls(framework)
    ]
    sections: list[str] = []
    for framework in accepted_frameworks:
        controls: list[str] = []
        for control in _accepted_controls(framework):
            badges = "".join(
                '<span class="contribution">'
                f"{html.escape(CONTRIBUTION_LABELS[item])}</span>"
                for item in control["contributions"]
            )
            evidence_items: list[str] = []
            for evidence in control["evidence"]:
                label = html.escape(evidence["description"])
                reference = html.escape(evidence["href"], quote=True)
                if urlparse(evidence["href"]).scheme in {"http", "https"}:
                    evidence_items.append(
                        f'<li><a href="{reference}" rel="noopener noreferrer">'
                        f"{label}</a></li>"
                    )
                else:
                    evidence_items.append(f"<li>{label} <code>{reference}</code></li>")
            controls.append(
                '<article class="control-card">'
                f'<div class="control-id">{html.escape(control["id"])}</div>'
                f'<div class="contributions">{badges}</div>'
                f"<p>{html.escape(control['public_interpretation'])}</p>"
                "<details><summary>Evidence and boundary</summary>"
                f"<ul>{''.join(evidence_items)}</ul>"
                f'<p class="limitation">{html.escape(control["limitations"])}</p>'
                "</details></article>"
            )
        sections.append(
            '<section class="framework">'
            '<div class="framework-heading">'
            f'<div><p class="eyebrow">{html.escape(framework["version"])}</p>'
            f"<h2>{html.escape(framework['name'])}</h2></div>"
            f'<a href="{html.escape(framework["reference"], quote=True)}" '
            'rel="noopener noreferrer">Official reference</a></div>'
            f'<div class="control-grid">{"".join(controls)}</div></section>'
        )

    if sections:
        mapping_content = "".join(sections)
        summary = (
            "Selected, strongly supported mappings are grouped by framework. "
            "Each statement describes Gluevenir's bounded technical contribution."
        )
    else:
        mapping_content = (
            '<section class="empty-state"><h2>Control selection is under review</h2>'
            "<p>No control mappings are published in this draft. Pending and excluded "
            "items are intentionally omitted.</p></section>"
        )
        summary = "No control mappings are published in this draft."

    content = (
        "<!-- GLUEVENIR_COMPLIANCE_CONTENT_START -->"
        '<main><header class="hero"><p class="eyebrow">IMPLEMENTATION EVIDENCE</p>'
        "<h1>Compliance mappings</h1>"
        f'<p class="lede">{html.escape(summary)}</p>'
        f'<p class="disclaimer">{html.escape(COMPLIANCE_DISCLAIMER)}</p>'
        f'<p class="updated">Reviewed selection: '
        f"{html.escape(selection['last_modified'])}</p></header>"
        f"{mapping_content}</main>"
        "<!-- GLUEVENIR_COMPLIANCE_CONTENT_END -->"
    )
    rendered, count = COMPLIANCE_CONTENT_PATTERN.subn(content, template, count=1)
    if count != 1 or rendered.count(COMPLIANCE_DISCLAIMER) != 1:
        raise ControlArtifactError(
            "generated compliance page must contain exactly one blanket disclaimer"
        )
    return rendered


def generate_control_artifacts(
    selection_path: Path, output_directory: Path
) -> dict[str, Path]:
    """Validate then atomically write artifacts to a new output directory."""

    if output_directory.exists():
        raise ControlArtifactError(
            "output directory already exists; use a new directory to prevent stale "
            "control artifacts"
        )
    try:
        selection_document = json.loads(selection_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ControlArtifactError(
            f"cannot load selection file {selection_path}"
        ) from error
    documents = generate_control_documents(selection_document)
    compliance_page = render_compliance_page(selection_document)

    output_directory.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{output_directory.name}-", dir=output_directory.parent
        )
    )
    try:
        for filename, document in documents.items():
            (temporary / filename).write_text(
                json.dumps(document, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        (temporary / "compliance.html").write_text(
            compliance_page,
            encoding="utf-8",
        )
        os.replace(temporary, output_directory)
    except BaseException:
        for path in temporary.glob("*"):
            path.unlink()
        temporary.rmdir()
        raise
    return {
        filename: output_directory / filename
        for filename in sorted([*documents, "compliance.html"])
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selection", type=Path)
    parser.add_argument("output_directory", type=Path)
    arguments = parser.parse_args(argv)
    generated = generate_control_artifacts(
        arguments.selection, arguments.output_directory
    )
    print(json.dumps({name: str(path) for name, path in generated.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
