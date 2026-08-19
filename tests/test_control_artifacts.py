from __future__ import annotations

import copy
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from scripts.generate_control_artifacts import (
    CATALOG_SCHEMA,
    COMPONENT_SCHEMA,
    ControlArtifactError,
    generate_control_artifacts,
    generate_control_documents,
    render_compliance_page,
    validate_generated_document,
    validate_selection,
)


def _selection() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "last_modified": "2026-08-17T16:00:00Z",
        "document_version": "0.1.0",
        "synthetic_data": True,
        "public_safe": True,
        "component": {
            "title": "Gluevenir governed memory runtime",
            "type": "software",
            "description": (
                "A deterministic memory action gateway around supported memory "
                "operations."
            ),
            "claim_boundary": (
                "Implementation evidence only; not a compliance, certification, "
                "assessment, or audit-readiness claim."
            ),
        },
        "frameworks": [
            {
                "id": "iso-27001-2022",
                "name": "ISO/IEC 27001:2022",
                "version": "2022",
                "reference": "https://www.iso.org/standard/27001",
                "controls": [
                    {"id": "A.8.10", "status": "excluded"},
                    {
                        "id": "A.8.11",
                        "status": "accepted",
                        "contributions": [
                            "provides_evidence",
                            "helps_implement_guidance",
                        ],
                        "project_interpretation": (
                            "Gluevenir applies project-defined masking and exact Safe "
                            "Derivative substitution before restricted memory reaches "
                            "an external model prompt."
                        ),
                        "public_interpretation": (
                            "Gluevenir substitutes approved context before restricted "
                            "memory reaches an external model."
                        ),
                        "evidence": [
                            {
                                "id": "safe-derivative-test",
                                "description": "Exact approved substitution test",
                                "href": "../tests/test_gateway.py",
                            },
                            {
                                "id": "synthetic-scenario",
                                "description": "Synthetic MODIFY scenario",
                                "href": "../evidence/demo-scenarios.json",
                            },
                        ],
                        "limitations": (
                            "Coverage is limited to supported Gluevenir memory actions "
                            "and synthetic demo data."
                        ),
                    },
                    {"id": "A.8.13", "status": "pending"},
                ],
            },
            {
                "id": "soc2-2017",
                "name": "AICPA Trust Services Criteria",
                "version": "2017",
                "reference": "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
                "controls": [
                    {"id": "CC6.1", "status": "pending"},
                    {"id": "CC6.2", "status": "excluded"},
                ],
            },
        ],
    }


def _component(documents: dict[str, dict[str, object]]) -> dict[str, object]:
    return documents["gluevenir-component-definition.json"]["component-definition"]


def test_generation_is_deterministic_and_emits_only_accepted_controls() -> None:
    first = generate_control_documents(_selection())
    reordered = _selection()
    reordered["frameworks"] = list(reversed(reordered["frameworks"]))
    reordered["frameworks"][1]["controls"] = list(
        reversed(reordered["frameworks"][1]["controls"])
    )
    second = generate_control_documents(reordered)

    assert first == second
    assert set(first) == {
        "catalog-iso-27001-2022.json",
        "gluevenir-component-definition.json",
    }
    rendered = json.dumps(first, sort_keys=True)
    assert "A.8.11" in rendered
    assert "A.8.10" not in rendered
    assert "A.8.13" not in rendered
    assert "CC6.1" not in rendered
    assert "CC6.2" not in rendered
    assert "pending" not in rendered
    assert "excluded" not in rendered
    assert "Selected control A.8.11" in rendered
    assert "source control text" in rendered

    component = _component(first)
    implementation = component["components"][0]["control-implementations"][0]
    requirement = implementation["implemented-requirements"][0]
    assert requirement["description"].startswith("Gluevenir applies")
    assert len(requirement["links"]) == 2
    assert any(
        prop["name"] == "implementation-limitation" for prop in requirement["props"]
    )
    assert {
        prop["value"]
        for prop in requirement["props"]
        if prop["name"] == "contribution-category"
    } == {"provides_evidence", "helps_implement_guidance"}


def test_every_emitted_document_is_public_safe_and_synthetic_marked() -> None:
    documents = generate_control_documents(_selection())
    for document in documents.values():
        root = document.get("catalog") or document["component-definition"]
        markers = {prop["name"]: prop["value"] for prop in root["metadata"]["props"]}
        assert markers == {
            "public-safe": "true",
            "synthetic-data": "true",
            "claim-status": "implementation-evidence-only",
        }
        assert "not" in root["metadata"]["remarks"].lower()


def test_output_content_changes_rotate_document_uuids() -> None:
    original = generate_control_documents(_selection())
    changed_selection = _selection()
    changed_selection["frameworks"][0]["controls"][1]["project_interpretation"] += (
        " The runtime also records a content-safe policy outcome."
    )
    changed = generate_control_documents(changed_selection)

    assert (
        original["catalog-iso-27001-2022.json"]["catalog"]["uuid"]
        == changed["catalog-iso-27001-2022.json"]["catalog"]["uuid"]
    )
    assert _component(original)["uuid"] != _component(changed)["uuid"]
    original_requirement = _component(original)["components"][0][
        "control-implementations"
    ][0]["implemented-requirements"][0]
    changed_requirement = _component(changed)["components"][0][
        "control-implementations"
    ][0]["implemented-requirements"][0]
    assert original_requirement["uuid"] != changed_requirement["uuid"]

    timestamp_change = _selection()
    timestamp_change["last_modified"] = "2026-08-17T16:01:00Z"
    later = generate_control_documents(timestamp_change)
    assert (
        original["catalog-iso-27001-2022.json"]["catalog"]["uuid"]
        != later["catalog-iso-27001-2022.json"]["catalog"]["uuid"]
    )
    assert _component(original)["uuid"] != _component(later)["uuid"]

    unselected_change = _selection()
    unselected_change["frameworks"][0]["controls"][0]["status"] = "pending"
    assert generate_control_documents(unselected_change) == original


def test_all_generated_uuids_are_deterministic_version_five() -> None:
    documents = generate_control_documents(_selection())

    def collect(value: object) -> list[str]:
        if isinstance(value, dict):
            own = [value["uuid"]] if "uuid" in value else []
            return own + [item for child in value.values() for item in collect(child)]
        if isinstance(value, list):
            return [item for child in value for item in collect(child)]
        return []

    values = collect(documents)
    assert values
    assert len(values) == len(set(values))
    assert all(uuid.UUID(value).version == 5 for value in values)


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda value: value["frameworks"][0]["controls"].append(
                {"id": "A.8.11", "status": "excluded"}
            ),
            "conflicting selection",
        ),
        (
            lambda value: value["frameworks"][0]["controls"].append(
                {"id": "A.8.10", "status": "excluded"}
            ),
            "duplicate selection",
        ),
        (
            lambda value: value["frameworks"][0]["controls"][1].update(
                {"original_control_text": "must never be represented"}
            ),
            "unsupported fields",
        ),
        (
            lambda value: value.update({"public_safe": False}),
            "must both be true",
        ),
        (
            lambda value: value.update({"last_modified": "2026-08-17T16:00:00-04:00"}),
            "explicit UTC timestamp",
        ),
        (
            lambda value: value["frameworks"][0]["controls"][1]["evidence"][0].update(
                {"href": "javascript:alert(1)"}
            ),
            "must use HTTP",
        ),
        (
            lambda value: value["frameworks"][0]["controls"][1].update(
                {"contributions": [{"not": "a string"}]}
            ),
            "must be a non-empty trimmed string",
        ),
    ],
)
def test_malformed_duplicate_and_conflicting_selections_fail_closed(
    mutator, match: str
) -> None:
    selection = _selection()
    mutator(selection)
    with pytest.raises(ControlArtifactError, match=match):
        validate_selection(selection)


def test_unselected_controls_cannot_carry_interpretation_material() -> None:
    selection = _selection()
    selection["frameworks"][0]["controls"][0]["public_interpretation"] = "should fail"
    with pytest.raises(ControlArtifactError, match="unsupported fields"):
        generate_control_documents(selection)


def test_empty_draft_is_valid_and_emits_no_invented_mapping() -> None:
    selection = _selection()
    selection["frameworks"] = []
    documents = generate_control_documents(selection)
    assert set(documents) == {"gluevenir-component-definition.json"}
    component = _component(documents)["components"][0]
    assert "control-implementations" not in component
    page = render_compliance_page(selection)
    assert "No control mappings are published in this draft." in page
    assert "Selected control" not in page


def test_pending_only_review_is_not_published_as_accepted() -> None:
    selection = _selection()
    selection["frameworks"][0]["controls"] = [{"id": "A.8.11", "status": "pending"}]
    documents = generate_control_documents(selection)
    assert set(documents) == {"gluevenir-component-definition.json"}
    page = render_compliance_page(selection)
    assert "A.8.11" not in page
    assert "No control mappings are published in this draft." in page


def test_official_schema_contract_rejects_mutated_output() -> None:
    documents = generate_control_documents(_selection())
    catalog = copy.deepcopy(documents["catalog-iso-27001-2022.json"])
    catalog["catalog"]["unexpected"] = True
    with pytest.raises(ControlArtifactError, match="unexpected properties"):
        validate_generated_document(
            catalog, schema_path=CATALOG_SCHEMA, root_key="catalog"
        )

    component = copy.deepcopy(documents["gluevenir-component-definition.json"])
    del component["component-definition"]["metadata"]["last-modified"]
    with pytest.raises(ControlArtifactError, match="missing properties"):
        validate_generated_document(
            component,
            schema_path=COMPONENT_SCHEMA,
            root_key="component_definition",
        )


def test_file_generation_is_atomic_and_refuses_stale_directory(tmp_path: Path) -> None:
    source = tmp_path / "selection.json"
    source.write_text(json.dumps(_selection()), encoding="utf-8")
    output = tmp_path / "generated"
    paths = generate_control_artifacts(source, output)
    assert set(paths) == {
        "catalog-iso-27001-2022.json",
        "compliance.html",
        "gluevenir-component-definition.json",
    }
    assert all(path.is_file() for path in paths.values())

    with pytest.raises(ControlArtifactError, match="already exists"):
        generate_control_artifacts(source, output)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{}", encoding="utf-8")
    never_created = tmp_path / "never-created"
    with pytest.raises(ControlArtifactError):
        generate_control_artifacts(malformed, never_created)
    assert not never_created.exists()


def test_public_selection_schema_has_no_source_control_text_surface() -> None:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "controls"
        / ("control-selection.schema.json")
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    rendered = json.dumps(schema, sort_keys=True)
    assert schema["properties"]["public_safe"] == {"const": True}
    assert schema["properties"]["synthetic_data"] == {"const": True}
    assert "original_control_text" not in rendered
    assert "control_title" not in rendered
    assert "project_interpretation" in rendered
    assert "public_interpretation" in rendered
    assert "aarm_aiuc_runtime_protection" in rendered
    assert (
        "control titles are intentionally not represented"
        in schema["description"].lower()
    )


def test_vendored_official_oscal_schema_identity_and_hashes_are_frozen() -> None:
    expected = {
        CATALOG_SCHEMA: (
            "http://csrc.nist.gov/ns/oscal/1.2.3/oscal-catalog-schema.json",
            "ab95836e9e8dfeb6fde80007f6cc76fa3192f595d427c751a3f3923c3f474fc2",
        ),
        COMPONENT_SCHEMA: (
            "http://csrc.nist.gov/ns/oscal/1.2.3/"
            "oscal-component-definition-schema.json",
            "95e76881151ececd5cb1a93ff0f70ad74b8cc1aa58771626ac8b262bf2c8e001",
        ),
    }
    for path, (schema_id, digest) in expected.items():
        content = path.read_bytes()
        assert json.loads(content)["$id"] == schema_id
        assert hashlib.sha256(content).hexdigest() == digest
