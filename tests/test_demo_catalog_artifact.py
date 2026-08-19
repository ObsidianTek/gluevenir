from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.generate_demo_catalog import generate_catalog_bytes

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "site" / "demo-catalog.json"

UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-"
    r"[0-9a-f]{12}\b",
    re.IGNORECASE,
)
SHA256_PATTERN = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:postgres(?:ql)?|cockroachdb)://", re.IGNORECASE),
)
CONTACT_VALUE_PATTERNS = (
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?<!\w)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"),
)
FORBIDDEN_KEYS = {
    "actor_id",
    "actor_role",
    "approval_id",
    "content_sha256",
    "destination",
    "expected_outcome",
    "expires_at",
    "fixture_role",
    "has_authorized_internal_detail",
    "identity_authorized",
    "memory_id",
    "missing_context",
    "program_id",
    "requested_fixture_roles",
    "source_memory_id",
    "tenant_id",
    "valid_from",
    "vector",
    "visible_to_personas",
}


def _walk_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for nested in value.values():
            keys.update(_walk_keys(nested))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for nested in value:
            keys.update(_walk_keys(nested))
        return keys
    return set()


def _catalog() -> dict[str, Any]:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def test_generated_catalog_has_no_drift() -> None:
    assert CATALOG_PATH.read_bytes() == generate_catalog_bytes()


def test_catalog_exposes_four_personas_and_five_journeys_each() -> None:
    catalog = _catalog()
    assert catalog["synthetic_data"] is True
    assert catalog["schema_version"] == 2
    assert catalog["browse"] == {
        "default_hierarchy": ["persona", "workstream"],
        "default_view": "split-list-detail",
        "page_size": 12,
        "sticky_filters": [
            "search",
            "persona",
            "workstream",
            "status",
            "room",
            "source",
        ],
    }
    assert len(catalog["personas"]) == 4
    assert len(catalog["journeys"]) == 20

    journey_counts = Counter(journey["persona_id"] for journey in catalog["journeys"])
    assert set(journey_counts.values()) == {5}
    persona_ids = {persona["persona_id"] for persona in catalog["personas"]}
    assert set(journey_counts) == persona_ids
    journey_ids = {journey["journey_id"] for journey in catalog["journeys"]}
    assert all(
        persona["default_journey_id"] in journey_ids for persona in catalog["personas"]
    )
    assert all(journey["synthetic_data"] is True for journey in catalog["journeys"])


def test_catalog_memories_are_explicitly_synthetic_and_browseable() -> None:
    catalog = _catalog()
    assert len(catalog["memories"]) == 30
    assert {memory["workstream"] for memory in catalog["memories"]} == {
        "clinical",
        "formulation",
        "partner",
        "program",
    }
    assert {memory["room"] for memory in catalog["memories"]} == {
        "clinical-restricted",
        "external-approved",
        "research-confidential",
    }
    assert {memory["status"] for memory in catalog["memories"]} >= {
        "active",
        "expired",
        "forgotten",
        "proposed",
        "quarantined",
        "revoked",
    }
    for memory in catalog["memories"]:
        assert memory["synthetic_data"] is True
        assert memory["catalog_key"].startswith("memory-")
        assert memory["title"].strip()
        assert memory["realism_note"].strip()
        if memory["summary"] is not None:
            assert not memory["summary"].startswith("SYNTHETIC DATA: ")
        assert memory["effective_date"].startswith("2026-")
        assert memory["program"] in {"HX-17", "HX-23", "VX-17"}

    by_title = {memory["title"]: memory for memory in catalog["memories"]}
    assert by_title["HX-23 wrong-program status decoy"]["program"] == "HX-23"
    assert by_title["Cross-tenant semantic decoy"]["workstream"] == "partner"
    assert by_title["Unauthorized audience release draft"]["status"] == "proposed"
    assert by_title["Approved partner program overview"]["room"] == (
        "external-approved"
    )


def test_persona_focus_is_editorial_workstream_taxonomy_not_authority() -> None:
    catalog = _catalog()
    assert {
        persona["persona_id"]: persona["featured_workstreams"]
        for persona in catalog["personas"]
    } == {
        "program_lead": ["program"],
        "formulation_scientist": ["formulation"],
        "clinical_operations_lead": ["clinical"],
        "authorized_external_partner": ["partner"],
    }
    assert "visible_to_personas" not in CATALOG_PATH.read_text(encoding="utf-8")
    assert (
        "Persona focus is an editorial browsing cue only" in catalog["privacy_boundary"]
    )


def test_catalog_links_only_to_declared_public_sources() -> None:
    catalog = _catalog()
    source_keys = {source["source_key"] for source in catalog["sources"]}
    assert len(source_keys) == 4
    for source in catalog["sources"]:
        assert source["url"].startswith("https://")
        assert source["generic_structure_only"] is True
        assert source["endorsement"] is False
    for item in [*catalog["journeys"], *catalog["memories"]]:
        assert set(item["source_keys"]) <= source_keys

    sources = {source["source_key"]: source for source in catalog["sources"]}
    assert sources["fda-m11"]["url"] == (
        "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/"
        "m11-clinical-electronic-structured-harmonised-protocol"
    )


def test_catalog_omits_runtime_authority_and_sensitive_technical_fields() -> None:
    catalog_bytes = CATALOG_PATH.read_bytes()
    catalog_text = catalog_bytes.decode()
    catalog = json.loads(catalog_text)

    assert not (_walk_keys(catalog) & FORBIDDEN_KEYS)
    assert UUID_PATTERN.search(catalog_text) is None
    assert SHA256_PATTERN.search(catalog_text) is None
    assert all(pattern.search(catalog_text) is None for pattern in SECRET_PATTERNS)
    assert all(
        pattern.search(catalog_text) is None for pattern in CONTACT_VALUE_PATTERNS
    )
    assert "derivative_approvals" not in catalog_text
    assert "persona_token" not in catalog_text
    assert "expected_outcome" not in catalog_text

    assert "maya.ellison@example.test" not in catalog_text
    assert "202-555-0147" not in catalog_text

    by_title = {memory["title"]: memory for memory in catalog["memories"]}
    for title in (
        "SYN-HX17-004 Day 42 follow-up",
        "SYN-HX17-004 restricted contact record",
    ):
        details = by_title[title]["details"]
        assert "synthetic_email" not in details
        assert "synthetic_phone" not in details
        assert details["participant_name"] == "Maya Ellison"
        assert "intentionally omitted" in by_title[title]["summary"]
