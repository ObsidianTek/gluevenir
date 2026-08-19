#!/usr/bin/env python3
"""Generate the privacy-bounded static catalog for the synthetic demo UI."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS_PATH = ROOT / "fixtures" / "synthetic" / "demo_scenarios.json"
MEMORIES_PATH = ROOT / "fixtures" / "synthetic" / "memory_records.json"
SOURCES_PATH = ROOT / "fixtures" / "synthetic" / "public_sources.json"
OUTPUT_PATH = ROOT / "site" / "demo-catalog.json"

_PERSONA_WORKSTREAMS = {
    "program_lead": ("program",),
    "formulation_scientist": ("formulation",),
    "clinical_operations_lead": ("clinical",),
    "authorized_external_partner": ("partner",),
}
_CONTACT_FIELD_MARKERS = ("contact", "email", "phone")
_EMAIL_VALUE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PHONE_VALUE = re.compile(
    r"(?<!\w)(?:\+?1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"
)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source_file:
        return json.load(source_file)


def build_catalog(
    scenarios: Mapping[str, Any],
    memories: Mapping[str, Any],
    sources: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the public presentation projection of the synthetic fixtures."""
    personas = [
        {
            "persona_id": persona["persona_id"],
            "display_name": persona["display_name"],
            "person_name": persona["person_name"],
            "organization": persona["organization"],
            "default_journey_id": persona["default_journey_id"],
            "featured_workstreams": list(_PERSONA_WORKSTREAMS[persona["persona_id"]]),
            "synthetic_data": True,
        }
        for persona in sorted(
            scenarios["personas"], key=lambda item: item["persona_id"]
        )
    ]
    journeys = [
        {
            "journey_id": journey["journey_id"],
            "persona_id": journey["persona_id"],
            "label": journey["label"],
            "prompt": journey["prompt"],
            "situation": journey["situation"],
            "source_keys": sorted(journey["source_basis_ids"]),
            "synthetic_data": True,
        }
        for journey in sorted(
            scenarios["journeys"],
            key=lambda item: (item["persona_id"], item["journey_id"]),
        )
    ]

    sorted_memories = sorted(
        memories["records"],
        key=lambda item: (
            item["workstream"],
            item["display_title"],
            item["memory_id"],
        ),
    )
    public_memories = []
    for index, memory in enumerate(sorted_memories, start=1):
        status = (
            "expired" if memory.get("lifecycle_case") == "expired" else memory["state"]
        )
        public_memories.append(
            {
                "catalog_key": f"memory-{index:03d}",
                "title": memory["display_title"],
                "workstream": memory["workstream"],
                "record_type": memory["record_type"],
                "room": memory["room"],
                "summary": _presentation_summary(memory),
                "data_classes": sorted(memory["data_classes"]),
                "status": status,
                "effective_date": memory["valid_from"][:10],
                "program": memory["program_code"],
                "details": _public_details(memory.get("catalog_fields", {})),
                "realism_note": memory["realism_note"],
                "source_keys": sorted(memory["source_basis_ids"]),
                "synthetic_data": True,
            }
        )

    public_sources = [
        {
            "source_key": source["source_id"],
            "publisher": source["publisher"],
            "title": source["title"],
            "url": source["url"],
            "used_for": sorted(source["used_for"]),
            "not_used_for": sorted(source["not_used_for"]),
            "generic_structure_only": source["generic_structure_only"],
            "endorsement": source["endorsement"],
        }
        for source in sorted(sources["sources"], key=lambda item: item["source_id"])
    ]

    return {
        "schema_version": 2,
        "synthetic_data": True,
        "synthetic_notice": (
            "Every organization, program, person, protocol, event, result, memory, "
            "decision, and approval shown in this catalog is wholly fictional."
        ),
        "privacy_boundary": (
            "This presentation-only catalog omits contact values, runtime "
            "identifiers, hashes, approval records, vectors, credentials, policy "
            "oracles, and authorization inputs. Persona focus is an editorial "
            "browsing cue only and never grants access or changes a gateway decision."
        ),
        "browse": {
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
        },
        "personas": personas,
        "journeys": journeys,
        "memories": public_memories,
        "sources": public_sources,
    }


def _presentation_summary(memory: Mapping[str, Any]) -> str | None:
    """Return the explicitly synthetic public training summary."""
    content = memory.get("catalog_summary", memory["content"])
    if content is None:
        return None
    marker = "SYNTHETIC DATA: "
    public_text = content.removeprefix(marker)
    detail_keys = memory.get("catalog_fields", {})
    has_contact_fields = any(
        field_marker in key.casefold()
        for key in detail_keys
        for field_marker in _CONTACT_FIELD_MARKERS
    )
    if (
        has_contact_fields
        or _EMAIL_VALUE.search(public_text)
        or _PHONE_VALUE.search(public_text)
    ):
        return (
            f"{memory['display_title']} is a wholly fictional training record. "
            "Its scheduling and contact values are intentionally omitted from the "
            "public catalog."
        )
    return public_text


def _public_details(details: Mapping[str, Any]) -> dict[str, str]:
    """Remove contact-value fields from the public presentation projection."""
    return {
        key: value
        for key, value in details.items()
        if not any(marker in key.casefold() for marker in _CONTACT_FIELD_MARKERS)
    }


def render_catalog(catalog: Mapping[str, Any]) -> bytes:
    """Render a stable JSON artifact suitable for byte-for-byte drift checks."""
    return (
        json.dumps(catalog, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode()


def generate_catalog_bytes() -> bytes:
    """Load the canonical fixtures and render the public catalog in memory."""
    return render_catalog(
        build_catalog(
            _load_json(SCENARIOS_PATH),
            _load_json(MEMORIES_PATH),
            _load_json(SOURCES_PATH),
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="output path (default: site/demo-catalog.json)",
    )
    arguments = parser.parse_args(argv)
    arguments.output.write_bytes(generate_catalog_bytes())
    print(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
