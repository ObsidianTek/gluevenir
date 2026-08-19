#!/usr/bin/env python3
"""Generate variable-free Grafana dashboards for external public sharing."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

OVERVIEW_UID = "gluevenir-local-telemetry"
PUBLIC_PERSONAS = (
    (
        "program_lead",
        "Program Lead",
        "gv-persona-program-lead",
        "9ab2bc2d01e29b2c642e14ccba48b9de",
    ),
    (
        "formulation_scientist",
        "Formulation Scientist",
        "gv-persona-formulation-scientist",
        "df2d55ae6508a21e8f5f0a083cb455ed",
    ),
    (
        "clinical_operations_lead",
        "Clinical Operations Lead",
        "gv-persona-clinical-ops-lead",
        "ba2e6408c254887fc6567c71efa533f0",
    ),
    (
        "authorized_external_partner",
        "Authorized External Partner",
        "gv-persona-external-partner",
        "e8827e00c81371176c524f34461e67d8",
    ),
)
OVERVIEW_TOKEN = "9e978d5eafa627ea61946044a80f3a41"


def _replace_strings(value: object, old: str, new: str) -> object:
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [_replace_strings(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: _replace_strings(item, old, new) for key, item in value.items()}
    return value


def _public_link(title: str, token: str) -> dict[str, object]:
    return {
        "asDropdown": False,
        "icon": "external link",
        "includeVars": False,
        "keepTime": True,
        "targetBlank": False,
        "title": title,
        "tooltip": "Open the fixed, synthetic-only public telemetry view.",
        "type": "link",
        "url": f"/public-dashboards/{token}",
    }


def generate_public_dashboards(input_dir: Path, output_dir: Path) -> tuple[Path, ...]:
    """Write one overview and four fixed-persona external-share dashboards."""

    if output_dir.exists():
        raise ValueError("output directory already exists")
    overview = json.loads(
        (input_dir / "governance-overview.json").read_text(encoding="utf-8")
    )
    persona_template = json.loads(
        (input_dir / "persona-governance.json").read_text(encoding="utf-8")
    )
    if overview.get("uid") != OVERVIEW_UID or persona_template.get("uid") != (
        "gluevenir-persona-governance"
    ):
        raise ValueError("canonical dashboard UID drifted")
    output_dir.mkdir(parents=True)

    overview = copy.deepcopy(overview)
    overview["links"] = [
        _public_link(display_name, token)
        for _persona_id, display_name, _uid, token in PUBLIC_PERSONAS
    ]
    paths = [output_dir / "governance-overview.json"]
    paths[0].write_text(
        json.dumps(overview, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    overview_link = _public_link("Governance overview", OVERVIEW_TOKEN)
    for persona_id, display_name, uid, _token in PUBLIC_PERSONAS:
        dashboard = _replace_strings(
            copy.deepcopy(persona_template), "$persona", persona_id
        )
        if not isinstance(dashboard, dict):
            raise TypeError("generated dashboard is invalid")
        dashboard["uid"] = uid
        dashboard["title"] = (
            f"Gluevenir Bio · {display_name} governance detail · Synthetic only"
        )
        dashboard["templating"] = {"list": []}
        dashboard["tags"] = [
            *dashboard["tags"],
            f"persona-{persona_id.replace('_', '-')}",
            "fixed-public-persona",
        ]
        dashboard["links"] = [
            overview_link,
            *(
                _public_link(other_display, other_token)
                for other_id, other_display, _other_uid, other_token in PUBLIC_PERSONAS
                if other_id != persona_id
            ),
        ]
        dashboard["panels"][0]["options"]["content"] = (
            f"# {display_name} governance detail\n"
            "**Synthetic telemetry only.** This fixed public view filters bounded "
            f"observations to the server-mapped `{persona_id}` demo persona. It "
            "does not derive authority from browser input."
        )
        dashboard["panels"][1]["options"]["content"] = (
            f"### Observed persona scope\n**{display_name}** · `{persona_id}`\n\n"
            "Purpose, audience, memory room, journey, and organizational identity "
            "are intentionally absent from exported telemetry."
        )
        path = output_dir / f"persona-{persona_id.replace('_', '-')}.json"
        path.write_text(
            json.dumps(dashboard, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        paths.append(path)
    return tuple(paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    generate_public_dashboards(args.input_dir, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
