from __future__ import annotations

import re

from scripts.generate_control_artifacts import (
    COMPLIANCE_DISCLAIMER,
    render_compliance_page,
)


def _selection() -> dict[str, object]:
    control = {
        "status": "accepted",
        "contributions": ["provides_evidence"],
        "project_interpretation": "PROJECT-ONLY implementation detail.",
        "public_interpretation": "A generalized public explanation.",
        "evidence": [
            {
                "id": "fixture-evidence",
                "description": "Fixture verification",
                "href": "../tests/fixture.py",
            }
        ],
        "limitations": "Fixture scope only.",
    }
    return {
        "schema_version": "1.0",
        "last_modified": "2026-08-17T18:00:00Z",
        "document_version": "test",
        "synthetic_data": True,
        "public_safe": True,
        "component": {
            "title": "Fixture component",
            "type": "software",
            "description": "Fixture component description.",
            "claim_boundary": "Fixture boundary.",
        },
        "frameworks": [
            {
                "id": "zeta-fixture",
                "name": "Zeta Fixture Framework",
                "version": "test",
                "reference": "https://example.test/zeta",
                "controls": [
                    {"id": "Z.10", **control},
                    {"id": "Z.2", **control},
                    {"id": "Z.1", "status": "pending"},
                ],
            },
            {
                "id": "alpha-fixture",
                "name": "Alpha Fixture Framework",
                "version": "test",
                "reference": "https://example.test/alpha",
                "controls": [{"id": "A.1", **control}],
            },
        ],
    }


def test_page_is_alphabetical_public_safe_and_uses_public_interpretation() -> None:
    page = render_compliance_page(_selection())

    assert page.index("Alpha Fixture Framework") < page.index("Zeta Fixture Framework")
    assert page.index("Z.2") < page.index("Z.10")
    assert '<div class="control-id">Z.1</div>' not in page
    assert "A generalized public explanation." in page
    assert "PROJECT-ONLY" not in page
    assert page.count(COMPLIANCE_DISCLAIMER) == 1
    assert "Provides evidence" in page


def test_page_escapes_reviewed_public_values() -> None:
    selection = _selection()
    selection["frameworks"][0]["controls"][0]["public_interpretation"] = (
        "Visible <script>alert(1)</script> explanation."
    )
    page = render_compliance_page(selection)

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_checked_in_page_uses_locked_complete_three_tier_review() -> None:
    from scripts.generate_control_artifacts import COMPLIANCE_TEMPLATE

    page = COMPLIANCE_TEMPLATE.read_text(encoding="utf-8")
    assert "01 / AGENTIC RUNTIME" in page
    assert "02 / AI GOVERNANCE" in page
    assert "03 / SECURITY AND ASSURANCE" in page
    assert page.index("<h3>AARM v1.0</h3>") < page.index("<h3>AIUC-1</h3>")
    assert page.index("<h3>CSA AI Controls Matrix") < page.index(
        "<h3>ISO/IEC 42001</h3>"
    )
    assert page.index("<h3>ISO/IEC 27001</h3>") < page.index(
        "<h3>SOC 2 Trust Services Criteria</h3>"
    )
    assert page.count(COMPLIANCE_DISCLAIMER) == 1
    assert page.count('class="control-card"') == 82
    assert page.count("General project interpretation") == 82
    assert page.count("Gluevenir-specific interpretation") == 82
    assert "Inspired by standards. Bounded by evidence." not in page
    assert "No control mappings are published in this draft." not in page
    assert '<a href="#agentic">Standards</a>' not in page
    assert (
        "https://www.obsidiantek.io/?utm_source=gluevenir&amp;"
        "utm_medium=referral&amp;utm_campaign=agentic_memory_hackathon"
    ) in page
    assert 'href="https://www.linkedin.com/company/obsidiantek/"' in page
    assert 'href="https://www.linkedin.com/in/kris-musard/"' in page
    assert "Original control" not in page
    assert "B005.1 through B005.4" not in page
    assert '<link rel="icon" type="image/svg+xml" href="./assets/favicon.svg">' in page
    aiuc_links = re.findall(
        r'<a class="control-link" href="([^"]+)" target="_blank" '
        r'rel="noopener noreferrer"[^>]*><code>([A-E][0-9]{3}\.[0-9]+)</code></a>',
        page,
    )
    assert len(aiuc_links) == 21
    assert dict((identifier, href) for href, identifier in aiuc_links)["A003.1"] == (
        "https://www.aiuc-1.com/data-and-privacy/implement-contextual-data-safeguards"
    )
    assert dict((identifier, href) for href, identifier in aiuc_links)["E016.4"] == (
        "https://www.aiuc-1.com/accountability/implement-ai-disclosure-mechanisms"
    )
    for reference in (
        "https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1",
        "https://www.iso.org/standard/27017",
        "https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022",
    ):
        assert f'href="{reference}"' in page
    assert all(
        'target="_blank" rel="noopener noreferrer"' in anchor
        for anchor in re.findall(r'<a href="https://[^>]+>Official reference</a>', page)
    )
    for identifier in (
        "R8",
        "E016.4",
        "LOG-09",
        "A.8.5",
        "8.35",
        "A.3.2",
        "PI1.4",
    ):
        assert f"<code>{identifier}</code>" in page
    assert "\N{EM DASH}" not in page
