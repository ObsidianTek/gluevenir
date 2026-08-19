from __future__ import annotations

import json
from pathlib import Path

import pytest

from gluevenir._demo_catalog import (
    _JOURNEYS,
    _DemoJourney,
    _DemoPersona,
    _journey_for,
    _journeys_for,
    _persona_token,
)


def test_each_persona_has_five_business_journeys_and_every_outcome() -> None:
    assert len(_JOURNEYS) == 20
    assert set(_JOURNEYS) == set(_DemoJourney)
    for persona in _DemoPersona:
        definitions = _journeys_for(persona)
        assert len(definitions) == 5
        assert {value.expected_decision for value in definitions} == {
            "ALLOW",
            "MODIFY",
            "STEP_UP",
            "DEFER",
            "DENY",
        }
        assert len({value.label for value in definitions}) == 5


def test_runtime_catalog_matches_the_public_fixture_contract() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "synthetic"
        / "demo_scenarios.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    expected = {
        item["journey_id"]: (
            item["persona_id"],
            item["label"],
            item["prompt"],
            item["expected_outcome"],
        )
        for item in fixture["journeys"]
    }

    assert {
        definition.journey.value: (
            definition.persona.value,
            definition.label,
            definition.example_prompt,
            definition.expected_decision,
        )
        for definition in _JOURNEYS.values()
    } == expected


def test_journey_lookup_rejects_cross_persona_authority() -> None:
    assert (
        _journey_for(_DemoPersona.PROGRAM_LEAD, _DemoJourney.PROGRAM_STATUS)
        == _JOURNEYS[_DemoJourney.PROGRAM_STATUS]
    )
    with pytest.raises(ValueError, match="not available"):
        _journey_for(_DemoPersona.EXTERNAL_PARTNER, _DemoJourney.PROGRAM_STATUS)


def test_persona_tokens_are_unique_bounded_demo_selectors() -> None:
    tokens = [_persona_token(persona) for persona in _DemoPersona]
    assert len(tokens) == len(set(tokens)) == 4
    assert all(token.endswith("-synthetic") for token in tokens)
