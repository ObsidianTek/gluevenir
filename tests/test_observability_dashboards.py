from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_ROOT = ROOT / "observability" / "shared" / "dashboards"
PROMETHEUS_UID = "gluevenir-prometheus"
EXPECTED_DASHBOARDS = {
    "governance-overview.json": "gluevenir-local-telemetry",
    "persona-governance.json": "gluevenir-persona-governance",
}
EMITTED_PROMETHEUS_LABELS = {
    "gluevenir_candidate_count",
    "gluevenir_decision",
    "gluevenir_excluded_count",
    "gluevenir_included_count",
    "gluevenir_model_invoked",
    "gluevenir_persona",
    "gluevenir_reason_code",
    "gluevenir_receipt_verified",
    "gluevenir_status",
}
FORBIDDEN_DATA_LABELS = {
    "gluevenir_actor_id",
    "gluevenir_agent_id",
    "gluevenir_answer",
    "gluevenir_content",
    "gluevenir_journey",
    "gluevenir_memory_id",
    "gluevenir_program_id",
    "gluevenir_prompt",
    "gluevenir_query",
    "gluevenir_receipt_id",
    "gluevenir_session_id",
    "gluevenir_tenant_id",
}


def _documents() -> dict[str, dict[str, object]]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(DASHBOARD_ROOT.glob("*.json"))
    }


def _targets(document: dict[str, object]) -> tuple[dict[str, object], ...]:
    return tuple(
        target for panel in document["panels"] for target in panel.get("targets", [])
    )


def _expressions(document: dict[str, object]) -> tuple[str, ...]:
    return tuple(str(target["expr"]) for target in _targets(document))


def _text(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True)


def test_canonical_dashboard_set_and_schema_are_frozen() -> None:
    documents = _documents()
    assert {name: document["uid"] for name, document in documents.items()} == (
        EXPECTED_DASHBOARDS
    )
    assert len({document["uid"] for document in documents.values()}) == 2

    for document in documents.values():
        assert document["editable"] is False
        assert document["schemaVersion"] == 40
        assert document["refresh"] == "5s"
        assert document["style"] == "dark"
        assert document["time"] == {"from": "now-30m", "to": "now"}
        assert document["timezone"] == "browser"
        assert "synthetic-telemetry-only" in document["tags"]
        assert document["title"].endswith("Synthetic only")
        panels = document["panels"]
        assert panels
        assert len({panel["id"] for panel in panels}) == len(panels)
        for panel in panels:
            assert panel["type"] in {
                "bargauge",
                "piechart",
                "stat",
                "table",
                "text",
                "timeseries",
            }
            grid = panel["gridPos"]
            assert 0 <= grid["x"] < 24
            assert 1 <= grid["w"] <= 24
            assert grid["x"] + grid["w"] <= 24
            assert grid["y"] >= 0
            assert grid["h"] >= 1


@pytest.mark.parametrize("filename", tuple(EXPECTED_DASHBOARDS))
def test_dashboard_panels_do_not_overlap(filename: str) -> None:
    panels = _documents()[filename]["panels"]
    for index, first in enumerate(panels):
        first_grid = first["gridPos"]
        for second in panels[index + 1 :]:
            second_grid = second["gridPos"]
            horizontal = (
                first_grid["x"] < second_grid["x"] + second_grid["w"]
                and second_grid["x"] < first_grid["x"] + first_grid["w"]
            )
            vertical = (
                first_grid["y"] < second_grid["y"] + second_grid["h"]
                and second_grid["y"] < first_grid["y"] + first_grid["h"]
            )
            assert not (horizontal and vertical), (
                first["id"],
                second["id"],
            )


def test_queries_use_only_bounded_emitted_fields_and_frozen_datasource() -> None:
    for document in _documents().values():
        for panel in document["panels"]:
            if "targets" not in panel:
                assert panel["type"] == "text"
                continue
            assert panel["datasource"] == {
                "type": "prometheus",
                "uid": PROMETHEUS_UID,
            }
        expressions = _expressions(document)
        assert expressions
        query_text = "\n".join(expressions)
        assert "increase(traces_span_metrics_calls_total" not in query_text
        used_labels = set(re.findall(r"gluevenir_[a-z_]+", query_text))
        assert used_labels <= EMITTED_PROMETHEUS_LABELS
        assert used_labels.isdisjoint(FORBIDDEN_DATA_LABELS)
        assert "traces_span_metrics_" in query_text
        assert "tenant" not in query_text
        assert "program_id" not in query_text
        assert "memory_id" not in query_text


def test_overview_has_required_governance_and_utility_surfaces() -> None:
    document = _documents()["governance-overview.json"]
    query_text = "\n".join(_expressions(document))
    title_text = "\n".join(panel.get("title", "") for panel in document["panels"])

    assert "gluevenir.gateway.evaluation" in query_text
    for outcome in ("ALLOW", "MODIFY", "STEP_UP", "DEFER", "DENY"):
        assert outcome in query_text
    assert "histogram_quantile(0.50" in query_text
    assert "histogram_quantile(0.95" in query_text
    assert 'gluevenir_model_invoked="true"' in query_text
    assert 'gluevenir_receipt_verified="true"' in query_text
    for count_label in (
        "gluevenir_candidate_count",
        "gluevenir_included_count",
        "gluevenir_excluded_count",
    ):
        assert count_label in query_text
    for title in (
        "Governed turns",
        "Five-outcome distribution",
        "Governed latency",
        "Model invocations",
        "Verified receipts",
        "Recall count profile",
        "Current task aggregate activity",
    ):
        assert title in title_text


def test_model_invocation_panels_count_only_emitted_true_model_stages() -> None:
    expected_overview = (
        'sum(traces_span_metrics_calls_total{span_name="gluevenir.model",'
        'gluevenir_model_invoked="true"})'
    )
    expected_persona = (
        'sum(traces_span_metrics_calls_total{span_name="gluevenir.model",'
        'gluevenir_persona=~"$persona",gluevenir_model_invoked="true"})'
    )

    documents = _documents()
    assert expected_overview in _expressions(documents["governance-overview.json"])
    assert expected_persona in _expressions(documents["persona-governance.json"])


def test_persona_detail_is_dynamic_and_every_query_is_persona_scoped() -> None:
    document = _documents()["persona-governance.json"]
    variables = document["templating"]["list"]
    assert len(variables) == 1
    variable = variables[0]
    assert variable["name"] == "persona"
    assert variable["type"] == "query"
    assert variable["multi"] is False
    assert variable["includeAll"] is False
    assert variable["refresh"] == 1
    assert variable["query"]["query"] == (
        "label_values(traces_span_metrics_calls_total{"
        'span_name="gluevenir.gateway.evaluation"},gluevenir_persona)'
    )
    expressions = _expressions(document)
    assert all('gluevenir_persona=~"$persona"' in expr for expr in expressions)
    assert "$persona" in _text(document)


def test_dashboard_copy_preserves_claim_and_privacy_boundaries() -> None:
    combined = "\n".join(_text(document) for document in _documents().values())
    lowered = combined.lower()
    assert "synthetic telemetry only" in lowered
    assert "aarm-inspired" in lowered
    assert "selected aiuc-1 implementation evidence" in lowered
    assert "not a conformance" in lowered
    assert "complete detection" in lowered
    assert lowered.count("current observability-task totals") == 4
    assert "recent bounded activity" not in lowered
    for prohibited_claim in (
        "aarm core",
        "aarm-conformant",
        "aiuc-1 ready",
        "hipaa compliant",
        "tamper-proof",
        "non-repudiable",
    ):
        assert prohibited_claim not in lowered


def test_approved_obsidian_accent_palette_is_present() -> None:
    combined = _text(_documents()["governance-overview.json"])
    for color in ("#48D597", "#F5B93C", "#4DA6FF", "#A875F5", "#FF4F57"):
        assert color in combined
    assert '"mode": "fixed-color"' not in combined
