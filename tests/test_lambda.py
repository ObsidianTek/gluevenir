from __future__ import annotations

import json
from collections.abc import Mapping
from uuid import UUID

import pytest

from gluevenir._demo_catalog import (
    _JOURNEYS,
    _DemoJourney,
    _DemoPersona,
    _persona_token,
)
from gluevenir._lambda import (
    _SyntheticRequest,
    create_lambda_handler,
)

ORIGIN = "https://gluevenir.obsidiantek.io"
HASH = "a" * 64
JSON_HEADERS = {"content-type": "application/json"}
TURN_ID = "90000000-0000-4000-8000-000000000001"
DEFAULT_QUERY = "What changed in the synthetic HX-17 program status?"
ALLOW_BODY = json.dumps(
    {
        "journey_id": "program-current-status",
        "persona": "program_lead",
        "persona_token": "program-lead-synthetic",
        "query": DEFAULT_QUERY,
        "turn_id": TURN_ID,
    }
)


def event(method="POST", path="/v1/demo", body=ALLOW_BODY, headers=None):
    return {
        "body": body,
        "headers": headers or {},
        "isBase64Encoded": False,
        "rawPath": path,
        "requestContext": {"http": {"method": method}},
    }


def result(decision="ALLOW", *, included=True, verified=True):
    value = {
        "decision": decision,
        "public_summary": "Bounded synthetic result.",
        "raw_answer": "DROP-ME",
        "public_receipt": {
            "receipt_id": "40000000-0000-4000-8000-000000000001",
            "decision": decision,
            "reason_code": "SYNTHETIC_REASON",
            "included_memory_ids": (
                ["10000000-0000-4000-8000-000000000001"] if included else []
            ),
            "included_content_sha256": [HASH] if included else [],
            "action_arguments_sha256": HASH,
            "policy_sha256": HASH,
            "exclusion_counts": {},
            "agent_signing_key_id": "demo-key",
            "signature_verified": verified,
            "raw_answer": "DROP-ME",
        },
    }
    if decision in {"STEP_UP", "DEFER"}:
        value["pending_action_id"] = "80000000-0000-4000-8000-000000000001"
    return value


def make_handler(recall=None, logs=None, input_guard=None):
    return create_lambda_handler(
        recall=recall or (lambda _: result()),
        input_guard=input_guard,
        allowed_origins=(ORIGIN,),
        request_id_factory=lambda: "request-1",
        event_sink=(logs if logs is not None else []).append,
    )


def test_health_is_bounded_and_skips_recall():
    calls = []
    response = make_handler(lambda scenario: calls.append(scenario))(
        event("GET", "/health"), None
    )
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["status"] == "ok"
    assert calls == []


def test_input_guard_runs_after_parsing_and_before_recall() -> None:
    calls: list[tuple[str, object]] = []

    def guard(query: str) -> bool:
        calls.append(("guard", query))
        return True

    def recall(request: _SyntheticRequest):
        calls.append(("recall", request))
        return result()

    response = make_handler(recall, input_guard=guard)(
        event(headers=JSON_HEADERS), None
    )

    assert response["statusCode"] == 200
    assert calls[0] == ("guard", DEFAULT_QUERY)
    assert calls[1][0] == "recall"


def test_input_guard_intervention_is_red_boundary_rejection_with_no_recall() -> None:
    recalls: list[_SyntheticRequest] = []
    logs: list[Mapping[str, object]] = []

    response = make_handler(
        recalls.append,
        logs,
        input_guard=lambda _query: False,
    )(event(headers=JSON_HEADERS), None)

    payload = json.loads(response["body"])
    assert response["statusCode"] == 400
    assert payload["error"]["code"] == "bedrock_guardrail_intervened"
    assert recalls == []
    assert logs[0]["failure_type"] == "InputGuardRejected"
    assert DEFAULT_QUERY not in json.dumps({"response": response, "logs": logs})


@pytest.mark.parametrize(
    "guard",
    [
        lambda _query: None,
        lambda _query: (_ for _ in ()).throw(RuntimeError("provider secret")),
    ],
)
def test_input_guard_invalid_result_or_outage_fails_closed_without_recall(guard):
    recalls: list[_SyntheticRequest] = []
    logs: list[Mapping[str, object]] = []

    response = make_handler(recalls.append, logs, input_guard=guard)(
        event(headers=JSON_HEADERS), None
    )

    rendered = json.dumps({"response": response, "logs": logs})
    assert response["statusCode"] == 503
    assert json.loads(response["body"])["error"]["code"] == ("input_guard_unavailable")
    assert recalls == []
    assert "provider secret" not in rendered


@pytest.mark.parametrize("definition", _JOURNEYS.values())
def test_persona_journeys_use_server_authority_and_project_public_fields(definition):
    calls = []
    decision = definition.expected_decision
    included = decision in {"ALLOW", "MODIFY"}

    def recall(value):
        calls.append(value)
        return result(decision, included=included)

    response = make_handler(recall)(
        event(
            body=json.dumps(
                {
                    "journey_id": definition.journey.value,
                    "persona": definition.persona.value,
                    "persona_token": _persona_token(definition.persona),
                    "query": DEFAULT_QUERY,
                    "turn_id": TURN_ID,
                }
            ),
            headers={"content-type": "application/json", "origin": ORIGIN},
        ),
        None,
    )
    assert response["statusCode"] == 200
    assert calls == [
        _SyntheticRequest(
            definition.persona,
            definition.journey,
            DEFAULT_QUERY,
            UUID(TURN_ID),
        )
    ]
    assert "DROP-ME" not in response["body"]
    payload = json.loads(response["body"])
    assert payload["public_result"]["decision"] == decision
    assert payload["public_events"][-1]["type"] == "turn.complete"
    assert all(event["turn_id"] == TURN_ID for event in payload["public_events"])
    assert response["headers"]["access-control-allow-origin"] == ORIGIN
    assert "access-control-allow-credentials" not in response["headers"]


@pytest.mark.parametrize(
    ("case", "status", "code"),
    [
        (event("GET", "/v1/demo"), 405, "method_not_allowed"),
        (event(path="/other"), 404, "not_found"),
        (event(headers={"content-type": "text/plain"}), 415, "unsupported_media_type"),
        (event(body="{", headers=JSON_HEADERS), 400, "invalid_request"),
        (event(body="x" * 1025, headers=JSON_HEADERS), 413, "request_too_large"),
        (
            event(
                body=json.dumps(
                    {
                        "journey_id": "program-current-status",
                        "persona": "program_lead",
                        "persona_token": "wrong",
                        "query": DEFAULT_QUERY,
                        "turn_id": TURN_ID,
                    }
                ),
                headers=JSON_HEADERS,
            ),
            400,
            "invalid_request",
        ),
        (
            event(
                body=ALLOW_BODY[:-1] + ',"tenant_id":"browser"}', headers=JSON_HEADERS
            ),
            400,
            "invalid_request",
        ),
    ],
)
def test_bad_requests_fail_closed(case, status, code):
    response = make_handler()(case, None)
    assert response["statusCode"] == status
    assert json.loads(response["body"])["error"]["code"] == code


def test_exact_cors_preflight():
    preflight = make_handler()(
        event(
            "OPTIONS",
            headers={
                "origin": ORIGIN,
                "access-control-request-method": "POST",
                "access-control-request-headers": "content-type",
            },
        ),
        None,
    )
    assert preflight["statusCode"] == 204
    assert "access-control-allow-credentials" not in preflight["headers"]
    denied = make_handler()(
        event("OPTIONS", headers={"origin": "https://evil.example"}), None
    )
    assert denied["statusCode"] == 403
    with pytest.raises(ValueError, match="explicit"):
        create_lambda_handler(recall=lambda _: {}, allowed_origins=("*",))


def test_gateway_errors_and_logs_are_content_free():
    logs: list[Mapping[str, object]] = []

    def fails(_):
        raise RuntimeError("RAW QUERY and RAW ANSWER and SELECT secret")

    response = make_handler(fails, logs)(
        event(headers=JSON_HEADERS),
        None,
    )
    rendered = json.dumps({"response": response, "logs": logs})
    assert response["statusCode"] == 503
    assert not any(term in rendered for term in ("RAW QUERY", "RAW ANSWER", "SELECT"))
    assert logs[0]["persona"] == "program_lead"
    assert logs[0]["journey"] == "program-current-status"
    assert logs[0]["status_code"] == 503
    assert logs[0]["failure_type"] == "RuntimeError"


@pytest.mark.parametrize(
    "query",
    [
        "Contact synthetic.user@example.com about HX-17.",
        "Use api_key=abcdefghijklmnopqrstuvwxyz123456 for HX-17.",
    ],
)
def test_public_prompt_rejects_sensitive_candidates_without_logging(query):
    logs: list[Mapping[str, object]] = []
    body = json.dumps(
        {
            "journey_id": "program-current-status",
            "persona": "program_lead",
            "persona_token": "program-lead-synthetic",
            "query": query,
            "turn_id": TURN_ID,
        }
    )
    response = make_handler(logs=logs)(event(body=body, headers=JSON_HEADERS), None)
    rendered = json.dumps({"response": response, "logs": logs})
    assert response["statusCode"] == 400
    assert json.loads(response["body"])["error"]["code"] == "unsafe_input"
    assert query not in rendered


@pytest.mark.parametrize("bad", [result(verified=False), result("DENY")])
def test_invalid_public_results_fail_closed(bad):
    response = make_handler(lambda _: bad)(event(headers=JSON_HEADERS), None)
    assert response["statusCode"] == 503
    assert "public_result" not in json.loads(response["body"])


def test_cross_persona_journey_and_noncanonical_turn_fail_closed():
    for body in (
        {
            "journey_id": _DemoJourney.PROGRAM_STATUS.value,
            "persona": _DemoPersona.EXTERNAL_PARTNER.value,
            "persona_token": _persona_token(_DemoPersona.EXTERNAL_PARTNER),
            "query": DEFAULT_QUERY,
            "turn_id": TURN_ID,
        },
        {
            "journey_id": _DemoJourney.PROGRAM_STATUS.value,
            "persona": _DemoPersona.PROGRAM_LEAD.value,
            "persona_token": _persona_token(_DemoPersona.PROGRAM_LEAD),
            "query": DEFAULT_QUERY,
            "turn_id": "90000000000040008000000000000001",
        },
    ):
        response = make_handler()(
            event(body=json.dumps(body), headers=JSON_HEADERS), None
        )
        assert response["statusCode"] == 400
