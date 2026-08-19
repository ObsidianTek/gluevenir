"""Bounded AWS Lambda Function URL boundary for the synthetic demo."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from gluevenir._demo_catalog import (
    _DemoJourney,
    _DemoPersona,
    _journey_for,
    _persona_token,
)
from gluevenir._demo_events import _project_validated_demo_events
from gluevenir._detectors import _ContentScanner, _ScanInput

_LOG = logging.getLogger(__name__)
_MAX_BODY = 1_024
_MAX_QUERY = 280
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_REASON = re.compile(r"[A-Z0-9_]{1,48}\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True, repr=False)
class _SyntheticRequest:
    """Bounded prompt plus server-mapped synthetic persona and business journey."""

    persona: _DemoPersona
    journey: _DemoJourney
    query: str
    turn_id: UUID

    def __post_init__(self) -> None:
        if type(self.persona) is not _DemoPersona:
            raise TypeError("persona must be a demo persona")
        if type(self.journey) is not _DemoJourney:
            raise TypeError("journey must be a demo journey")
        _journey_for(self.persona, self.journey)
        if type(self.query) is not str:
            raise TypeError("query must be a string")
        normalized = self.query.strip()
        if (
            not normalized
            or len(normalized) > _MAX_QUERY
            or _CONTROL_CHARACTER.search(normalized)
        ):
            raise ValueError("query is invalid")
        object.__setattr__(self, "query", normalized)
        if not isinstance(self.turn_id, UUID):
            raise TypeError("turn_id must be a UUID")

    def __repr__(self) -> str:
        return (
            f"_SyntheticRequest(persona={self.persona!r}, "
            f"journey={self.journey!r}, turn_id={self.turn_id!r}, query=<redacted>)"
        )


class _HttpError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


def create_lambda_handler(
    *,
    recall: Callable[[_SyntheticRequest], Mapping[str, object]],
    input_guard: Callable[[str], bool] | None = None,
    allowed_origins: Sequence[str] = (),
    request_id_factory: Callable[[], object] = uuid4,
    event_sink: Callable[[Mapping[str, object]], None] | None = None,
) -> Callable[[object, object], dict[str, object]]:
    if not callable(recall) or not callable(request_id_factory):
        raise TypeError("runtime dependencies must be callable")
    if input_guard is not None and not callable(input_guard):
        raise TypeError("input_guard must be callable")
    if event_sink is not None and not callable(event_sink):
        raise TypeError("event_sink must be callable")
    origins = frozenset(_origin_config(value) for value in allowed_origins)

    def handler(event: object, _context: object) -> dict[str, object]:
        request_id = _new_id(request_id_factory)
        method, path, persona_name, journey_name, origin = (
            "UNKNOWN",
            "UNKNOWN",
            None,
            None,
            None,
        )
        failure_type = None
        try:
            method, path, headers = _request(event)
            origin = headers.get("origin")
            if origin is not None and origin not in origins:
                raise _HttpError(403, "origin_denied")
            if method == "GET" and path == "/health":
                response = _response(
                    200,
                    {"request_id": request_id, "status": "ok", "synthetic": True},
                    origin,
                )
            elif method == "OPTIONS" and path == "/v1/demo":
                response = _preflight(headers, origin, request_id)
            elif method == "POST" and path == "/v1/demo":
                demo_request = _parse_scenario(event, headers)
                persona_name = demo_request.persona.value
                journey_name = demo_request.journey.value
                definition = _journey_for(
                    demo_request.persona,
                    demo_request.journey,
                )
                if input_guard is not None:
                    try:
                        input_allowed = input_guard(demo_request.query)
                    except Exception as error:
                        failure_type = type(error).__name__
                        raise _HttpError(503, "input_guard_unavailable") from None
                    if type(input_allowed) is not bool:
                        failure_type = "InputGuardContractError"
                        raise _HttpError(503, "input_guard_unavailable")
                    if not input_allowed:
                        failure_type = "InputGuardRejected"
                        raise _HttpError(400, "bedrock_guardrail_intervened")
                try:
                    public = _project_public(
                        recall(demo_request), definition.expected_decision
                    )
                    public_events = [
                        value.as_dict()
                        for value in _project_validated_demo_events(
                            public,
                            turn_id=str(demo_request.turn_id),
                            request_id=request_id,
                        )
                    ]
                except Exception as error:
                    failure_type = type(error).__name__
                    raise _HttpError(503, "gateway_unavailable") from None
                response = _response(
                    200,
                    {
                        "public_result": public,
                        "public_events": public_events,
                        "request_id": request_id,
                    },
                    origin,
                )
            elif path in {"/health", "/v1/demo"}:
                raise _HttpError(405, "method_not_allowed")
            else:
                raise _HttpError(404, "not_found")
        except _HttpError as error:
            response = _error(error.status, error.code, request_id, origin)
        except Exception:
            response = _error(400, "invalid_request", request_id, origin)
        log_event = {
            "event": "lambda_request",
            "method": method,
            "path": path,
            "request_id": request_id,
            "persona": persona_name,
            "journey": journey_name,
            "status_code": response["statusCode"],
        }
        if failure_type is not None:
            log_event["failure_type"] = failure_type
        _emit(event_sink, log_event)
        return response

    return handler


def _request(event: object) -> tuple[str, str, dict[str, str]]:
    if type(event) is not dict or event.get("rawQueryString", "") != "":
        raise _HttpError(400, "invalid_request")
    context, path = event.get("requestContext"), event.get("rawPath")
    http = context.get("http") if type(context) is dict else None
    method = http.get("method") if type(http) is dict else None
    if type(method) is not str or type(path) is not str or method != method.upper():
        raise _HttpError(400, "invalid_request")
    if not path.startswith("/") or len(path) > 64:
        raise _HttpError(400, "invalid_request")
    raw = event.get("headers", {})
    if type(raw) is not dict:
        raise _HttpError(400, "invalid_request")
    headers: dict[str, str] = {}
    for name, value in raw.items():
        key = name.casefold() if type(name) is str else ""
        if not key or type(value) is not str or key in headers:
            raise _HttpError(400, "invalid_request")
        headers[key] = value.strip()
    return method, path, headers


def _parse_scenario(
    event: dict[str, object], headers: Mapping[str, str]
) -> _SyntheticRequest:
    if headers.get("content-type", "").casefold() not in {
        "application/json",
        "application/json; charset=utf-8",
        'application/json; charset="utf-8"',
    }:
        raise _HttpError(415, "unsupported_media_type")
    body = event.get("body")
    if type(body) is not str or event.get("isBase64Encoded", False) is not False:
        raise _HttpError(400, "invalid_request")
    try:
        raw = body.encode("utf-8")
    except UnicodeEncodeError:
        raise _HttpError(400, "invalid_request") from None
    if len(raw) > _MAX_BODY:
        raise _HttpError(413, "request_too_large")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise _HttpError(400, "invalid_request") from None
    if type(value) is not dict or set(value) != {
        "journey_id",
        "persona",
        "persona_token",
        "query",
        "turn_id",
    }:
        raise _HttpError(400, "invalid_request")
    try:
        persona = _DemoPersona(value["persona"])
        journey = _DemoJourney(value["journey_id"])
        if type(value["turn_id"]) is not str:
            raise ValueError
        turn_id = UUID(value["turn_id"])
        if str(turn_id) != value["turn_id"]:
            raise ValueError
    except (TypeError, ValueError):
        raise _HttpError(400, "invalid_request") from None
    if type(value["persona_token"]) is not str or value[
        "persona_token"
    ] != _persona_token(persona):
        raise _HttpError(400, "invalid_request")
    try:
        request = _SyntheticRequest(  # type: ignore[arg-type]
            persona,
            journey,
            value["query"],
            turn_id,
        )
        scan = _ContentScanner().scan_public_demo_write(_ScanInput(request.query))
    except (TypeError, ValueError):
        raise _HttpError(400, "invalid_request") from None
    except Exception:
        raise _HttpError(400, "unsafe_input") from None
    if not scan.is_allowed:
        raise _HttpError(400, "unsafe_input")
    return request


def _project_public(result: object, expected: str) -> dict[str, object]:
    if not isinstance(result, Mapping):
        raise ValueError
    view = result.get("public_result", result)
    if not isinstance(view, Mapping):
        raise ValueError
    decision, summary = view.get("decision"), view.get("public_summary")
    receipt = view.get("public_receipt", view.get("receipt"))
    if (
        decision != expected
        or type(summary) is not str
        or not summary.strip()
        or len(summary) > 500
        or not isinstance(receipt, Mapping)
        or receipt.get("decision") != decision
        or receipt.get("signature_verified") is not True
    ):
        raise ValueError
    ids = receipt.get("included_memory_ids")
    hashes = receipt.get("included_content_sha256")
    exclusions = receipt.get("exclusion_counts")
    if (
        type(ids) is not list
        or type(hashes) is not list
        or len(ids) > 5
        or len(ids) != len(hashes)
        or decision in {"DENY", "STEP_UP", "DEFER"}
        and ids
        or type(exclusions) is not dict
        or len(exclusions) > 4
    ):
        raise ValueError
    public_ids = [_uuid(value) for value in ids]
    if len(set(public_ids)) != len(public_ids) or any(
        not _hash(value) for value in hashes
    ):
        raise ValueError
    valid_exclusions = all(
        type(reason) is str
        and _REASON.fullmatch(reason) is not None
        and type(count) is int
        and 1 <= count <= 10_000
        for reason, count in exclusions.items()
    )
    if not valid_exclusions:
        raise ValueError
    reason, key = receipt.get("reason_code"), receipt.get("agent_signing_key_id")
    action_hash = receipt.get("action_arguments_sha256")
    policy_hash = receipt.get("policy_sha256")
    if (
        type(reason) is not str
        or not _REASON.fullmatch(reason)
        or type(key) is not str
        or not _ID.fullmatch(key)
        or not _hash(action_hash)
        or not _hash(policy_hash)
    ):
        raise ValueError
    return {
        "decision": decision,
        "public_summary": summary,
        "public_receipt": {
            "receipt_id": _uuid(receipt.get("receipt_id")),
            "decision": decision,
            "reason_code": reason,
            "included_memory_ids": public_ids,
            "included_content_sha256": list(hashes),
            "action_arguments_sha256": action_hash,
            "policy_sha256": policy_hash,
            "exclusion_counts": dict(exclusions),
            "agent_signing_key_id": key,
            "signature_verified": True,
        },
        **(
            {"pending_action_id": _uuid(view.get("pending_action_id"))}
            if decision in {"STEP_UP", "DEFER"}
            else {}
        ),
    }


def _preflight(
    headers: Mapping[str, str], origin: str | None, request_id: str
) -> dict[str, object]:
    requested = {
        item.strip().casefold()
        for item in headers.get("access-control-request-headers", "").split(",")
        if item.strip()
    }
    if (
        origin is None
        or headers.get("access-control-request-method") != "POST"
        or not requested.issubset({"content-type"})
    ):
        raise _HttpError(403, "origin_denied")
    response = _response(204, {}, origin)
    response["body"] = ""
    response["headers"].update(  # type: ignore[union-attr]
        {
            "access-control-allow-headers": "content-type",
            "access-control-allow-methods": "POST",
            "access-control-max-age": "300",
            "x-request-id": request_id,
        }
    )
    return response


def _response(
    status: int, payload: Mapping[str, object], origin: str | None
) -> dict[str, object]:
    headers = {
        "cache-control": "no-store",
        "content-type": "application/json; charset=utf-8",
        "x-content-type-options": "nosniff",
    }
    if origin is not None:
        headers.update({"access-control-allow-origin": origin, "vary": "origin"})
    return {
        "statusCode": status,
        "headers": headers,
        "body": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def _error(
    status: int, code: str, request_id: str, origin: str | None
) -> dict[str, object]:
    return _response(
        status,
        {
            "error": {
                "code": code,
                "message": "The request could not be completed.",
            },
            "request_id": request_id,
        },
        origin,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _origin_config(value: object) -> str:
    if type(value) is not str or value == "*":
        raise ValueError("origins must be explicit")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or value != f"https://{parsed.netloc}"
    ):
        raise ValueError("origins must be exact HTTPS origins")
    return value


def _uuid(value: object) -> str:
    if type(value) is not str or str(UUID(value)) != value:
        raise ValueError
    return value


def _hash(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _new_id(factory: Callable[[], object]) -> str:
    try:
        value = str(factory())
    except Exception:
        return "request-unavailable"
    return value if _REQUEST_ID.fullmatch(value) else "request-unavailable"


def _emit(sink, event) -> None:
    try:
        callback = sink or (lambda value: _LOG.info("%s", json.dumps(value)))
        callback(dict(event))
    except Exception:
        pass


def _unconfigured(_request: _SyntheticRequest) -> Mapping[str, object]:
    raise RuntimeError("runtime is not configured")


handler = create_lambda_handler(
    recall=_unconfigured,
)
