from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from gluevenir._demo_catalog import (
    _JOURNEYS,
    _DemoJourney,
    _DemoPersona,
)

ROOT = Path(__file__).resolve().parents[1]


def _credentialed_test_url(query: str) -> str:
    base = "postgresql://runtime" + ":secret@" + "example.invalid:26257/defaultdb"
    return f"{base}?{query}"


class _RecordingGenerator:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object | None]] = []

    def generate(
        self,
        request: str,
        *,
        authorized_memory: str,
        allowed_tool: object | None = None,
    ) -> str:
        self.calls.append((request, authorized_memory, allowed_tool))
        return "Synthetic current status."


def test_demo_generator_preserves_fictional_context_and_useful_fallback() -> None:
    from gluevenir._demo_runtime import _SyntheticDemoGenerator

    delegate = _RecordingGenerator()
    tool = object()
    generator = _SyntheticDemoGenerator(delegate)

    answer = generator.generate(
        "What changed in HX-17?",
        authorized_memory='{"memories":[]}',
        allowed_tool=tool,
    )

    assert answer == "Synthetic current status."
    assert len(delegate.calls) == 1
    request, memory, allowed_tool = delegate.calls[0]
    assert "public Gluevenir Bio demonstration" in request
    assert "HelixCure and\nHX-17 are wholly fictional" in request
    assert "Lead with the useful facts" in request
    assert "does not establish a delta" in request
    assert "Never invent changes" in request
    assert "Never repeat a person's name" in request
    assert "answer only with aggregate facts" in request
    assert "at most 65 words and 450 characters" in request
    assert request.endswith("What changed in HX-17?")
    assert memory == '{"memories":[]}'
    assert allowed_tool is tool


def test_clinical_model_projection_is_fixture_bound_useful_and_identifier_free() -> (
    None
):
    from gluevenir._demo_runtime import _ClinicalModelSafeProjector
    from gluevenir._detectors import _ContentScanner
    from gluevenir._memory_store import RecalledMemory
    from gluevenir._policy import _Destination

    fixture = json.loads(
        (ROOT / "fixtures/synthetic/memory_records.json").read_text(encoding="utf-8")
    )
    selected_roles = {
        "active_clinical",
        "clinical_current_cohort",
        "clinical_current_safety_review",
    }
    rows = tuple(
        row for row in fixture["records"] if row["fixture_role"] in selected_roles
    )
    records = tuple(
        RecalledMemory(
            UUID(row["memory_id"]),
            row["content"],
            row["content_sha256"],
        )
        for row in rows
    )
    action = SimpleNamespace(
        policy=SimpleNamespace(
            actor_role="clinical_operations_lead",
            purpose="safety_review",
            audience="internal-clinical",
            destination=_Destination.INTERNAL,
        )
    )

    projected = _ClinicalModelSafeProjector(_ContentScanner()).project(
        action=action,
        records=records,
    )

    assert tuple(row.source_memory_id for row in projected) == tuple(
        row.memory_id for row in records
    )
    assert tuple(row.source_content_sha256 for row in projected) == tuple(
        row.content_sha256 for row in records
    )
    assert all(
        row.content_sha256 == hashlib.sha256(row.content.encode()).hexdigest()
        for row in projected
    )
    assert all(row.content_sha256 != row.source_content_sha256 for row in projected)
    model_context = json.dumps([row.content for row in projected])
    assert "Day 42 follow-up moved" in model_context
    assert "resolved mild nausea observation" in model_context
    for identifier in (
        "Maya Ellison",
        "Noah Bell",
        "maya.ellison@example.test",
        "+1 202-555-0147",
        "SYN-HX17-004",
    ):
        assert identifier not in model_context


def test_clinical_model_projection_fails_if_bound_text_is_tampered(
    monkeypatch,
) -> None:
    from gluevenir._demo_runtime import (
        _CLINICAL_MODEL_SAFE_PROJECTIONS,
        _ClinicalModelSafeProjector,
    )
    from gluevenir._detectors import _ContentScanner
    from gluevenir._memory_store import RecalledMemory
    from gluevenir._policy import _Destination

    memory_id, projection = next(iter(_CLINICAL_MODEL_SAFE_PROJECTIONS.items()))
    source_hash, projected_hash, content = projection
    monkeypatch.setitem(
        _CLINICAL_MODEL_SAFE_PROJECTIONS,
        memory_id,
        (source_hash, projected_hash, f"{content} tampered"),
    )
    action = SimpleNamespace(
        policy=SimpleNamespace(
            actor_role="clinical_operations_lead",
            purpose="safety_review",
            audience="internal-clinical",
            destination=_Destination.INTERNAL,
        )
    )

    with pytest.raises(ValueError, match="does not match"):
        _ClinicalModelSafeProjector(_ContentScanner()).project(
            action=action,
            records=(RecalledMemory(memory_id, "source", source_hash),),
        )


def test_runtime_database_url_binds_verify_full_to_image_ca_bundle() -> None:
    from gluevenir._demo_runtime import _runtime_database_url

    url = _runtime_database_url(
        _credentialed_test_url("sslmode=verify-full"),
        database_name="gluevenir",
        root_certificate="/etc/pki/tls/certs/ca-bundle.crt",
    )
    assert url.drivername == "cockroachdb+psycopg"
    assert url.database == "gluevenir"
    assert url.query == {
        "sslmode": "verify-full",
        "sslrootcert": "/etc/pki/tls/certs/ca-bundle.crt",
    }


def test_runtime_database_url_preserves_secret_database_without_override() -> None:
    from gluevenir._demo_runtime import _runtime_database_url

    url = _runtime_database_url(
        _credentialed_test_url("sslmode=verify-full"),
        database_name=None,
        root_certificate="/etc/pki/tls/certs/ca-bundle.crt",
    )

    assert url.database == "defaultdb"


@pytest.mark.parametrize(
    ("query", "root_certificate"),
    [
        ("sslmode=require", "/etc/pki/tls/certs/ca-bundle.crt"),
        ("sslmode=verify-full", "/tmp/untrusted.crt"),
        (
            "sslmode=verify-full&sslrootcert=/tmp/untrusted.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ),
    ],
)
def test_runtime_database_url_rejects_weakened_or_overridden_tls(
    query: str, root_certificate: str
) -> None:
    from gluevenir._demo_runtime import _runtime_database_url

    with pytest.raises(ValueError):
        _runtime_database_url(
            _credentialed_test_url(query),
            database_name="gluevenir",
            root_certificate=root_certificate,
        )


def _event(method: str, path: str, body: str = "") -> dict[str, object]:
    return {
        "requestContext": {"http": {"method": method}},
        "rawPath": path,
        "rawQueryString": "",
        "headers": {"content-type": "application/json"},
        "body": body,
        "isBase64Encoded": False,
    }


def test_environment_factory_fails_closed_without_deployment_secrets(
    monkeypatch,
) -> None:
    for name in (
        "GLUEVENIR_COCKROACH_SECRET_ARN",
        "GLUEVENIR_SIGNING_KEY_ID",
        "GLUEVENIR_SIGNING_SECRET_ARN",
        "GLUEVENIR_BEDROCK_GUARDRAIL_ID",
        "GLUEVENIR_APP_SHA256",
    ):
        monkeypatch.delenv(name, raising=False)
    module = importlib.import_module("gluevenir._demo_runtime")
    module = importlib.reload(module)

    health = module.handler(_event("GET", "/health"), None)
    denied = module.handler(
        _event(
            "POST",
            "/v1/demo",
            json.dumps(
                {
                    "journey_id": "program-current-status",
                    "persona": "program_lead",
                    "persona_token": "program-lead-synthetic",
                    "query": "What changed in synthetic HX-17?",
                    "turn_id": "90000000-0000-4000-8000-000000000001",
                }
            ),
        ),
        None,
    )

    assert health["statusCode"] == 200
    assert denied["statusCode"] == 503
    assert "runtime unavailable" not in str(denied)


def test_runtime_telemetry_is_bounded_and_contains_no_object_identifiers() -> None:
    from gluevenir._demo_runtime import _runtime_telemetry_points
    from gluevenir._gateway import _GatewayResult, _ResponseStatus
    from gluevenir._policy import _Decision, _ReasonCode

    result = _GatewayResult(
        _Decision.DENY,
        _ReasonCode.IDENTITY_DENIED,
        _ResponseStatus.DENIED,
        UUID("40000000-0000-4000-8000-000000000001"),
    )
    signed = SimpleNamespace(
        payload=SimpleNamespace(candidate_count=2, included_count=0)
    )

    points = _runtime_telemetry_points(
        persona=_DemoPersona.CLINICAL_OPERATIONS_LEAD,
        result=result,
        signed=signed,
        signature_verified=True,
        total_duration_ms=27,
        gateway_offset_ms=3,
        gateway_duration_ms=22,
        recall_offset_ms=4,
        recall_duration_ms=5,
        model_offset_ms=9,
        model_duration_ms=12,
        receipt_offset_ms=21,
        receipt_duration_ms=2,
        projection_offset_ms=25,
        projection_duration_ms=1,
        approval_offset_ms=None,
        approval_duration_ms=None,
    )

    assert [point.sequence for point in points] == list(range(len(points)))
    assert points[0].stage.value == "request"
    assert points[-1].stage.value == "response.projection"
    rendered = json.dumps([point.as_span() for point in points], sort_keys=True)
    assert "clinical_operations_lead" in rendered
    assert "IDENTITY_DENIED" in rendered
    assert "40000000-0000-4000-8000-000000000001" not in rendered


def test_runtime_telemetry_reports_exact_external_derivative_without_model() -> None:
    from gluevenir._agent import _AgentAnswer
    from gluevenir._demo_runtime import _runtime_telemetry_points
    from gluevenir._gateway import _GatewayResult, _ResponseStatus
    from gluevenir._policy import _Decision, _ReasonCode

    result = _GatewayResult(
        _Decision.MODIFY,
        _ReasonCode.EXACT_APPROVED_DERIVATIVE,
        _ResponseStatus.COMPLETED,
        UUID("40000000-0000-4000-8000-000000000001"),
        output=_AgentAnswer(
            "SYNTHETIC DATA: approved external status.",
            (UUID("10000000-0000-4000-8000-000000000002"),),
            ("a" * 64,),
            model_invoked=False,
        ),
    )
    signed = SimpleNamespace(
        payload=SimpleNamespace(candidate_count=1, included_count=1)
    )

    points = _runtime_telemetry_points(
        persona=_DemoPersona.EXTERNAL_PARTNER,
        result=result,
        signed=signed,
        signature_verified=True,
        total_duration_ms=11,
        gateway_offset_ms=1,
        gateway_duration_ms=7,
        recall_offset_ms=2,
        recall_duration_ms=4,
        model_offset_ms=6,
        model_duration_ms=0,
        receipt_offset_ms=8,
        receipt_duration_ms=2,
        projection_offset_ms=10,
        projection_duration_ms=1,
        approval_offset_ms=None,
        approval_duration_ms=None,
    )

    model = next(point for point in points if point.stage.value == "model")
    assert model.model_invoked is False


def test_optional_otlp_sink_disables_on_partial_or_invalid_configuration(
    monkeypatch,
    caplog,
) -> None:
    from gluevenir._demo_runtime import _optional_otlp_batch_sink

    monkeypatch.setenv(
        "GLUEVENIR_OTLP_TRACES_ENDPOINT",
        "https://telemetry.example.test/v1/traces",
    )
    monkeypatch.delenv("GLUEVENIR_OTLP_AUTH_SECRET_ARN", raising=False)
    assert _optional_otlp_batch_sink(object()) is None
    assert "partial_configuration" in caplog.text

    monkeypatch.setenv(
        "GLUEVENIR_OTLP_AUTH_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:111122223333:secret:synthetic",
    )
    assert _optional_otlp_batch_sink(object()) is None
    assert "configuration_failed" in caplog.text


def test_optional_otlp_sink_accepts_exact_versioned_secret(monkeypatch) -> None:
    import gluevenir._demo_runtime as module

    class Client:
        def get_secret_value(self, *, SecretId: str) -> object:
            assert SecretId.endswith(":secret:synthetic")
            return {
                "SecretString": json.dumps(
                    {
                        "schema": "gluevenir.otlp.auth.v1",
                        "bearer_token": "s" * 48,
                    }
                )
            }

    captured: dict[str, object] = {}

    def create(endpoint: str, *, bearer_token: str) -> object:
        captured.update(endpoint=endpoint, bearer_token=bearer_token)
        return object()

    wrapped = object()
    monkeypatch.setenv(
        "GLUEVENIR_OTLP_TRACES_ENDPOINT",
        "https://telemetry.example.test/v1/traces",
    )
    monkeypatch.setenv(
        "GLUEVENIR_OTLP_AUTH_SECRET_ARN",
        "arn:aws:secretsmanager:us-east-1:111122223333:secret:synthetic",
    )
    monkeypatch.setattr(module, "_create_otlp_span_sink", create)
    monkeypatch.setattr(module, "_flushing_batch_sink", lambda _sink: wrapped)

    assert module._optional_otlp_batch_sink(Client()) is wrapped
    assert captured == {
        "endpoint": "https://telemetry.example.test/v1/traces",
        "bearer_token": "s" * 48,
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"bearer_token": "s" * 48},
        {"schema": "wrong", "bearer_token": "s" * 48},
        {
            "schema": "gluevenir.otlp.auth.v1",
            "bearer_token": "s" * 48,
            "extra": True,
        },
        {"schema": "gluevenir.otlp.auth.v1", "bearer_token": "too short"},
    ],
)
def test_otlp_secret_rejects_unexpected_shape(payload: object) -> None:
    from gluevenir._demo_runtime import _otlp_bearer_token

    class Client:
        def get_secret_value(self, *, SecretId: str) -> object:
            return {"SecretString": json.dumps(payload)}

    with pytest.raises(ValueError, match="secret"):
        _otlp_bearer_token(
            Client(),
            "arn:aws:secretsmanager:us-east-1:111122223333:secret:synthetic",
        )


def test_flushing_otlp_sink_exports_before_runtime_returns() -> None:
    from gluevenir._demo_runtime import _flushing_batch_sink

    class Sink:
        def __init__(self) -> None:
            self.calls = []

        def emit_batch(self, envelopes) -> None:
            self.calls.append(("emit", envelopes))

        def force_flush(self, timeout_millis=1_000) -> bool:
            self.calls.append(("flush", timeout_millis))
            return True

    sink = Sink()
    emit = _flushing_batch_sink(sink)
    emit(({"bounded": True},))
    assert sink.calls == [
        ("emit", ({"bounded": True},)),
        ("flush", 1_000),
    ]


def test_failed_runtime_request_emits_only_unavailable_request_point(
    monkeypatch,
) -> None:
    import gluevenir._demo_runtime as module

    batches = []
    runtime = object.__new__(module._DemoRuntime)
    runtime._telemetry_batch_sink = batches.append

    def fail(_runtime, _request, _started_ns):
        raise RuntimeError("synthetic failure sentinel")

    monkeypatch.setattr(module._DemoRuntime, "_execute_request", fail)
    request = module._SyntheticRequest(
        _DemoPersona.PROGRAM_LEAD,
        _DemoJourney.PROGRAM_STATUS,
        "Synthetic status?",
        UUID("90000000-0000-4000-8000-000000000001"),
    )

    with pytest.raises(RuntimeError, match="synthetic failure sentinel"):
        runtime(request)

    assert len(batches) == 1
    (envelope,) = batches[0]
    assert envelope["name"] == "gluevenir.request"
    assert envelope["attributes"]["gluevenir.status"] == "unavailable"
    assert "synthetic failure sentinel" not in json.dumps(envelope)


def test_runtime_logs_bounded_health_when_batch_sink_fails(caplog) -> None:
    import gluevenir._demo_runtime as module
    from gluevenir._telemetry import (
        _TelemetryPoint,
        _TelemetryStage,
        _TelemetryStatus,
    )

    runtime = object.__new__(module._DemoRuntime)

    def fail(_envelopes):
        raise RuntimeError("raw telemetry failure sentinel")

    runtime._telemetry_batch_sink = fail
    runtime._emit_telemetry(
        (
            _TelemetryPoint(
                0,
                _TelemetryStage.REQUEST,
                _TelemetryStatus.UNAVAILABLE,
                1,
                persona=_DemoPersona.PROGRAM_LEAD,
            ),
        )
    )

    assert "telemetry_export_health" in caplog.text
    assert "export_failed" in caplog.text
    assert "raw telemetry failure sentinel" not in caplog.text


def test_runtime_sink_uses_explicit_key_id_not_process_environment(
    monkeypatch,
) -> None:
    import gluevenir._demo_runtime as module

    captured = {}

    class Delegate:
        pass

    def signed_sink(**values):
        captured.update(values)
        return Delegate()

    runtime = object.__new__(module._DemoRuntime)
    runtime._signer = object()
    runtime._receipt_store = object()
    runtime._clock = object()
    runtime._key_id = "gluevenir-local-a1b2c3d4e5f60708"
    runtime._app_sha256 = "a" * 64
    monkeypatch.delenv("GLUEVENIR_SIGNING_KEY_ID", raising=False)
    monkeypatch.setattr(module, "_SignedReceiptSink", signed_sink)

    runtime._sink()
    assert captured["key_id"] == "gluevenir-local-a1b2c3d4e5f60708"


def test_all_persona_journeys_have_server_owned_policy_shapes() -> None:
    from datetime import UTC, datetime

    from gluevenir._demo_runtime import _MEMORY_IDS, _SCENARIOS
    from gluevenir._policy import _PolicyFacts

    fixture = json.loads(
        (ROOT / "fixtures/synthetic/demo_scenarios.json").read_text(encoding="utf-8")
    )
    memories = json.loads(
        (ROOT / "fixtures/synthetic/memory_records.json").read_text(encoding="utf-8")
    )
    approvals = json.loads(
        (ROOT / "fixtures/synthetic/derivative_approvals.json").read_text(
            encoding="utf-8"
        )
    )
    memory_ids = {row["fixture_role"]: row["memory_id"] for row in memories["records"]}
    reviewer_ids = {
        row["approval_id"]: row["reviewer"]["reviewer_handle"]
        for row in approvals["approvals"]
    }
    runtime_memory_ids = {role: str(value) for role, value in _MEMORY_IDS.items()}

    assert set(_SCENARIOS) == set(_DemoJourney)
    assert len(_SCENARIOS) == 20
    intent_labels = tuple(f"demo_{journey.value}" for journey in _DemoJourney)
    assert len(set(intent_labels)) == len(_DemoJourney)
    assert all(len(label) <= 64 for label in intent_labels)
    for persona in _DemoPersona:
        definitions = [
            value for value in _JOURNEYS.values() if value.persona == persona
        ]
        assert {value.expected_decision for value in definitions} == {
            "ALLOW",
            "MODIFY",
            "STEP_UP",
            "DEFER",
            "DENY",
        }
    for row in fixture["journeys"]:
        journey = _DemoJourney(row["journey_id"])
        spec = _SCENARIOS[journey]
        assert spec.actor_id == next(
            persona["actor_id"]
            for persona in fixture["personas"]
            if persona["persona_id"] == row["persona_id"]
        )
        assert spec.actor_role == next(
            persona["actor_role"]
            for persona in fixture["personas"]
            if persona["persona_id"] == row["persona_id"]
        )
        assert spec.purpose == row["purpose"]
        assert spec.audience == row["audience"]
        assert spec.destination.value == row["destination"]
        assert tuple(str(value) for value in spec.requested_ids) == tuple(
            memory_ids[role] for role in row["requested_fixture_roles"]
        )
        assert spec.data_classes == tuple(row["data_classes"])
        assert spec.identity_authorized is row["identity_authorized"]
        assert spec.human_review_allowed is row["human_review_allowed"]
        assert spec.missing_context == tuple(row["missing_context"])
        assert set(spec.missing_context).issubset(
            {"partner_authorization", "session_intent"}
        )
        assert len(spec.missing_context) <= 2
        facts = _PolicyFacts(
            now=datetime(2026, 8, 15, 18, tzinfo=UTC),
            policy_available=True,
            identity_authorized=spec.identity_authorized,
            missing_context=spec.missing_context,
            human_review_allowed=spec.human_review_allowed,
        )
        if spec.missing_context:
            assert facts.missing_context == spec.missing_context
        assert (str(spec.approval_id) if spec.approval_id is not None else None) == row[
            "approval_id"
        ]
        assert spec.reviewer_id == reviewer_ids.get(row["approval_id"])
        assert all(
            runtime_memory_ids[role] == memory_ids[role]
            for role in row["requested_fixture_roles"]
        )


def test_public_projection_fails_closed_for_failed_executable_outcome() -> None:
    from gluevenir._demo_runtime import _DemoRuntime, _GatewayExecutionFailure
    from gluevenir._gateway import _GatewayResult, _ResponseStatus
    from gluevenir._policy import _Decision, _ReasonCode

    runtime = object.__new__(_DemoRuntime)
    result = _GatewayResult(
        _Decision.MODIFY,
        _ReasonCode.EXACT_APPROVED_DERIVATIVE,
        _ResponseStatus.FAILED,
        UUID("40000000-0000-4000-8000-000000000001"),
    )

    with pytest.raises(_GatewayExecutionFailure):
        runtime._public(result, object())  # type: ignore[arg-type]


class _SecretsClient:
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values
        self.calls: list[str] = []

    def get_secret_value(self, *, SecretId: str) -> object:
        self.calls.append(SecretId)
        return self.values[SecretId]


def test_deployment_secrets_load_exact_json_shapes() -> None:
    from gluevenir._demo_runtime import _deployment_secrets

    cockroach_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:db"
    signing_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:key"
    client = _SecretsClient(
        {
            cockroach_arn: {
                "SecretString": json.dumps(
                    {"runtime_database_url": "cockroachdb://runtime.example"}
                )
            },
            signing_arn: {
                "SecretString": json.dumps({"private_key_b64": "c3ludGhldGlj"})
            },
        }
    )

    assert _deployment_secrets(
        client,
        cockroach_secret_arn=cockroach_arn,
        signing_secret_arn=signing_arn,
    ) == {
        "runtime_database_url": "cockroachdb://runtime.example",
        "private_key_b64": "c3ludGhldGlj",
    }
    assert client.calls == [cockroach_arn, signing_arn]


@pytest.mark.parametrize(
    "secret_string",
    [
        "{}",
        '{"private_key_b64":"one","private_key_b64":"two"}',
        '{"private_key_b64":"one","extra":"two"}',
        '{"private_key_b64":1}',
    ],
)
def test_deployment_secrets_reject_malformed_values(secret_string: str) -> None:
    from gluevenir._demo_runtime import _deployment_secrets

    cockroach_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:db"
    signing_arn = "arn:aws:secretsmanager:us-east-1:111111111111:secret:key"
    client = _SecretsClient(
        {
            cockroach_arn: {"SecretString": '{"runtime_database_url":"synthetic-url"}'},
            signing_arn: {"SecretString": secret_string},
        }
    )

    with pytest.raises(ValueError, match="secret"):
        _deployment_secrets(
            client,
            cockroach_secret_arn=cockroach_arn,
            signing_secret_arn=signing_arn,
        )
