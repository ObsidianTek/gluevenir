"""Deployment-only construction for the fixed synthetic Gluevenir Bio demo."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from gluevenir._agent import _AgentAnswer, _BedrockRecallExecutor, _ModelMemory
from gluevenir._approval_store import (
    _CockroachApprovalStore,
    _TrustedReviewerIdentity,
)
from gluevenir._bedrock import (
    _BedrockInputGuard,
    _NovaLiteConverse,
    _TitanTextEmbeddingsV2,
)
from gluevenir._database import cockroach_url
from gluevenir._demo_catalog import (
    _DemoJourney,
    _DemoPersona,
    _journey_for,
)
from gluevenir._detectors import _ContentScanner, _DeterministicDetector, _ScanInput
from gluevenir._gateway import (
    _GatewayAction,
    _GatewayResult,
    _hash_action_arguments,
    _MemoryActionGateway,
    _ResponseStatus,
)
from gluevenir._lambda import (
    _SyntheticRequest,
    create_lambda_handler,
)
from gluevenir._memory_store import RecalledMemory, _CockroachMemoryStore
from gluevenir._otel import _create_otlp_span_sink
from gluevenir._pending_store import _CockroachPendingActionStore
from gluevenir._policy import (
    _BioDemoPolicy,
    _Decision,
    _Destination,
    _PolicyAction,
    _PolicyFacts,
)
from gluevenir._ports import MemoryOperation
from gluevenir._presidio import (
    _CompositeDetector,
    _create_presidio_analyzer,
    _PresidioDetector,
)
from gluevenir._receipt_sink import _SignedReceiptSink
from gluevenir._receipt_store import _CockroachReceiptStore
from gluevenir._receipts import (
    _ReceiptSigner,
    _ReceiptVerifier,
    _SignedReceipt,
)
from gluevenir._session_context import (
    _CandidateLabel,
    _ClassificationCount,
    _CockroachSessionContextWriter,
    _prior_receipt_context_sha256,
    _SessionContextRecord,
    _SessionDatabaseAuthorizationError,
    _SessionDatabaseConnectionRefusedError,
    _SessionDatabaseDnsError,
    _SessionDatabaseError,
    _SessionDatabaseOperationalError,
    _SessionDatabaseTimeoutError,
    _SessionDatabaseTlsError,
)
from gluevenir._telemetry import _TelemetryPoint, _TelemetryStage, _TelemetryStatus

_TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
_PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
_FORMULATION_SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
_FORMULATION_DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
_FORMULATION_APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000001")
_CLINICAL_APPROVAL_ID = UUID("30000000-0000-4000-8000-000000000003")
_POLICY_VERSION = "bio-demo-v1"
_RUNTIME_PRINCIPAL = "gluevenir_runtime"

_TELEMETRY_STATUS = {
    _Decision.ALLOW: _TelemetryStatus.SUCCEEDED,
    _Decision.MODIFY: _TelemetryStatus.SUCCEEDED,
    _Decision.DENY: _TelemetryStatus.DENIED,
    _Decision.STEP_UP: _TelemetryStatus.PENDING,
    _Decision.DEFER: _TelemetryStatus.PENDING,
}
_SYSTEM_CA_BUNDLE = "/etc/pki/tls/certs/ca-bundle.crt"
_LOG = logging.getLogger(__name__)


class _Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class _SessionContextFailure(Exception):
    pass


class _SessionContextAuthorizationFailure(Exception):
    pass


class _SessionContextConsistencyFailure(Exception):
    pass


class _ApprovalLoadFailure(Exception):
    pass


class _GatewayExecutionFailure(Exception):
    pass


class _ReceiptStore(Protocol):
    def save(self, receipt: _SignedReceipt) -> None: ...


class _TextGenerator(Protocol):
    def generate(
        self,
        request: str,
        *,
        authorized_memory: str,
        allowed_tool: object | None = None,
    ) -> str: ...


class _BatchSpanSink(Protocol):
    def emit_batch(self, envelopes: tuple[Mapping[str, object], ...]) -> None: ...

    def force_flush(self, timeout_millis: int = 1_000) -> bool: ...


_DEMO_TASK_CONTEXT = """\
You are answering inside the public Gluevenir Bio demonstration. HelixCure and
HX-17 are wholly fictional, and every program detail is synthetic. Answer as
Gluevenir Bio helping the selected synthetic persona, not as a generic document
retrieval assistant. Use only the authorized memory for program-specific claims.
Lead with the useful facts the authorized memory supports. If the request asks
what changed but the memory contains no explicit before-and-after comparison,
state that the authorized context does not establish a delta, then still summarize
the supported current status and name the exact limitation. Never invent changes,
measurements, dates, safety conclusions, approvals, or access. Keep the fictional
demo framing clear. Never repeat a person's name, participant identifier, email,
phone number, or individual clinical detail from the user request. For a
partner-facing question, answer only with aggregate facts present in the
authorized memory. Keep the entire answer to at most 65 words and 450 characters.

SYNTHETIC_DEMO_USER_REQUEST:
"""


class _SyntheticDemoGenerator:
    """Bind generation to the fictional demo without changing core policy."""

    __slots__ = ("_delegate",)

    def __init__(self, delegate: _TextGenerator) -> None:
        self._delegate = delegate

    def generate(
        self,
        request: str,
        *,
        authorized_memory: str,
        allowed_tool: object | None = None,
    ) -> str:
        return self._delegate.generate(
            f"{_DEMO_TASK_CONTEXT}{request}",
            authorized_memory=authorized_memory,
            allowed_tool=allowed_tool,
        )


class _CapturingSink:
    """Keep the exact signed public receipt while delegating durable writes."""

    def __init__(self, delegate: _SignedReceiptSink, store: _ReceiptStore) -> None:
        self._delegate = delegate
        self._store = store
        self.signed: list[_SignedReceipt] = []
        self.timings_ns: list[tuple[int, int]] = []

    def record(self, **values: object) -> UUID:
        started_ns = time.perf_counter_ns()
        try:
            receipt = self._delegate.build(**values)
            self.signed.append(receipt)
            self._store.save(receipt)
            return receipt.payload.receipt_id
        finally:
            self.timings_ns.append((started_ns, time.perf_counter_ns()))

    def build(self, **values: object) -> _SignedReceipt:
        started_ns = time.perf_counter_ns()
        try:
            receipt = self._delegate.build(**values)
            self.signed.append(receipt)
            return receipt
        finally:
            self.timings_ns.append((started_ns, time.perf_counter_ns()))

    def persist_in_transaction(
        self, connection: object, receipt: _SignedReceipt
    ) -> None:
        started_ns = time.perf_counter_ns()
        try:
            self._delegate.persist_in_transaction(connection, receipt)  # type: ignore[arg-type]
        finally:
            self.timings_ns.append((started_ns, time.perf_counter_ns()))

    def timing(self, request_started_ns: int) -> tuple[int, int]:
        if not self.timings_ns:
            return 0, 0
        offset_ms = _offset_ms(request_started_ns, min(x[0] for x in self.timings_ns))
        duration_ms = min(
            sum(max(0, end - start) for start, end in self.timings_ns) // 1_000_000,
            120_000,
        )
        return offset_ms, duration_ms


class _TimedRecallExecutor:
    """Request-local timing wrapper; it does not change executor behavior."""

    def __init__(self, delegate: _BedrockRecallExecutor) -> None:
        self._delegate = delegate
        self.prepare_timing_ns: tuple[int, int] | None = None
        self.execute_timing_ns: tuple[int, int] | None = None

    def prepare(self, **values: object):
        started_ns = time.perf_counter_ns()
        try:
            return self._delegate.prepare(**values)  # type: ignore[arg-type]
        finally:
            self.prepare_timing_ns = (started_ns, time.perf_counter_ns())

    def execute(self, **values: object):
        started_ns = time.perf_counter_ns()
        try:
            return self._delegate.execute(**values)  # type: ignore[arg-type]
        finally:
            self.execute_timing_ns = (started_ns, time.perf_counter_ns())

    def timing(
        self,
        value: tuple[int, int] | None,
        request_started_ns: int,
    ) -> tuple[int, int]:
        if value is None:
            return 0, 0
        started_ns, ended_ns = value
        return (
            _offset_ms(request_started_ns, started_ns),
            _duration_ms(started_ns, ended_ns),
        )


@dataclass(frozen=True, slots=True)
class _ScenarioSpec:
    actor_id: str
    actor_role: str
    purpose: str
    audience: str
    destination: _Destination
    requested_ids: tuple[UUID, ...]
    data_classes: tuple[str, ...]
    identity_authorized: bool = True
    human_review_allowed: bool = False
    missing_context: tuple[str, ...] = ()
    approval_id: UUID | None = None
    reviewer_id: str | None = None


_PERSONA_ACTORS = {
    _DemoPersona.PROGRAM_LEAD: ("synthetic-program-lead", "program_lead"),
    _DemoPersona.FORMULATION_SCIENTIST: (
        "synthetic-formulation-scientist",
        "formulation_scientist",
    ),
    _DemoPersona.CLINICAL_OPERATIONS_LEAD: (
        "synthetic-clinical-operations-lead",
        "clinical_operations_lead",
    ),
    _DemoPersona.EXTERNAL_PARTNER: (
        "synthetic-partner-alpha-user",
        "external_partner",
    ),
}

_MEMORY_IDS = {
    "restricted_source": _FORMULATION_SOURCE_ID,
    "active_clinical": UUID("10000000-0000-4000-8000-000000000003"),
    "revoked_source": UUID("10000000-0000-4000-8000-000000000005"),
    "cross_tenant_semantic_decoy": UUID("10000000-0000-4000-8000-000000000009"),
    "program_prior_checkpoint": UUID("10000000-0000-4000-8000-000000000010"),
    "program_current_milestone": UUID("10000000-0000-4000-8000-000000000011"),
    "program_safe_derivative": UUID("10000000-0000-4000-8000-000000000012"),
    "program_pending_milestone": UUID("10000000-0000-4000-8000-000000000014"),
    "formulation_prior_baseline": UUID("10000000-0000-4000-8000-000000000016"),
    "formulation_current_assay": UUID("10000000-0000-4000-8000-000000000017"),
    "formulation_pending_b9": UUID("10000000-0000-4000-8000-000000000019"),
    "clinical_prior_cohort": UUID("10000000-0000-4000-8000-000000000022"),
    "clinical_current_cohort": UUID("10000000-0000-4000-8000-000000000023"),
    "clinical_current_safety_review": UUID("10000000-0000-4000-8000-000000000026"),
    "clinical_pending_safety_summary": UUID("10000000-0000-4000-8000-000000000027"),
    "synthetic_detector_candidate": UUID("10000000-0000-4000-8000-000000000030"),
}

_CLINICAL_MODEL_SAFE_PROJECTIONS = {
    _MEMORY_IDS["active_clinical"]: (
        "b9a8af7e45d9e814328e0a72a0281228a6187f3dc620789b93369dc62def3434",
        "158ea2cbc885d5eae559e7ad7bc5beecffe312d56c7a149c9cece2d4d28a47ba",
        (
            "SYNTHETIC DATA: One Day 42 follow-up moved from 2026-08-19 to "
            "2026-08-21 because of participant availability. A mild nausea "
            "observation reported 2026-08-13 resolved 2026-08-14, and the "
            "follow-up was completed 2026-08-15."
        ),
    ),
    _MEMORY_IDS["clinical_current_cohort"]: (
        "93eb5b95b7eb7e4922b532c08af230c4f4d831ac21122134f41857f4128d668b",
        "2c709c5f57f533373580c1db80160e3f0131823f2dfcd80a4946181159ca7457",
        (
            "SYNTHETIC DATA: As of 2026-08-15, protocol HC-HX17-101 has six "
            "participants enrolled against 24 anticipated at Site SYN-03. One "
            "Day 42 visit moved from 2026-08-19 to 2026-08-21; the change does "
            "not alter the current cohort-planning timeline."
        ),
    ),
    _MEMORY_IDS["clinical_current_safety_review"]: (
        "11c6dea522da968e38e5b17d88e5b9e1c9975e1dd9e7b07b6f3e51de944a6611",
        "062c8efe56bb2cff8cb394746047e9c1ba89aac9c978b0d58ccd4239b0b086e1",
        (
            "SYNTHETIC DATA: The 2026-08-15 HX-17 safety review records one "
            "resolved mild nausea observation, follow-up complete, with no "
            "protocol-defined escalation. A summary groups three mild training "
            "observations and awaits external-release review."
        ),
    ),
}


class _ClinicalModelSafeProjector:
    """Expose fixed useful clinical facts to the model without identifiers."""

    __slots__ = ("_scanner",)

    def __init__(self, scanner: _ContentScanner) -> None:
        if not isinstance(scanner, _ContentScanner):
            raise TypeError("scanner must be a _ContentScanner")
        self._scanner = scanner

    def project(
        self,
        *,
        action: _GatewayAction,
        records: tuple[RecalledMemory, ...],
    ) -> tuple[_ModelMemory, ...]:
        if not (
            action.policy.actor_role == "clinical_operations_lead"
            and action.policy.purpose == "safety_review"
            and action.policy.audience == "internal-clinical"
            and action.policy.destination is _Destination.INTERNAL
        ):
            return tuple(
                _ModelMemory(
                    source_memory_id=record.memory_id,
                    source_content_sha256=record.content_sha256,
                    content=record.content,
                    content_sha256=hashlib.sha256(
                        record.content.encode("utf-8")
                    ).hexdigest(),
                )
                for record in records
            )

        projected = []
        for record in records:
            projection = _CLINICAL_MODEL_SAFE_PROJECTIONS.get(record.memory_id)
            if projection is None or projection[0] != record.content_sha256:
                raise ValueError("clinical model projection is unavailable")
            content = projection[2]
            if not self._scanner.scan_internal_output(_ScanInput(content)).is_allowed:
                raise ValueError("clinical model projection did not pass scanning")
            projected.append(
                _ModelMemory(
                    source_memory_id=record.memory_id,
                    source_content_sha256=record.content_sha256,
                    content=content,
                    content_sha256=projection[1],
                )
            )
        return tuple(projected)


def _scenario(
    persona: _DemoPersona,
    purpose: str,
    audience: str,
    destination: _Destination,
    requested_roles: tuple[str, ...],
    data_classes: tuple[str, ...],
    *,
    identity_authorized: bool = True,
    human_review_allowed: bool = False,
    missing_context: tuple[str, ...] = (),
    approval_id: UUID | None = None,
    reviewer_id: str | None = None,
) -> _ScenarioSpec:
    actor_id, actor_role = _PERSONA_ACTORS[persona]
    return _ScenarioSpec(
        actor_id,
        actor_role,
        purpose,
        audience,
        destination,
        tuple(_MEMORY_IDS[role] for role in requested_roles),
        data_classes,
        identity_authorized=identity_authorized,
        human_review_allowed=human_review_allowed,
        missing_context=missing_context,
        approval_id=approval_id,
        reviewer_id=reviewer_id,
    )


def _build_scenarios() -> dict[_DemoJourney, _ScenarioSpec]:
    internal = _Destination.INTERNAL
    external = _Destination.EXTERNAL
    program = _DemoPersona.PROGRAM_LEAD
    formulation = _DemoPersona.FORMULATION_SCIENTIST
    clinical = _DemoPersona.CLINICAL_OPERATIONS_LEAD
    partner = _DemoPersona.EXTERNAL_PARTNER
    return {
        _DemoJourney.PROGRAM_STATUS: _scenario(
            program,
            "program_status",
            "internal-program-lead",
            internal,
            (
                "program_prior_checkpoint",
                "program_current_milestone",
                "clinical_current_cohort",
            ),
            ("IP_CONFIDENTIAL", "PHI_CANDIDATE"),
        ),
        _DemoJourney.PARTNER_READY_SUMMARY: _scenario(
            program,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("restricted_source",),
            ("IP_CONFIDENTIAL",),
            approval_id=_FORMULATION_APPROVAL_ID,
            reviewer_id="human-lucia-chen-syn",
        ),
        _DemoJourney.PENDING_MILESTONE: _scenario(
            program,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("program_pending_milestone",),
            ("MNPI_CANDIDATE",),
            human_review_allowed=True,
        ),
        _DemoJourney.AMBIGUOUS_DISTRIBUTION: _scenario(
            program,
            "program_status",
            "internal-program-lead",
            internal,
            ("program_current_milestone",),
            ("IP_CONFIDENTIAL",),
            missing_context=("session_intent",),
        ),
        _DemoJourney.OTHER_ORGANIZATION: _scenario(
            program,
            "program_status",
            "internal-program-lead",
            internal,
            ("cross_tenant_semantic_decoy",),
            ("IP_CONFIDENTIAL",),
            identity_authorized=False,
        ),
        _DemoJourney.STABILITY_OBSERVATIONS: _scenario(
            formulation,
            "research_review",
            "internal-research",
            internal,
            (
                "restricted_source",
                "formulation_prior_baseline",
                "formulation_current_assay",
            ),
            ("IP_CONFIDENTIAL",),
        ),
        _DemoJourney.EXTERNAL_FORMULATION: _scenario(
            formulation,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("restricted_source",),
            ("IP_CONFIDENTIAL",),
            approval_id=_FORMULATION_APPROVAL_ID,
            reviewer_id="human-lucia-chen-syn",
        ),
        _DemoJourney.PENDING_B9_INTERPRETATION: _scenario(
            formulation,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("formulation_pending_b9",),
            ("IP_CONFIDENTIAL",),
            human_review_allowed=True,
        ),
        _DemoJourney.UNSPECIFIED_RESULTS: _scenario(
            formulation,
            "research_review",
            "internal-research",
            internal,
            ("formulation_current_assay",),
            ("IP_CONFIDENTIAL",),
            missing_context=("session_intent",),
        ),
        _DemoJourney.RESTRICTED_ASSAY_DETAIL: _scenario(
            formulation,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("revoked_source",),
            ("IP_CONFIDENTIAL",),
        ),
        _DemoJourney.COHORT_CHANGES: _scenario(
            clinical,
            "safety_review",
            "internal-clinical",
            internal,
            (
                "active_clinical",
                "clinical_current_cohort",
                "clinical_current_safety_review",
            ),
            ("PHI_CANDIDATE",),
        ),
        _DemoJourney.PARTNER_COHORT_UPDATE: _scenario(
            clinical,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("clinical_current_cohort",),
            ("PHI_CANDIDATE",),
            approval_id=_CLINICAL_APPROVAL_ID,
            reviewer_id="human-lucia-chen-syn",
        ),
        _DemoJourney.PENDING_SAFETY_REVIEW: _scenario(
            clinical,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("clinical_pending_safety_summary",),
            ("PHI_CANDIDATE",),
            human_review_allowed=True,
        ),
        _DemoJourney.UNSCOPED_ENROLLMENT: _scenario(
            clinical,
            "safety_review",
            "internal-clinical",
            internal,
            ("synthetic_detector_candidate",),
            ("PHI_CANDIDATE",),
            missing_context=("session_intent",),
        ),
        _DemoJourney.PARTICIPANT_CONTACTS: _scenario(
            clinical,
            "safety_review",
            "internal-clinical",
            internal,
            ("cross_tenant_semantic_decoy",),
            ("PII", "PHI_CANDIDATE"),
            identity_authorized=False,
        ),
        _DemoJourney.APPROVED_OVERVIEW: _scenario(
            partner,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("program_safe_derivative",),
            ("EXTERNAL_APPROVED",),
        ),
        _DemoJourney.STABILITY_FORMULATION_UPDATE: _scenario(
            partner,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("clinical_current_cohort",),
            ("PHI_CANDIDATE",),
            approval_id=_CLINICAL_APPROVAL_ID,
            reviewer_id="human-lucia-chen-syn",
        ),
        _DemoJourney.PENDING_PRESS_STATEMENT: _scenario(
            partner,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("program_pending_milestone",),
            ("MNPI_CANDIDATE",),
            human_review_allowed=True,
        ),
        _DemoJourney.UNSPECIFIED_FORWARDING: _scenario(
            partner,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("program_current_milestone",),
            ("IP_CONFIDENTIAL",),
            missing_context=("partner_authorization",),
        ),
        _DemoJourney.OTHER_TENANT: _scenario(
            partner,
            "partner_status",
            "partner-alpha-synthetic",
            external,
            ("synthetic_detector_candidate",),
            ("EXTERNAL_APPROVED",),
            identity_authorized=False,
        ),
    }


_SCENARIOS = _build_scenarios()


class _DemoRuntime:
    def __init__(
        self,
        *,
        engine: object,
        bedrock_client: object,
        signer: _ReceiptSigner,
        verifier: _ReceiptVerifier,
        key_id: str,
        guardrail_id: str,
        guardrail_version: str,
        app_sha256: str,
        scanner: _ContentScanner | None = None,
        telemetry_batch_sink: (
            Callable[[tuple[Mapping[str, object], ...]], object] | None
        ) = None,
    ) -> None:
        self._clock = _Clock()
        self._engine = engine
        self._signer = signer
        self._verifier = verifier
        if not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise ValueError("key_id is invalid")
        self._key_id = key_id
        self._app_sha256 = app_sha256
        self._telemetry_batch_sink = telemetry_batch_sink
        self._input_guard = _BedrockInputGuard(
            bedrock_client,  # type: ignore[arg-type]
            guardrail_identifier=guardrail_id,
            guardrail_version=guardrail_version,
        )
        content_scanner = _ContentScanner() if scanner is None else scanner
        self._executor = _BedrockRecallExecutor(
            embedder=_TitanTextEmbeddingsV2(bedrock_client),
            memory_store=_CockroachMemoryStore(
                engine,
                application_principal=_RUNTIME_PRINCIPAL,  # type: ignore[arg-type]
            ),
            generator=_SyntheticDemoGenerator(
                _NovaLiteConverse(
                    bedrock_client,
                    guardrail_identifier=guardrail_id,
                    guardrail_version=guardrail_version,
                    max_output_tokens=192,
                )
            ),
            scanner=content_scanner,
            memory_projector=_ClinicalModelSafeProjector(content_scanner),
        )
        self._session_writer = _CockroachSessionContextWriter(
            engine,
            application_principal=_RUNTIME_PRINCIPAL,  # type: ignore[arg-type]
        )
        self._receipt_store = _CockroachReceiptStore(
            engine,
            application_principal=_RUNTIME_PRINCIPAL,  # type: ignore[arg-type]
        )
        self._pending_store = _CockroachPendingActionStore(
            engine,
            application_principal=_RUNTIME_PRINCIPAL,  # type: ignore[arg-type]
        )
        self._approval_store = _CockroachApprovalStore(
            engine,
            application_principal=_RUNTIME_PRINCIPAL,  # type: ignore[arg-type]
        )

    def guard_input(self, query: str) -> bool:
        """Evaluate one bounded request before session, recall, or model activity."""

        return self._input_guard(query)

    def __call__(self, request: _SyntheticRequest) -> dict[str, object]:
        if not isinstance(request, _SyntheticRequest):
            raise TypeError("request must be a synthetic request")
        started_ns = time.perf_counter_ns()
        try:
            return self._execute_request(request, started_ns)
        except Exception:
            self._emit_telemetry(
                (
                    _TelemetryPoint(
                        0,
                        _TelemetryStage.REQUEST,
                        _TelemetryStatus.UNAVAILABLE,
                        _elapsed_ms(started_ns),
                        persona=request.persona,
                        operation=MemoryOperation.RECALL,
                    ),
                )
            )
            raise

    def _execute_request(
        self,
        request: _SyntheticRequest,
        started_ns: int,
    ) -> dict[str, object]:
        persona, journey, query = request.persona, request.journey, request.query
        _journey_for(persona, journey)
        spec = _SCENARIOS[journey]
        now = self._clock.now()
        session_id, intent_id, request_id = uuid4(), uuid4(), uuid4()
        intent_hash = hashlib.sha256(
            f"synthetic:{persona.value}:{journey.value}:{query}".encode()
        ).hexdigest()
        try:
            self._session_writer.write(
                _SessionContextRecord(
                    tenant_id=_TENANT_ID,
                    program_id=_PROGRAM_ID,
                    session_id=session_id,
                    intent_id=intent_id,
                    intent_label=f"demo_{journey.value}",
                    original_intent_sha256=intent_hash,
                    agent_id="gluevenir-bio",
                    actor_id=spec.actor_id,
                    actor_role=spec.actor_role,
                    declared_purpose=spec.purpose,
                    declared_audience=spec.audience,
                    classification_summary=tuple(
                        _ClassificationCount(_CandidateLabel(value), 1)
                        for value in spec.data_classes
                        if value != "EXTERNAL_APPROVED"
                    ),
                    prior_receipt_ids=(),
                    created_at=now,
                    updated_at=now,
                    expires_at=now + timedelta(minutes=15),
                )
            )
        except (
            _SessionDatabaseAuthorizationError,
            _SessionDatabaseConnectionRefusedError,
            _SessionDatabaseDnsError,
            _SessionDatabaseError,
            _SessionDatabaseOperationalError,
            _SessionDatabaseTimeoutError,
            _SessionDatabaseTlsError,
        ):
            raise
        except PermissionError:
            raise _SessionContextAuthorizationFailure from None
        except RuntimeError:
            raise _SessionContextConsistencyFailure from None
        except Exception:
            raise _SessionContextFailure from None
        approval = None
        approval_duration_ms = None
        approval_offset_ms = None
        if spec.approval_id is not None:
            if spec.reviewer_id is None:
                raise _ApprovalLoadFailure
            approval_started_ns = time.perf_counter_ns()
            try:
                approval = self._approval_store.load_approved(
                    spec.approval_id,
                    reviewer=_TrustedReviewerIdentity(
                        spec.reviewer_id,
                        "human_reviewer",
                        _TENANT_ID,
                        _PROGRAM_ID,
                    ),
                    purpose=spec.purpose,
                    audience=spec.audience,
                    policy_version=_POLICY_VERSION,
                    now=now,
                )
            except Exception:
                raise _ApprovalLoadFailure from None
            approval_duration_ms = _elapsed_ms(approval_started_ns)
            approval_offset_ms = _offset_ms(started_ns, approval_started_ns)
        arguments = {"query": query, "top_k": 4}
        action = _GatewayAction(
            request_id=request_id,
            session_id=session_id,
            intent_id=intent_id,
            agent_id="gluevenir-bio",
            actor_id=spec.actor_id,
            evaluated_at=now,
            action_arguments_sha256=_hash_action_arguments(arguments),
            original_intent_sha256=intent_hash,
            prior_action_context_sha256=_prior_receipt_context_sha256(()),
            policy=_PolicyAction(
                MemoryOperation.RECALL,
                _TENANT_ID,
                _PROGRAM_ID,
                spec.actor_role,
                spec.purpose,
                spec.audience,
                spec.destination,
                _POLICY_VERSION,
                spec.requested_ids,
                spec.data_classes,
            ),
        )
        sink = self._sink()
        executor = _TimedRecallExecutor(self._executor)
        gateway_started_ns = time.perf_counter_ns()
        try:
            result = _MemoryActionGateway(
                policy=_BioDemoPolicy(),
                executor=executor,  # type: ignore[arg-type]
                receipt_sink=sink,
                pending_store=self._pending_store,
                clock=self._clock,
            ).execute(
                action=action,
                action_arguments=arguments,
                facts=_PolicyFacts(
                    now=now,
                    policy_available=True,
                    identity_authorized=spec.identity_authorized,
                    missing_context=spec.missing_context,
                    approved_derivative=approval,
                    human_review_allowed=spec.human_review_allowed,
                ),
            )
        except Exception:
            raise _GatewayExecutionFailure from None
        gateway_duration_ms = _elapsed_ms(gateway_started_ns)
        recall_offset_ms, recall_duration_ms = executor.timing(
            executor.prepare_timing_ns,
            started_ns,
        )
        model_offset_ms, model_duration_ms = executor.timing(
            executor.execute_timing_ns,
            started_ns,
        )
        receipt_offset_ms, receipt_duration_ms = sink.timing(started_ns)
        projection_started_ns = time.perf_counter_ns()
        signed = sink.signed[-1]
        public = self._public(result, signed)
        projection_duration_ms = _elapsed_ms(projection_started_ns)
        self._emit_telemetry(
            _runtime_telemetry_points(
                persona=persona,
                result=result,
                signed=signed,
                signature_verified=bool(
                    public["public_receipt"]["signature_verified"]  # type: ignore[index]
                ),
                total_duration_ms=_elapsed_ms(started_ns),
                gateway_offset_ms=_offset_ms(started_ns, gateway_started_ns),
                gateway_duration_ms=gateway_duration_ms,
                recall_offset_ms=recall_offset_ms,
                recall_duration_ms=recall_duration_ms,
                model_offset_ms=model_offset_ms,
                model_duration_ms=model_duration_ms,
                receipt_offset_ms=receipt_offset_ms,
                receipt_duration_ms=receipt_duration_ms,
                projection_offset_ms=_offset_ms(started_ns, projection_started_ns),
                projection_duration_ms=projection_duration_ms,
                approval_offset_ms=approval_offset_ms,
                approval_duration_ms=approval_duration_ms,
            )
        )
        return public

    def _emit_telemetry(self, points: tuple[_TelemetryPoint, ...]) -> None:
        if self._telemetry_batch_sink is None:
            return
        try:
            self._telemetry_batch_sink(tuple(point.as_span() for point in points))
        except Exception:
            _log_telemetry_health("unavailable", "export_failed")
            return

    def _sink(self) -> _CapturingSink:
        delegate = _SignedReceiptSink(
            signer=self._signer,
            store=self._receipt_store,
            clock=self._clock,
            new_receipt_id=uuid4,
            key_id=self._key_id,
            policy_sha256=hashlib.sha256(_POLICY_VERSION.encode()).hexdigest(),
            app_version="0.1.0",
            app_sha256=self._app_sha256,
        )
        return _CapturingSink(delegate, self._receipt_store)

    def _public(
        self, result: _GatewayResult, signed: _SignedReceipt
    ) -> dict[str, object]:
        if result.response_status is _ResponseStatus.FAILED:
            raise _GatewayExecutionFailure
        payload = signed.payload
        output = result.output
        summaries = {
            "DENY": "The synthetic request was denied before memory execution.",
            "STEP_UP": (
                "The synthetic action awaits exact human approval; "
                "memory execution did not run."
            ),
            "DEFER": (
                "The synthetic action awaits trusted context; "
                "memory execution did not run."
            ),
        }
        if isinstance(output, _AgentAnswer):
            summary = output.text
        else:
            summary = summaries.get(result.decision.value)
            if summary is None:
                raise _GatewayExecutionFailure
        return {
            "decision": result.decision.value,
            "public_summary": summary,
            "public_receipt": {
                "receipt_id": str(payload.receipt_id),
                "decision": payload.decision,
                "reason_code": payload.reason_code,
                "included_memory_ids": [
                    str(value) for value in payload.included_memory_ids
                ],
                "included_content_sha256": list(payload.included_content_sha256),
                "action_arguments_sha256": payload.action_arguments_sha256,
                "policy_sha256": payload.policy_sha256,
                "agent_signing_key_id": payload.agent_signing_key_id,
                "exclusion_counts": dict(payload.exclusion_counts),
                "signature_verified": self._verifier.verify(signed),
            },
            **(
                {"pending_action_id": str(result.pending_action_id)}
                if result.pending_action_id is not None
                else {}
            ),
        }


def _runtime_from_environment() -> _DemoRuntime:
    import boto3

    region = os.environ.get("AWS_REGION", "us-east-1")
    secrets_client = boto3.client("secretsmanager", region_name=region)
    deployment_secrets = _deployment_secrets(
        secrets_client,
        cockroach_secret_arn=os.environ["GLUEVENIR_COCKROACH_SECRET_ARN"],
        signing_secret_arn=os.environ["GLUEVENIR_SIGNING_SECRET_ARN"],
    )
    raw_key = base64.b64decode(deployment_secrets["private_key_b64"], validate=True)
    private_key = Ed25519PrivateKey.from_private_bytes(raw_key)
    key_id = os.environ["GLUEVENIR_SIGNING_KEY_ID"]
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio", key_id=key_id, private_key=private_key
    )
    verifier = _ReceiptVerifier.from_public_key_bytes(
        agent_id="gluevenir-bio", key_id=key_id, public_key=signer.public_key_bytes()
    )
    engine = create_engine(
        _runtime_database_url(
            deployment_secrets["runtime_database_url"],
            database_name=os.environ.get("GLUEVENIR_DATABASE"),
            root_certificate=os.environ["GLUEVENIR_SSL_ROOT_CERT"],
        ),
        poolclass=NullPool,
        hide_parameters=True,
    )
    return _DemoRuntime(
        engine=engine,
        bedrock_client=boto3.client("bedrock-runtime", region_name=region),
        signer=signer,
        verifier=verifier,
        key_id=key_id,
        guardrail_id=os.environ["GLUEVENIR_BEDROCK_GUARDRAIL_ID"],
        guardrail_version=os.environ.get("GLUEVENIR_BEDROCK_GUARDRAIL_VERSION", "2"),
        app_sha256=os.environ["GLUEVENIR_APP_SHA256"],
        scanner=_ContentScanner(
            _CompositeDetector(
                (
                    _DeterministicDetector(),
                    _PresidioDetector(_create_presidio_analyzer()),
                )
            )
        ),
        telemetry_batch_sink=_optional_otlp_batch_sink(secrets_client),
    )


def _optional_otlp_batch_sink(client: object):
    endpoint = os.environ.get("GLUEVENIR_OTLP_TRACES_ENDPOINT")
    secret_arn = os.environ.get("GLUEVENIR_OTLP_AUTH_SECRET_ARN")
    if endpoint is None and secret_arn is None:
        return None
    if endpoint is None or secret_arn is None:
        _log_telemetry_health("disabled", "partial_configuration")
        return None
    try:
        bearer_token = _otlp_bearer_token(client, secret_arn)
        return _flushing_batch_sink(
            _create_otlp_span_sink(
                endpoint,
                bearer_token=bearer_token,
            )
        )
    except Exception:
        _log_telemetry_health("disabled", "configuration_failed")
        return None


def _flushing_batch_sink(
    sink: _BatchSpanSink,
) -> Callable[[tuple[Mapping[str, object], ...]], None]:
    def emit(envelopes: tuple[Mapping[str, object], ...]) -> None:
        sink.emit_batch(envelopes)
        if not sink.force_flush(1_000):
            raise RuntimeError("bounded telemetry flush failed")

    return emit


def _log_telemetry_health(status: str, reason_code: str) -> None:
    _LOG.warning(
        "%s",
        json.dumps(
            {
                "event": "telemetry_export_health",
                "reason_code": reason_code,
                "status": status,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _runtime_telemetry_points(
    *,
    persona: _DemoPersona,
    result: _GatewayResult,
    signed: _SignedReceipt,
    signature_verified: bool,
    total_duration_ms: int,
    gateway_offset_ms: int,
    gateway_duration_ms: int,
    recall_offset_ms: int,
    recall_duration_ms: int,
    model_offset_ms: int,
    model_duration_ms: int,
    receipt_offset_ms: int,
    receipt_duration_ms: int,
    projection_offset_ms: int,
    projection_duration_ms: int,
    approval_offset_ms: int | None,
    approval_duration_ms: int | None,
) -> tuple[_TelemetryPoint, ...]:
    status = _TELEMETRY_STATUS[result.decision]
    payload = signed.payload
    included_count = payload.included_count
    excluded_count = payload.candidate_count - included_count
    model_invoked = (
        result.output.model_invoked
        if isinstance(result.output, _AgentAnswer)
        else False
    )
    points = [
        _TelemetryPoint(
            0,
            _TelemetryStage.REQUEST,
            status,
            total_duration_ms,
            persona=persona,
            operation=MemoryOperation.RECALL,
        )
    ]
    if approval_duration_ms is not None:
        if approval_offset_ms is None:
            raise ValueError("approval timing is incomplete")
        points.append(
            _TelemetryPoint(
                len(points),
                _TelemetryStage.APPROVAL,
                _TelemetryStatus.SUCCEEDED,
                approval_duration_ms,
                start_offset_ms=approval_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
            )
        )
    points.extend(
        (
            _TelemetryPoint(
                len(points),
                _TelemetryStage.GATEWAY_EVALUATION,
                status,
                gateway_duration_ms,
                start_offset_ms=gateway_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
                decision=result.decision,
                reason_code=result.reason_code,
            ),
            _TelemetryPoint(
                len(points) + 1,
                _TelemetryStage.RECALL,
                status,
                recall_duration_ms,
                start_offset_ms=recall_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
                candidate_count=payload.candidate_count,
                included_count=included_count,
                excluded_count=excluded_count,
            ),
            _TelemetryPoint(
                len(points) + 2,
                _TelemetryStage.MODEL,
                _TelemetryStatus.SUCCEEDED if model_invoked else status,
                model_duration_ms,
                start_offset_ms=model_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
                model_invoked=model_invoked,
            ),
            _TelemetryPoint(
                len(points) + 3,
                _TelemetryStage.RECEIPT,
                (
                    _TelemetryStatus.SUCCEEDED
                    if signature_verified
                    else _TelemetryStatus.FAILED
                ),
                receipt_duration_ms,
                start_offset_ms=receipt_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
                receipt_verified=signature_verified,
            ),
            _TelemetryPoint(
                len(points) + 4,
                _TelemetryStage.RESPONSE_PROJECTION,
                status,
                projection_duration_ms,
                start_offset_ms=projection_offset_ms,
                persona=persona,
                operation=MemoryOperation.RECALL,
                decision=result.decision,
            ),
        )
    )
    return tuple(points)


def _elapsed_ms(started_ns: int) -> int:
    elapsed = max(0, (time.perf_counter_ns() - started_ns) // 1_000_000)
    return min(elapsed, 120_000)


def _duration_ms(started_ns: int, ended_ns: int) -> int:
    return min(max(0, ended_ns - started_ns) // 1_000_000, 120_000)


def _offset_ms(request_started_ns: int, stage_started_ns: int) -> int:
    return min(max(0, stage_started_ns - request_started_ns) // 1_000_000, 120_000)


def _runtime_database_url(
    raw_url: str, *, database_name: str | None, root_certificate: str
):
    if root_certificate != _SYSTEM_CA_BUNDLE:
        raise ValueError("runtime root certificate must use the image CA bundle")
    url = cockroach_url(raw_url, database_name=database_name)
    if url.query.get("sslmode") != "verify-full" or "sslrootcert" in url.query:
        raise ValueError("runtime database URL must require full TLS verification")
    return url.update_query_dict({"sslrootcert": root_certificate})


def _deployment_secrets(
    client: object, *, cockroach_secret_arn: str, signing_secret_arn: str
) -> dict[str, str]:
    if not _bounded_secret_arn(cockroach_secret_arn) or not _bounded_secret_arn(
        signing_secret_arn
    ):
        raise ValueError("invalid secret reference")
    return {
        "runtime_database_url": _secret_value(
            client, cockroach_secret_arn, "runtime_database_url"
        ),
        "private_key_b64": _secret_value(client, signing_secret_arn, "private_key_b64"),
    }


def _secret_value(client: object, secret_arn: str, key: str) -> str:
    getter = getattr(client, "get_secret_value", None)
    if not callable(getter):
        raise TypeError("invalid secrets client")
    response = getter(SecretId=secret_arn)
    if type(response) is not dict or type(response.get("SecretString")) is not str:
        raise ValueError("secret value unavailable")
    try:
        value = json.loads(response["SecretString"], object_pairs_hook=_unique_pairs)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("invalid secret value") from None
    if type(value) is not dict or set(value) != {key}:
        raise ValueError("invalid secret shape")
    secret = value[key]
    if type(secret) is not str or not secret or len(secret) > 8192:
        raise ValueError("invalid secret field")
    return secret


def _otlp_bearer_token(client: object, secret_arn: str) -> str:
    if not _bounded_secret_arn(secret_arn):
        raise ValueError("invalid secret reference")
    getter = getattr(client, "get_secret_value", None)
    if not callable(getter):
        raise TypeError("invalid secrets client")
    response = getter(SecretId=secret_arn)
    if type(response) is not dict or type(response.get("SecretString")) is not str:
        raise ValueError("secret value unavailable")
    try:
        value = json.loads(response["SecretString"], object_pairs_hook=_unique_pairs)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise ValueError("invalid secret value") from None
    if (
        type(value) is not dict
        or set(value) != {"schema", "bearer_token"}
        or value.get("schema") != "gluevenir.otlp.auth.v1"
    ):
        raise ValueError("invalid OTLP secret shape")
    token = value["bearer_token"]
    if (
        type(token) is not str
        or not 16 <= len(token) <= 512
        or any(character.isspace() for character in token)
    ):
        raise ValueError("invalid OTLP secret field")
    return token


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate secret field")
        result[key] = value
    return result


def _bounded_secret_arn(value: object) -> bool:
    return (
        type(value) is str
        and 20 <= len(value) <= 512
        and value.startswith("arn:")
        and ":secretsmanager:" in value
    )


def _unavailable(_request: _SyntheticRequest) -> dict[str, object]:
    raise RuntimeError("runtime unavailable")


def _safe_event_sink(event: object) -> None:
    _LOG.warning("%s", json.dumps(event, sort_keys=True, separators=(",", ":")))


try:
    _recall = _runtime_from_environment()
    _input_guard = _recall.guard_input
except Exception as error:
    _LOG.warning(
        "%s",
        json.dumps(
            {
                "event": "runtime_initialization_failed",
                "failure_type": type(error).__name__,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
    )
    _recall = _unavailable
    _input_guard = None

handler = create_lambda_handler(
    recall=_recall,
    input_guard=_input_guard,
    allowed_origins=tuple(
        value.strip()
        for value in os.environ.get("GLUEVENIR_ALLOWED_ORIGINS", "").split(",")
        if value.strip()
    ),
    event_sink=_safe_event_sink,
)
