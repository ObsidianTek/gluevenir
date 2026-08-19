from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest

from gluevenir._agent import (
    _AgentAnswer,
    _AgentUnavailable,
    _AuthorizedMemoryProjector,
    _BedrockRecallExecutor,
    _ModelMemory,
)
from gluevenir._detectors import (
    _CandidateLabel,
    _ContentScanner,
    _DetectionResult,
    _FindingSummary,
    _ScanInput,
)
from gluevenir._gateway import _GatewayAction, _hash_action_arguments
from gluevenir._memory_store import RecalledMemory, RecallScope
from gluevenir._policy import _Destination, _PolicyAction
from gluevenir._ports import MemoryOperation

TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
PROGRAM_ID = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
SOURCE_ID = UUID("10000000-0000-4000-8000-000000000001")
DERIVATIVE_ID = UUID("10000000-0000-4000-8000-000000000002")
CLINICAL_MEMORY_ID = UUID("10000000-0000-4000-8000-000000000003")
NOW = datetime(2026, 8, 15, 18, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
CLINICAL_HASH = "b9a8af7e45d9e814328e0a72a0281228a6187f3dc620789b93369dc62def3434"
ARGUMENTS = {"query": "What changed for HX-17?", "top_k": 4}


class _Embedder:
    def __init__(self, *, fails: bool = False) -> None:
        self.fails = fails
        self.queries: list[str] = []

    def embed(self, text: str) -> tuple[float, ...]:
        self.queries.append(text)
        if self.fails:
            raise RuntimeError("provider detail")
        return (0.25,) * 256


class _Store:
    def __init__(self, records: tuple[RecalledMemory, ...]) -> None:
        self.records = records
        self.scopes: list[RecallScope] = []

    def recall(self, scope: RecallScope) -> tuple[RecalledMemory, ...]:
        self.scopes.append(scope)
        return self.records


class _Generator:
    def __init__(self, answer: str | tuple[str, ...]) -> None:
        self.answers = (answer,) if isinstance(answer, str) else answer
        self.calls: list[tuple[str, str]] = []

    def generate(
        self,
        request: str,
        *,
        authorized_memory: str,
        allowed_tool: object | None = None,
    ) -> str:
        assert allowed_tool is None
        self.calls.append((request, authorized_memory))
        return self.answers[min(len(self.calls) - 1, len(self.answers) - 1)]


def _action(*, external: bool = False, clinical: bool = False) -> _GatewayAction:
    audience = (
        "partner-alpha-synthetic"
        if external
        else "internal-clinical"
        if clinical
        else "internal-program-lead"
    )
    destination = _Destination.EXTERNAL if external else _Destination.INTERNAL
    return _GatewayAction(
        request_id=UUID("50000000-0000-4000-8000-000000000001"),
        session_id=UUID("60000000-0000-4000-8000-000000000001"),
        intent_id=UUID("70000000-0000-4000-8000-000000000001"),
        agent_id="gluevenir-bio",
        actor_id=(
            "synthetic-clinical-operations-lead"
            if clinical
            else "synthetic-program-lead"
        ),
        evaluated_at=NOW,
        action_arguments_sha256=_hash_action_arguments(ARGUMENTS),
        original_intent_sha256=HASH_A,
        prior_action_context_sha256=HASH_B,
        policy=_PolicyAction(
            operation=MemoryOperation.RECALL,
            tenant_id=TENANT_ID,
            program_id=PROGRAM_ID,
            actor_role="clinical_operations_lead" if clinical else "program_lead",
            purpose=(
                "partner_status"
                if external
                else "safety_review"
                if clinical
                else "program_status"
            ),
            audience=audience,
            destination=destination,
            policy_version="bio-demo-v1",
            requested_memory_ids=(SOURCE_ID,),
            data_classes=("IP_CONFIDENTIAL",),
        ),
    )


def _executor(
    records: tuple[RecalledMemory, ...],
    *,
    answer: str | tuple[str, ...] = "Synthetic authorized status is on schedule.",
    embedder: _Embedder | None = None,
    scanner: _ContentScanner | None = None,
    memory_projector: _AuthorizedMemoryProjector | None = None,
) -> tuple[_BedrockRecallExecutor, _Store, _Generator, _Embedder]:
    store = _Store(records)
    generator = _Generator(answer)
    actual_embedder = embedder or _Embedder()
    return (
        _BedrockRecallExecutor(
            embedder=actual_embedder,
            memory_store=store,
            generator=generator,
            scanner=_ContentScanner() if scanner is None else scanner,
            memory_projector=memory_projector,
        ),
        store,
        generator,
        actual_embedder,
    )


class _SentinelNameDetector:
    def detect(self, subject: _ScanInput) -> _DetectionResult:
        if "Maya Ellison" not in subject.text:
            return _DetectionResult(())
        return _DetectionResult(
            (
                _FindingSummary(
                    _CandidateLabel.PII,
                    "synthetic-name-detector-v1",
                    1,
                ),
            )
        )


class _FailingDetector:
    def detect(self, subject: _ScanInput) -> _DetectionResult:
        raise RuntimeError("raw detector failure detail")


def test_internal_prepare_embeds_after_authorization_and_binds_scoped_rows() -> None:
    source = RecalledMemory(SOURCE_ID, "Synthetic internal fact.", HASH_A)
    executor, store, _, embedder = _executor((source,))

    prepared = executor.prepare(
        action=_action(),
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )

    assert embedder.queries == [ARGUMENTS["query"]]
    assert prepared.memory_ids == (SOURCE_ID,)
    assert prepared.content_sha256 == (HASH_A,)
    assert prepared.payload.model_content_sha256 == (
        hashlib.sha256(source.content.encode()).hexdigest(),
    )
    assert prepared.model_prompt_sha256 == prepared.payload.model_prompt_sha256
    assert prepared.payload.source_content_sha256 == (HASH_A,)
    assert store.scopes[0].allowed_rooms == (
        "clinical-restricted",
        "research-confidential",
    )
    assert store.scopes[0].tenant_id == TENANT_ID
    assert store.scopes[0].program_id == PROGRAM_ID


def test_external_modify_returns_only_exact_derivative_without_model() -> None:
    source = RecalledMemory(SOURCE_ID, "Restricted formulation source.", HASH_A)
    derivative_content = "Synthetic approved status remains on schedule."
    derivative_hash = hashlib.sha256(derivative_content.encode()).hexdigest()
    derivative = RecalledMemory(DERIVATIVE_ID, derivative_content, derivative_hash)
    executor, store, generator, _ = _executor((source, derivative))
    action = _action(external=True)

    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(DERIVATIVE_ID,),
        expected_content_sha256=(derivative_hash,),
        action_arguments=ARGUMENTS,
    )
    answer = executor.execute(
        action=action,
        prepared=prepared,
        action_arguments=ARGUMENTS,
    )

    assert isinstance(answer, _AgentAnswer)
    assert answer.memory_ids == (DERIVATIVE_ID,)
    assert answer.content_sha256 == (derivative_hash,)
    assert answer.text == derivative_content
    assert answer.model_invoked is False
    assert prepared.model_prompt_sha256 is None
    assert store.scopes[0].allowed_rooms == ("external-approved",)
    assert generator.calls == []
    memory_document = json.loads(prepared.payload.authorized_memory_json)
    model_memory = memory_document["authorized_memories"][0]
    assert model_memory["source_memory_id"] == str(DERIVATIVE_ID)
    assert model_memory["source_content_sha256"] == derivative_hash
    assert (
        model_memory["content_sha256"]
        == hashlib.sha256(model_memory["content"].encode()).hexdigest()
    )
    assert (
        "Restricted formulation source" not in prepared.payload.authorized_memory_json
    )
    assert "Synthetic approved status" in prepared.payload.authorized_memory_json


def test_clinical_projection_keeps_useful_facts_and_identifiers_out_of_model() -> None:
    from gluevenir._demo_runtime import _ClinicalModelSafeProjector

    raw = (
        "SYNTHETIC DATA: Maya Ellison moved the Day 42 follow-up from "
        "2026-08-19 to 2026-08-21. Contact maya.ellison@example.test or "
        "+1 202-555-0147."
    )
    source = RecalledMemory(CLINICAL_MEMORY_ID, raw, CLINICAL_HASH)
    scanner = _ContentScanner(_SentinelNameDetector())
    executor, _, generator, _ = _executor(
        (source,),
        answer=(
            "The synthetic Day 42 follow-up moved from 2026-08-19 to "
            "2026-08-21 because of participant availability."
        ),
        scanner=scanner,
        memory_projector=_ClinicalModelSafeProjector(scanner),
    )
    action = _action(clinical=True)

    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(CLINICAL_MEMORY_ID,),
        expected_content_sha256=(CLINICAL_HASH,),
        action_arguments=ARGUMENTS,
    )
    answer = executor.execute(
        action=action,
        prepared=prepared,
        action_arguments=ARGUMENTS,
    )

    assert answer.memory_ids == (CLINICAL_MEMORY_ID,)
    assert answer.content_sha256 == (CLINICAL_HASH,)
    assert prepared.payload.model_content_sha256 == (
        "158ea2cbc885d5eae559e7ad7bc5beecffe312d56c7a149c9cece2d4d28a47ba",
    )
    assert prepared.model_prompt_sha256 == prepared.payload.model_prompt_sha256
    assert prepared.payload.source_content_sha256 == (CLINICAL_HASH,)
    assert "Day 42 follow-up moved" in answer.text
    model_input = generator.calls[0][1]
    model_memory = json.loads(model_input)["authorized_memories"][0]
    assert model_memory["source_memory_id"] == str(CLINICAL_MEMORY_ID)
    assert model_memory["source_content_sha256"] == CLINICAL_HASH
    assert (
        model_memory["content_sha256"]
        == hashlib.sha256(model_memory["content"].encode()).hexdigest()
    )
    assert model_memory["content_sha256"] != model_memory["source_content_sha256"]
    assert "Day 42 follow-up moved" in model_input
    for identifier in (
        "Maya Ellison",
        "maya.ellison@example.test",
        "+1 202-555-0147",
    ):
        assert identifier not in model_input
        assert identifier not in answer.text


def test_model_memory_rejects_content_hash_tampering() -> None:
    safe_content = "SYNTHETIC DATA: bounded model-safe status."

    with pytest.raises(ValueError, match="does not match"):
        _ModelMemory(
            source_memory_id=CLINICAL_MEMORY_ID,
            source_content_sha256=CLINICAL_HASH,
            content=f"{safe_content} tampered",
            content_sha256=hashlib.sha256(safe_content.encode()).hexdigest(),
        )


def test_clinical_projection_detector_failure_fails_before_model() -> None:
    from gluevenir._demo_runtime import _ClinicalModelSafeProjector

    source = RecalledMemory(
        CLINICAL_MEMORY_ID,
        "Maya Ellison, maya.ellison@example.test, +1 202-555-0147.",
        CLINICAL_HASH,
    )
    scanner = _ContentScanner(_FailingDetector())
    executor, _, generator, _ = _executor(
        (source,),
        scanner=scanner,
        memory_projector=_ClinicalModelSafeProjector(scanner),
    )

    with pytest.raises(_AgentUnavailable, match="preparation failed") as error:
        executor.prepare(
            action=_action(clinical=True),
            executable_memory_ids=(CLINICAL_MEMORY_ID,),
            expected_content_sha256=(CLINICAL_HASH,),
            action_arguments=ARGUMENTS,
        )

    assert error.value.__cause__ is None
    assert "raw detector failure detail" not in repr(error.value)
    assert generator.calls == []


def test_clinical_output_name_leakage_still_fails_closed() -> None:
    from gluevenir._demo_runtime import _ClinicalModelSafeProjector

    source = RecalledMemory(
        CLINICAL_MEMORY_ID,
        "Maya Ellison, maya.ellison@example.test, +1 202-555-0147.",
        CLINICAL_HASH,
    )
    scanner = _ContentScanner(_SentinelNameDetector())
    executor, _, generator, _ = _executor(
        (source,),
        answer="Maya Ellison completed the synthetic follow-up.",
        scanner=scanner,
        memory_projector=_ClinicalModelSafeProjector(scanner),
    )
    action = _action(clinical=True)
    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(CLINICAL_MEMORY_ID,),
        expected_content_sha256=(CLINICAL_HASH,),
        action_arguments=ARGUMENTS,
    )

    with pytest.raises(_AgentUnavailable, match="execution failed") as error:
        executor.execute(
            action=action,
            prepared=prepared,
            action_arguments=ARGUMENTS,
        )

    assert len(generator.calls) == 2
    assert "Maya Ellison" not in repr(error.value)


def test_external_output_scanner_blocks_restricted_candidate() -> None:
    derivative_content = "The confidential formulation is HX-17-FORMULA-Z9."
    derivative_hash = hashlib.sha256(derivative_content.encode()).hexdigest()
    derivative = RecalledMemory(
        DERIVATIVE_ID,
        derivative_content,
        derivative_hash,
    )
    executor, _, generator, _ = _executor(
        (derivative,),
    )
    action = _action(external=True)
    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(DERIVATIVE_ID,),
        expected_content_sha256=(derivative_hash,),
        action_arguments=ARGUMENTS,
    )

    with pytest.raises(_AgentUnavailable, match="execution failed") as error:
        executor.execute(
            action=action,
            prepared=prepared,
            action_arguments=ARGUMENTS,
        )

    assert generator.calls == []
    assert "FORMULA-Z9" not in repr(error.value)


def test_internal_output_scanner_blocks_direct_identifier_but_allows_ip_context() -> (
    None
):
    source = RecalledMemory(SOURCE_ID, "Synthetic internal fact.", HASH_A)
    blocked, _, _, _ = _executor(
        (source,),
        answer="Synthetic SUBJECT DEMO004 completed a dose follow-up.",
    )
    prepared = blocked.prepare(
        action=_action(),
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )
    with pytest.raises(_AgentUnavailable, match="execution failed"):
        blocked.execute(
            action=_action(),
            prepared=prepared,
            action_arguments=ARGUMENTS,
        )

    allowed, _, _, _ = _executor(
        (source,),
        answer="Synthetic confidential formulation checkpoint remains stable.",
    )
    prepared = allowed.prepare(
        action=_action(),
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )
    answer = allowed.execute(
        action=_action(),
        prepared=prepared,
        action_arguments=ARGUMENTS,
    )
    assert answer.text.startswith("Synthetic confidential")
    assert answer.model_invoked is True


def test_internal_output_retries_one_rejected_draft_without_disclosing_it() -> None:
    source = RecalledMemory(SOURCE_ID, "Synthetic internal fact.", HASH_A)
    executor, _, generator, _ = _executor(
        (source,),
        answer=(
            "Synthetic SUBJECT DEMO004 completed a dose follow-up.",
            "Synthetic aggregate follow-up status remains on schedule.",
        ),
    )
    action = _action()
    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )

    answer = executor.execute(
        action=action,
        prepared=prepared,
        action_arguments=ARGUMENTS,
    )

    assert answer.text == "Synthetic aggregate follow-up status remains on schedule."
    assert len(generator.calls) == 2
    assert "DEMO004" not in repr(answer)


def test_internal_output_second_rejected_draft_still_fails_closed() -> None:
    source = RecalledMemory(SOURCE_ID, "Synthetic internal fact.", HASH_A)
    executor, _, generator, _ = _executor(
        (source,),
        answer=(
            "Synthetic SUBJECT DEMO004 completed a dose follow-up.",
            "Synthetic SUBJECT DEMO005 completed a dose follow-up.",
        ),
    )
    action = _action()
    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )

    with pytest.raises(_AgentUnavailable, match="execution failed") as error:
        executor.execute(
            action=action,
            prepared=prepared,
            action_arguments=ARGUMENTS,
        )

    assert len(generator.calls) == 2
    assert "DEMO00" not in repr(error.value)


def test_internal_output_detector_outage_is_not_retried() -> None:
    source = RecalledMemory(SOURCE_ID, "Synthetic internal fact.", HASH_A)
    executor, _, generator, _ = _executor(
        (source,),
        scanner=_ContentScanner(_FailingDetector()),
    )
    action = _action()
    prepared = executor.prepare(
        action=action,
        executable_memory_ids=(SOURCE_ID,),
        expected_content_sha256=(),
        action_arguments=ARGUMENTS,
    )

    with pytest.raises(_AgentUnavailable, match="execution failed"):
        executor.execute(
            action=action,
            prepared=prepared,
            action_arguments=ARGUMENTS,
        )

    assert len(generator.calls) == 1


def test_prepare_failures_are_sanitized_and_model_is_not_called() -> None:
    executor, store, generator, _ = _executor((), embedder=_Embedder(fails=True))

    with pytest.raises(_AgentUnavailable, match="preparation failed") as error:
        executor.prepare(
            action=_action(),
            executable_memory_ids=(SOURCE_ID,),
            expected_content_sha256=(),
            action_arguments=ARGUMENTS,
        )

    assert error.value.__cause__ is None
    assert store.scopes == []
    assert generator.calls == []


@pytest.mark.parametrize(
    "arguments",
    [
        {"query": "", "top_k": 4},
        {"query": "synthetic", "top_k": True},
        {"query": "synthetic", "top_k": 6},
        {"query": "synthetic", "top_k": 4, "tenant_id": "other"},
    ],
)
def test_invalid_recall_arguments_fail_before_embedding(
    arguments: dict[str, object],
) -> None:
    executor, store, generator, embedder = _executor(())

    with pytest.raises(ValueError, match="arguments|query|top_k"):
        executor.prepare(
            action=_action(),
            executable_memory_ids=(SOURCE_ID,),
            expected_content_sha256=(),
            action_arguments=arguments,
        )

    assert embedder.queries == []
    assert store.scopes == []
    assert generator.calls == []
