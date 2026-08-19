"""Private single-agent recall execution behind the Memory Action Gateway."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from gluevenir._detectors import _ContentScanner, _ScanInput, _ScanReason
from gluevenir._gateway import _GatewayAction, _PreparedAction
from gluevenir._memory_store import RecalledMemory, RecallScope
from gluevenir._policy import _Destination
from gluevenir._ports import MemoryOperation

_MAX_QUERY_CHARACTERS = 4_000
_MAX_AUTHORIZED_MEMORY_CHARACTERS = 12_000
_MAX_SCANNED_OUTPUT_CHARACTERS = 2_000


class _Embedder(Protocol):
    def embed(self, text: str) -> tuple[float, ...]: ...


class _MemoryStore(Protocol):
    def recall(self, scope: RecallScope) -> tuple[RecalledMemory, ...]: ...


class _Generator(Protocol):
    def generate(
        self,
        request: str,
        *,
        authorized_memory: str,
        allowed_tool: object | None = None,
    ) -> str: ...


class _AuthorizedMemoryProjector(Protocol):
    """Create model-safe text while retaining explicit source provenance."""

    def project(
        self,
        *,
        action: _GatewayAction,
        records: tuple[RecalledMemory, ...],
    ) -> tuple[_ModelMemory, ...]: ...


@dataclass(frozen=True, slots=True, repr=False)
class _ModelMemory:
    """Exact model context plus the separately bound source record."""

    source_memory_id: UUID
    source_content_sha256: str
    content: str = field(repr=False)
    content_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_memory_id, UUID):
            raise TypeError("source_memory_id must be a UUID")
        for name in ("source_content_sha256", "content_sha256"):
            value = getattr(self, name)
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if type(self.content) is not str or not self.content.strip():
            raise ValueError("model memory content must not be empty")
        if hashlib.sha256(self.content.encode("utf-8")).hexdigest() != (
            self.content_sha256
        ):
            raise ValueError("model memory content does not match its hash")


@dataclass(frozen=True, slots=True, repr=False)
class _RecallPayload:
    request: str = field(repr=False)
    authorized_memory_json: str = field(repr=False)
    model_contents: tuple[str, ...] = field(repr=False)
    source_memory_ids: tuple[UUID, ...]
    source_content_sha256: tuple[str, ...]
    model_content_sha256: tuple[str, ...]
    model_prompt_sha256: str | None


@dataclass(frozen=True, slots=True, repr=False)
class _AgentAnswer:
    """Useful answer plus content bindings; raw text is omitted from repr/logs."""

    text: str = field(repr=False)
    memory_ids: tuple[UUID, ...]
    content_sha256: tuple[str, ...]
    model_invoked: bool = True

    def __post_init__(self) -> None:
        if type(self.model_invoked) is not bool:
            raise TypeError("model_invoked must be a bool")


class _AgentUnavailable(RuntimeError):
    """Sanitized model, storage, or detector failure."""


class _BedrockRecallExecutor:
    """Prepare authorized vector context, then run one bounded Bedrock answer."""

    __slots__ = (
        "_embedder",
        "_generator",
        "_memory_projector",
        "_memory_store",
        "_scanner",
    )

    def __init__(
        self,
        *,
        embedder: _Embedder,
        memory_store: _MemoryStore,
        generator: _Generator,
        scanner: _ContentScanner,
        memory_projector: _AuthorizedMemoryProjector | None = None,
    ) -> None:
        if not isinstance(scanner, _ContentScanner):
            raise TypeError("scanner must be a _ContentScanner")
        self._embedder = embedder
        self._memory_store = memory_store
        self._generator = generator
        self._scanner = scanner
        self._memory_projector = memory_projector

    def prepare(
        self,
        *,
        action: _GatewayAction,
        executable_memory_ids: tuple[UUID, ...],
        expected_content_sha256: tuple[str, ...],
        action_arguments: Mapping[str, object],
    ) -> _PreparedAction:
        """Retrieve only policy-authorized records without invoking the model."""

        query, top_k = _recall_arguments(action, action_arguments)
        try:
            embedding = self._embedder.embed(query)
            records = self._memory_store.recall(
                RecallScope(
                    tenant_id=action.policy.tenant_id,
                    program_id=action.policy.program_id,
                    embedding=embedding,
                    executable_memory_ids=executable_memory_ids,
                    now=action.evaluated_at,
                    top_k=top_k,
                    allowed_rooms=_allowed_rooms(action),
                    purpose=action.policy.purpose,
                    audience=action.policy.audience,
                )
            )
        except Exception:
            raise _AgentUnavailable("authorized recall preparation failed") from None

        authorized = tuple(
            record for record in records if record.memory_id in executable_memory_ids
        )
        if expected_content_sha256:
            expected = dict(
                zip(
                    executable_memory_ids,
                    expected_content_sha256,
                    strict=True,
                )
            )
            authorized = tuple(
                record
                for record in authorized
                if expected.get(record.memory_id) == record.content_sha256
            )
        model_records = tuple(_model_memory(record) for record in authorized)
        if self._memory_projector is not None:
            try:
                model_records = self._memory_projector.project(
                    action=action,
                    records=authorized,
                )
                _validate_projection_bindings(authorized, model_records)
            except Exception:
                raise _AgentUnavailable(
                    "authorized recall preparation failed"
                ) from None
        authorized_memory_json = _authorized_memory_json(model_records)
        payload = _RecallPayload(
            request=query,
            authorized_memory_json=authorized_memory_json,
            model_contents=tuple(record.content for record in model_records),
            source_memory_ids=tuple(
                record.source_memory_id for record in model_records
            ),
            source_content_sha256=tuple(
                record.source_content_sha256 for record in model_records
            ),
            model_content_sha256=tuple(
                record.content_sha256 for record in model_records
            ),
            model_prompt_sha256=(
                None
                if action.policy.destination == _Destination.EXTERNAL
                else _model_prompt_sha256(
                    request=query,
                    authorized_memory_json=authorized_memory_json,
                )
            ),
        )
        return _PreparedAction(
            memory_ids=payload.source_memory_ids,
            content_sha256=payload.source_content_sha256,
            payload=payload,
            model_prompt_sha256=payload.model_prompt_sha256,
        )

    def execute(
        self,
        *,
        action: _GatewayAction,
        prepared: _PreparedAction,
        action_arguments: Mapping[str, object],
    ) -> _AgentAnswer:
        """Use an exact external derivative or generate one internal answer."""

        query, _ = _recall_arguments(action, action_arguments)
        if not isinstance(prepared.payload, _RecallPayload):
            raise _AgentUnavailable("authorized recall execution failed")
        if prepared.payload.request != query:
            raise _AgentUnavailable("authorized recall execution failed")
        if (
            prepared.memory_ids != prepared.payload.source_memory_ids
            or prepared.content_sha256 != prepared.payload.source_content_sha256
            or prepared.model_prompt_sha256 != prepared.payload.model_prompt_sha256
        ):
            raise _AgentUnavailable("authorized recall execution failed")
        try:
            if len(prepared.payload.model_contents) != len(
                prepared.payload.model_content_sha256
            ) or any(
                hashlib.sha256(content.encode("utf-8")).hexdigest() != content_hash
                for content, content_hash in zip(
                    prepared.payload.model_contents,
                    prepared.payload.model_content_sha256,
                    strict=True,
                )
            ):
                raise ValueError
            model_invoked = action.policy.destination != _Destination.EXTERNAL
            if model_invoked:
                if prepared.payload.model_prompt_sha256 is None:
                    raise ValueError
                normalized = self._generate_internal_answer(
                    query=query,
                    authorized_memory_json=(prepared.payload.authorized_memory_json),
                )
            else:
                if (
                    prepared.payload.model_prompt_sha256 is not None
                    or len(prepared.payload.model_contents) != 1
                    or prepared.payload.source_content_sha256
                    != prepared.payload.model_content_sha256
                ):
                    raise ValueError
                (answer,) = prepared.payload.model_contents
                if (
                    not isinstance(answer, str)
                    or not answer.strip()
                    or len(answer) > _MAX_SCANNED_OUTPUT_CHARACTERS
                    or not self._scanner.scan_external_output(
                        _ScanInput(answer)
                    ).is_allowed
                ):
                    raise ValueError
                normalized = answer
        except Exception:
            raise _AgentUnavailable("authorized recall execution failed") from None
        return _AgentAnswer(
            text=normalized,
            memory_ids=prepared.memory_ids,
            content_sha256=prepared.content_sha256,
            model_invoked=model_invoked,
        )

    def _generate_internal_answer(
        self,
        *,
        query: str,
        authorized_memory_json: str,
    ) -> str:
        """Retry one rejected draft without retaining or disclosing its text."""

        for attempt in range(2):
            answer = self._generator.generate(
                query,
                authorized_memory=authorized_memory_json,
            )
            if not isinstance(answer, str) or not answer.strip():
                raise ValueError
            normalized = answer.strip()
            if len(normalized) > _MAX_SCANNED_OUTPUT_CHARACTERS:
                raise ValueError
            scan = self._scanner.scan_internal_output(_ScanInput(normalized))
            if scan.is_allowed:
                return normalized
            if (
                scan.reason_codes != (_ScanReason.INTERNAL_OUTPUT_RESTRICTED_CANDIDATE,)
                or attempt == 1
            ):
                raise ValueError
        raise AssertionError("bounded internal generation loop did not terminate")


def _recall_arguments(
    action: _GatewayAction,
    arguments: Mapping[str, object],
) -> tuple[str, int]:
    if not isinstance(action, _GatewayAction):
        raise TypeError("action must be a _GatewayAction")
    if action.policy.operation != MemoryOperation.RECALL:
        raise ValueError("Bedrock recall executor supports only RECALL")
    if not isinstance(arguments, Mapping) or set(arguments) != {"query", "top_k"}:
        raise ValueError("recall arguments are invalid")
    query = arguments.get("query")
    top_k = arguments.get("top_k")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query is invalid")
    normalized = query.strip()
    if len(normalized) > _MAX_QUERY_CHARACTERS:
        raise ValueError("query is invalid")
    if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 5:
        raise ValueError("top_k is invalid")
    return normalized, top_k


def _allowed_rooms(action: _GatewayAction) -> tuple[str, ...]:
    if action.policy.destination == _Destination.EXTERNAL:
        return ("external-approved",)
    return {
        "internal-clinical": ("clinical-restricted",),
        "internal-research": ("research-confidential",),
        "internal-program-lead": (
            "clinical-restricted",
            "research-confidential",
        ),
    }[action.policy.audience]


def _authorized_memory_json(records: tuple[_ModelMemory, ...]) -> str:
    document = {
        "authorized_memories": [
            {
                "source_memory_id": str(record.source_memory_id),
                "source_content_sha256": record.source_content_sha256,
                "content_sha256": record.content_sha256,
                "content": record.content,
            }
            for record in records
        ]
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(encoded) > _MAX_AUTHORIZED_MEMORY_CHARACTERS:
        raise _AgentUnavailable("authorized recall preparation failed")
    return encoded


def _model_prompt_sha256(*, request: str, authorized_memory_json: str) -> str:
    """Bind the exact dynamic request/context sent through the model adapter."""

    encoded = json.dumps(
        {
            "authorized_memory_json": authorized_memory_json,
            "request": request,
        },
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_projection_bindings(
    authorized: tuple[RecalledMemory, ...],
    projected: tuple[_ModelMemory, ...],
) -> None:
    """Projection text may change; its source provenance may not."""

    if type(projected) is not tuple or len(projected) != len(authorized):
        raise ValueError("authorized memory projection is invalid")
    for source, model_record in zip(authorized, projected, strict=True):
        if type(model_record) is not _ModelMemory:
            raise TypeError("authorized memory projection is invalid")
        if (
            model_record.source_memory_id != source.memory_id
            or model_record.source_content_sha256 != source.content_sha256
        ):
            raise ValueError("authorized memory projection changed source provenance")


def _model_memory(record: RecalledMemory) -> _ModelMemory:
    return _ModelMemory(
        source_memory_id=record.memory_id,
        source_content_sha256=record.content_sha256,
        content=record.content,
        content_sha256=hashlib.sha256(record.content.encode("utf-8")).hexdigest(),
    )
