"""Typed foundation contracts for Gluevenir.

This module is private so storage, model, and tool adapters cannot become public
bypasses around the Memory Action Gateway.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

_MAX_CONTEXT_CHARACTERS = 256
_MAX_RECALL_QUERY_CHARACTERS = 4_000


class MemoryOperation(StrEnum):
    """Memory operations understood by the public SDK boundary."""

    REMEMBER = "REMEMBER"
    RECALL = "RECALL"
    USE = "USE"
    SHARE = "SHARE"
    REVOKE = "REVOKE"
    FORGET = "FORGET"


@dataclass(frozen=True, slots=True)
class MemoryContext:
    """Server-authorized context supplied to a memory operation."""

    tenant_id: str
    program_id: str
    actor_id: str
    actor_role: str
    agent_id: str
    purpose: str
    audience: str

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
            normalized = value.strip()
            if len(normalized) > _MAX_CONTEXT_CHARACTERS:
                raise ValueError(f"{field_name} is too long")
            object.__setattr__(self, field_name, normalized)


@dataclass(frozen=True, slots=True)
class RecallRequest:
    """A bounded semantic-recall request."""

    query: str
    top_k: int = 4

    def __post_init__(self) -> None:
        if not isinstance(self.query, str) or not self.query.strip():
            raise ValueError("query must be a non-empty string")
        normalized = self.query.strip()
        if len(normalized) > _MAX_RECALL_QUERY_CHARACTERS:
            raise ValueError("query is too long")
        object.__setattr__(self, "query", normalized)
        if isinstance(self.top_k, bool) or not isinstance(self.top_k, int):
            raise TypeError("top_k must be an integer")
        if not 1 <= self.top_k <= 5:
            raise ValueError("top_k must be between 1 and 5")


class MemoryActionGateway[GatewayOutputT](Protocol):
    """The single execution boundary used by public framework methods."""

    def execute(
        self,
        *,
        operation: MemoryOperation,
        payload: object,
        context: MemoryContext,
    ) -> GatewayOutputT: ...


@dataclass(frozen=True, slots=True)
class Detection:
    """Content-safe detector output; matched text is intentionally omitted."""

    label: str
    start: int
    end: int
    detector: str


class Clock(Protocol):
    def now(self) -> datetime: ...


class Embedder(Protocol):
    def embed(self, text: str) -> tuple[float, ...]: ...


class Detector(Protocol):
    def detect(self, text: str) -> tuple[Detection, ...]: ...


class TextModel(Protocol):
    def generate(self, prompt: str) -> str: ...


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...

    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class ToolAdapter(Protocol):
    def invoke(
        self, name: str, arguments: Mapping[str, object]
    ) -> Mapping[str, object]: ...
