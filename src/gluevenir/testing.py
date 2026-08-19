"""Deterministic offline fakes for Gluevenir tests and examples."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ._ports import Detection, MemoryContext, MemoryOperation

__all__ = [
    "FakeClock",
    "FakeDetector",
    "FakeEmbedder",
    "FakeSigner",
    "FakeTextModel",
    "FakeToolAdapter",
    "GatewayCall",
    "RecordingGateway",
    "ToolCall",
]


class FakeClock:
    def __init__(self, current: datetime) -> None:
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("current must be timezone-aware")
        self._current = current.astimezone(UTC)

    def now(self) -> datetime:
        return self._current

    def advance(self, delta: timedelta) -> None:
        if delta.total_seconds() < 0:
            raise ValueError("delta must not move time backwards")
        self._current += delta


class FakeEmbedder:
    """Stable SHA-256-derived vectors; not a semantic embedding model."""

    def __init__(self, *, dimensions: int = 8) -> None:
        if dimensions < 1:
            raise ValueError("dimensions must be positive")
        self.dimensions = dimensions

    def embed(self, text: str) -> tuple[float, ...]:
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        return tuple(
            (digest[index % len(digest)] / 127.5) - 1.0
            for index in range(self.dimensions)
        )


class FakeDetector:
    """Exact-literal detector whose results never contain matched content."""

    def __init__(self, literals: Mapping[str, str]) -> None:
        self._literals = dict(literals)

    def detect(self, text: str) -> tuple[Detection, ...]:
        found: list[Detection] = []
        for label, literal in sorted(self._literals.items()):
            start = text.find(literal)
            while start >= 0:
                found.append(
                    Detection(
                        label=label,
                        start=start,
                        end=start + len(literal),
                        detector="fake-exact",
                    )
                )
                start = text.find(literal, start + 1)
        return tuple(sorted(found, key=lambda item: (item.start, item.end, item.label)))


class FakeTextModel:
    def __init__(self, responses: Mapping[str, str]) -> None:
        self._responses = dict(responses)
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if prompt not in self._responses:
            raise KeyError("no scripted response for prompt")
        return self._responses[prompt]


class FakeSigner:
    """Deterministic HMAC test double; never use as a production signer."""

    def __init__(self, secret: bytes = b"gluevenir-test-only") -> None:
        if not secret:
            raise ValueError("secret must not be empty")
        self._secret = bytes(secret)
        self.key_id = "fake-hmac-sha256"

    def sign(self, payload: bytes) -> bytes:
        return hmac.digest(self._secret, payload, "sha256")

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass(frozen=True, slots=True)
class ToolCall:
    name: str
    arguments: Mapping[str, object]


class FakeToolAdapter:
    def __init__(self, responses: Mapping[str, Mapping[str, object]]) -> None:
        self._responses = {name: dict(value) for name, value in responses.items()}
        self.calls: list[ToolCall] = []

    def invoke(
        self, name: str, arguments: Mapping[str, object]
    ) -> Mapping[str, object]:
        self.calls.append(ToolCall(name=name, arguments=dict(arguments)))
        if name not in self._responses:
            raise KeyError("tool is not allowlisted by this fake")
        return dict(self._responses[name])


@dataclass(frozen=True, slots=True)
class GatewayCall:
    operation: MemoryOperation
    payload: object
    context: MemoryContext


class RecordingGateway[ResultT]:
    """Gateway boundary test double; it contains no policy or decision logic."""

    def __init__(self, result: ResultT) -> None:
        self.result = result
        self.calls: list[GatewayCall] = []

    def execute(
        self,
        *,
        operation: MemoryOperation,
        payload: object,
        context: MemoryContext,
    ) -> ResultT:
        self.calls.append(GatewayCall(operation, payload, context))
        return self.result
