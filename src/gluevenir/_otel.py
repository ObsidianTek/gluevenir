"""OpenTelemetry bridge for Gluevenir's bounded telemetry envelopes."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Protocol
from urllib.parse import urlsplit

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import set_span_in_context

_SCHEMA = "gluevenir.telemetry.span.v1"
_SERVICE_NAME = "gluevenir-bio"
_LOCAL_HOSTS = frozenset({"127.0.0.1", "::1", "collector", "localhost", "otel"})
_SPAN_NAME = re.compile(r"gluevenir\.[a-z.]{1,48}\Z")
_ATTRIBUTE_KEYS = frozenset(
    {
        "gluevenir.stage",
        "gluevenir.status",
        "gluevenir.duration_ms",
        "gluevenir.persona",
        "gluevenir.operation",
        "gluevenir.decision",
        "gluevenir.reason_code",
        "gluevenir.candidate_count",
        "gluevenir.included_count",
        "gluevenir.excluded_count",
        "gluevenir.model_invoked",
        "gluevenir.receipt_verified",
    }
)


class _TracerLike(Protocol):
    def start_as_current_span(self, name: str): ...

    def start_span(
        self,
        name: str,
        *,
        context: object | None = None,
        start_time: int | None = None,
    ): ...


class _OtelConfigurationError(ValueError):
    """Sanitized configuration failure."""


class _ResultTrackingExporter(SpanExporter):
    """Remember bounded export health that the SDK processor does not expose."""

    __slots__ = ("_delegate", "_failed", "_lock")

    def __init__(self, delegate: SpanExporter) -> None:
        self._delegate = delegate
        self._failed = False
        self._lock = threading.Lock()

    def export(self, spans: Sequence[object]) -> SpanExportResult:
        try:
            result = self._delegate.export(spans)  # type: ignore[arg-type]
        except Exception:
            with self._lock:
                self._failed = True
            raise
        if result is not SpanExportResult.SUCCESS:
            with self._lock:
                self._failed = True
        return result

    def shutdown(self) -> None:
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return bool(self._delegate.force_flush(timeout_millis))

    def consume_success(self) -> bool:
        with self._lock:
            succeeded = not self._failed
            self._failed = False
        return succeeded


class _OtelSpanSink:
    """Translate one already-bounded envelope into a short OpenTelemetry span."""

    __slots__ = ("_exporter", "_provider", "_tracer")

    def __init__(
        self,
        provider: TracerProvider,
        tracer: _TracerLike,
        exporter: _ResultTrackingExporter,
    ) -> None:
        self._provider = provider
        self._tracer = tracer
        self._exporter = exporter

    def __repr__(self) -> str:
        return "_OtelSpanSink(provider=<configured>, tracer=<configured>)"

    def __call__(self, envelope: Mapping[str, object]) -> None:
        name, _offset_ms, attributes = _validated_envelope(envelope)
        end_ns = time.time_ns()
        duration_ns = int(attributes["gluevenir.duration_ms"]) * 1_000_000
        span = self._tracer.start_span(name, start_time=end_ns - duration_ns)
        try:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        finally:
            span.end(end_time=end_ns)

    def emit_batch(self, envelopes: Sequence[Mapping[str, object]]) -> None:
        """Emit one request root and its bounded governance-stage children."""

        if isinstance(envelopes, (str, bytes)) or not isinstance(envelopes, Sequence):
            raise TypeError("telemetry batch is invalid")
        if not 1 <= len(envelopes) <= 16:
            raise ValueError("telemetry batch is invalid")
        validated = tuple(_validated_envelope(envelope) for envelope in envelopes)
        root_name, _root_offset_ms, root_attributes = validated[0]
        if root_name != "gluevenir.request":
            raise ValueError("telemetry batch must begin with request")
        root_end_ns = time.time_ns()
        root_duration_ns = int(root_attributes["gluevenir.duration_ms"]) * 1_000_000
        root_start_ns = root_end_ns - root_duration_ns
        root = self._tracer.start_span(root_name, start_time=root_start_ns)
        try:
            for key, value in root_attributes.items():
                root.set_attribute(key, value)
            root_context = set_span_in_context(root)
            for name, offset_ms, attributes in validated[1:]:
                start_ns = min(
                    root_end_ns,
                    root_start_ns + offset_ms * 1_000_000,
                )
                end_ns = min(
                    root_end_ns,
                    start_ns + int(attributes["gluevenir.duration_ms"]) * 1_000_000,
                )
                span = self._tracer.start_span(
                    name,
                    context=root_context,
                    start_time=start_ns,
                )
                try:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                finally:
                    span.end(end_time=end_ns)
        finally:
            root.end(end_time=root_end_ns)

    def force_flush(self, timeout_millis: int = 1_000) -> bool:
        if type(timeout_millis) is not int or not 1 <= timeout_millis <= 5_000:
            raise ValueError("timeout_millis is invalid")
        provider_succeeded = bool(self._provider.force_flush(timeout_millis))
        export_succeeded = self._exporter.consume_success()
        return provider_succeeded and export_succeeded


def _create_otlp_span_sink(
    endpoint: str,
    *,
    bearer_token: str | None = None,
    allow_insecure_local: bool = False,
    _exporter: SpanExporter | None = None,
    _synchronous: bool = False,
) -> _OtelSpanSink:
    """Create an isolated provider; never mutate OpenTelemetry global state."""

    normalized_endpoint = _validated_endpoint(endpoint, allow_insecure_local)
    headers = None
    if bearer_token is not None:
        if (
            type(bearer_token) is not str
            or not 16 <= len(bearer_token) <= 512
            or any(character.isspace() for character in bearer_token)
        ):
            raise _OtelConfigurationError("OTLP bearer token is invalid")
        headers = {"Authorization": f"Bearer {bearer_token}"}
    delegate = (
        OTLPSpanExporter(
            endpoint=normalized_endpoint,
            headers=headers,
            timeout=2.0,
        )
        if _exporter is None
        else _exporter
    )
    exporter = _ResultTrackingExporter(delegate)
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": _SERVICE_NAME,
                "deployment.environment.name": "synthetic-demo",
                "gluevenir.synthetic_telemetry_only": True,
            }
        )
    )
    if _synchronous:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
    else:
        provider.add_span_processor(
            BatchSpanProcessor(
                exporter,
                max_queue_size=128,
                schedule_delay_millis=500,
                max_export_batch_size=32,
                export_timeout_millis=2_000,
            )
        )
    return _OtelSpanSink(
        provider,
        provider.get_tracer("gluevenir.telemetry", "1"),
        exporter,
    )


def _validated_endpoint(endpoint: object, allow_insecure_local: bool) -> str:
    if type(endpoint) is not str or not endpoint or len(endpoint) > 512:
        raise _OtelConfigurationError("OTLP endpoint is invalid")
    if type(allow_insecure_local) is not bool:
        raise TypeError("allow_insecure_local must be a boolean")
    parsed = urlsplit(endpoint)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
        or parsed.path not in {"/v1/traces", "/otlp/v1/traces"}
    ):
        raise _OtelConfigurationError("OTLP endpoint is invalid")
    if parsed.scheme == "https" and parsed.port in {None, 443}:
        return endpoint
    if (
        allow_insecure_local
        and parsed.scheme == "http"
        and parsed.hostname in _LOCAL_HOSTS
        and parsed.port is not None
    ):
        return endpoint
    raise _OtelConfigurationError("OTLP endpoint must use approved transport")


def _validated_envelope(
    envelope: object,
) -> tuple[str, int, dict[str, str | int | bool]]:
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "schema",
        "name",
        "sequence",
        "start_offset_ms",
        "attributes",
    }:
        raise TypeError("telemetry envelope is invalid")
    name, sequence, start_offset_ms, raw_attributes = (
        envelope["name"],
        envelope["sequence"],
        envelope["start_offset_ms"],
        envelope["attributes"],
    )
    if envelope["schema"] != _SCHEMA or type(name) is not str:
        raise ValueError("telemetry envelope is invalid")
    if _SPAN_NAME.fullmatch(name) is None:
        raise ValueError("telemetry envelope is invalid")
    if type(sequence) is not int or not 0 <= sequence <= 1_000_000_000:
        raise ValueError("telemetry envelope is invalid")
    if type(start_offset_ms) is not int or not 0 <= start_offset_ms <= 120_000:
        raise ValueError("telemetry envelope is invalid")
    if not isinstance(raw_attributes, Mapping) or not set(raw_attributes).issubset(
        _ATTRIBUTE_KEYS
    ):
        raise ValueError("telemetry attributes are invalid")
    attributes: dict[str, str | int | bool] = {"gluevenir.sequence": sequence}
    for key, value in raw_attributes.items():
        if type(key) is not str or type(value) not in {str, int, bool}:
            raise TypeError("telemetry attributes are invalid")
        if type(value) is str and (not value or len(value) > 64):
            raise ValueError("telemetry attributes are invalid")
        attributes[key] = value
    return name, start_offset_ms, attributes
