"""Development-only HTTP adapter for the checked-in Gluevenir demo.

The adapter translates local HTTP requests into the same bounded Lambda event
shape used by the hosted runtime. It does not expose a second policy path.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import stat
from collections.abc import Callable, Mapping, Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Protocol
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from botocore.session import Session as BotocoreSession
from botocore.tokens import FrozenAuthToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.pool import NullPool

from gluevenir._database import cockroach_url
from gluevenir._lambda import create_lambda_handler
from gluevenir._otel import _create_otlp_span_sink
from gluevenir._receipts import _ReceiptSigner, _ReceiptVerifier

_MAX_SECRET_BYTES = 8_192
_MAX_REQUEST_BYTES = 1_024
_LOCAL_DATABASE_HOST = "cockroach"
_LOCAL_RUNTIME_PRINCIPAL = "gluevenir_runtime"
_LOCAL_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
_API_META = re.compile(
    r'(<meta name="gluevenir-api-url" content=")[^"]*(">)',
    re.ASCII,
)
_OBSERVABILITY_MODE_META = re.compile(
    r'(<meta name="gluevenir-observability-mode" content=")[^"]*(">)',
    re.ASCII,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class _LambdaHandler(Protocol):
    def __call__(self, event: object, context: object) -> dict[str, object]: ...


class _BedrockTokenProvider:
    """Supply one in-memory Bedrock token without environment credentials."""

    METHOD = "gluevenir-file"

    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        self._token = token

    def load_token(self, **kwargs: object) -> FrozenAuthToken | None:
        if kwargs.get("signing_name") == "bedrock":
            return FrozenAuthToken(self._token)
        return None

    def __repr__(self) -> str:
        return "_BedrockTokenProvider(<redacted>)"


def _read_secret_file(path: Path, *, label: str) -> str:
    """Read one bounded single-line secret without retaining path metadata."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_SECRET_BYTES:
            raise ValueError
        raw = path.read_bytes()
    except (OSError, ValueError):
        raise ValueError(f"{label} file is unavailable") from None
    if not raw or len(raw) > _MAX_SECRET_BYTES:
        raise ValueError(f"{label} file is invalid")
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(f"{label} file is invalid") from None
    value = value.removesuffix("\n")
    if not value or value != value.strip() or _CONTROL.search(value):
        raise ValueError(f"{label} file is invalid")
    return value


def _bedrock_client_from_file(
    token_path: Path,
    *,
    region: str,
    botocore_session_factory: Callable[[], BotocoreSession] = BotocoreSession,
) -> object:
    """Create a bearer-authenticated Bedrock client from a mounted secret."""
    token = _read_secret_file(token_path, label="Bedrock API key")
    session = botocore_session_factory()
    resolver = session.get_component("token_provider")
    resolver.insert_before("env", _BedrockTokenProvider(token))
    import boto3

    return boto3.Session(botocore_session=session).client(
        "bedrock-runtime",
        region_name=_bounded_identifier(region, label="AWS region"),
    )


def _database_url(
    raw_url: str,
    *,
    mode: str,
    database_name: str = "gluevenir",
) -> URL:
    """Enforce the local or Cloud runtime-principal connection boundary."""
    url = cockroach_url(raw_url, database_name=database_name)
    if url.username != _LOCAL_RUNTIME_PRINCIPAL:
        raise ValueError("database URL must use the bounded runtime principal")
    if mode == "local":
        if (
            url.host != _LOCAL_DATABASE_HOST
            or url.port != 26257
            or url.password is not None
            or dict(url.query) != {"sslmode": "disable"}
        ):
            raise ValueError("local database URL must use the Compose database")
        return url
    if mode != "hybrid":
        raise ValueError("database mode is invalid")
    if (
        url.host in {None, "localhost", "127.0.0.1", _LOCAL_DATABASE_HOST}
        or url.password is None
        or url.query.get("sslmode") != "verify-full"
        or "sslrootcert" in url.query
    ):
        raise ValueError("hybrid database URL must require full TLS verification")
    return url.update_query_dict({"sslrootcert": _LOCAL_CA_BUNDLE})


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        metadata = path.lstat()
        raw = path.read_bytes()
    except OSError:
        raise ValueError("local signing key is unavailable") from None
    if not stat.S_ISREG(metadata.st_mode) or len(raw) != 32:
        raise ValueError("local signing key is invalid")
    if metadata.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("local signing key permissions are too broad")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _local_key_id(private_key: Ed25519PrivateKey) -> str:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519 private key")
    public_key = private_key.public_key().public_bytes_raw()
    return f"gluevenir-local-{hashlib.sha256(public_key).hexdigest()[:16]}"


def _ensure_private_key(path: Path, *, owner: tuple[int, int] | None = None) -> None:
    """Create a local development key exactly once; never replace an existing key."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        _read_private_key(path)
        return
    raw = Ed25519PrivateKey.generate().private_bytes_raw()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o400)
    try:
        written = os.write(descriptor, raw)
        if written != len(raw):
            raise OSError("short signing-key write")
        os.fsync(descriptor)
        if owner is not None:
            os.fchown(descriptor, owner[0], owner[1])
        os.fchmod(descriptor, 0o400)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def _application_sha256() -> str:
    package = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(package.glob("*.py")):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _local_lambda_handler(
    *,
    mode: str,
    database_url: str,
    bedrock_token_path: Path,
    signing_key_path: Path,
    region: str,
    guardrail_id: str,
    guardrail_version: str,
    allowed_origins: Sequence[str],
) -> _LambdaHandler:
    """Construct the existing one-agent runtime behind the Lambda boundary."""
    private_key = _read_private_key(signing_key_path)
    public_key = private_key.public_key().public_bytes_raw()
    key_id = _local_key_id(private_key)
    configured_key_id = os.environ.get("GLUEVENIR_SIGNING_KEY_ID")
    if configured_key_id is not None and configured_key_id != key_id:
        raise ValueError("local signing key ID does not match the mounted key")
    signer = _ReceiptSigner(
        agent_id="gluevenir-bio",
        key_id=key_id,
        private_key=private_key,
    )
    verifier = _ReceiptVerifier.from_public_key_bytes(
        agent_id="gluevenir-bio",
        key_id=key_id,
        public_key=public_key,
    )
    engine = create_engine(
        _database_url(database_url, mode=mode),
        poolclass=NullPool,
        hide_parameters=True,
    )
    bedrock_client = _bedrock_client_from_file(
        bedrock_token_path,
        region=region,
    )

    runtime_logger = logging.getLogger("gluevenir._demo_runtime")
    previous_disabled = runtime_logger.disabled
    runtime_logger.disabled = True
    try:
        from gluevenir._demo_runtime import _DemoRuntime, _flushing_batch_sink
    finally:
        runtime_logger.disabled = previous_disabled
    from gluevenir._detectors import _ContentScanner, _DeterministicDetector
    from gluevenir._presidio import (
        _CompositeDetector,
        _create_presidio_analyzer,
        _PresidioDetector,
    )

    runtime = _DemoRuntime(
        engine=engine,
        bedrock_client=bedrock_client,
        signer=signer,
        verifier=verifier,
        key_id=key_id,
        guardrail_id=_bounded_identifier(guardrail_id, label="guardrail ID"),
        guardrail_version=_bounded_identifier(
            guardrail_version,
            label="guardrail version",
        ),
        app_sha256=_application_sha256(),
        scanner=_ContentScanner(
            _CompositeDetector(
                (
                    _DeterministicDetector(),
                    _PresidioDetector(_create_presidio_analyzer()),
                )
            )
        ),
        telemetry_batch_sink=_local_otlp_batch_sink(_flushing_batch_sink),
    )
    return create_lambda_handler(
        recall=runtime,
        input_guard=runtime.guard_input,
        allowed_origins=allowed_origins,
        event_sink=_content_safe_event,
    )


def _local_otlp_batch_sink(flushing_sink_factory: Callable[[object], object]):
    endpoint = os.environ.get("GLUEVENIR_OTLP_TRACES_ENDPOINT")
    token_file = os.environ.get("GLUEVENIR_OTLP_AUTH_TOKEN_FILE")
    if endpoint is None and token_file is None:
        return None
    if endpoint is None:
        logging.getLogger(__name__).warning(
            '{"event":"telemetry_export_health",'
            '"reason_code":"partial_configuration","status":"disabled"}'
        )
        return None
    try:
        bearer_token = (
            _read_secret_file(Path(token_file), label="OTLP bearer token")
            if token_file is not None
            else None
        )
        sink = _create_otlp_span_sink(
            endpoint,
            bearer_token=bearer_token,
            allow_insecure_local=True,
        )
        return flushing_sink_factory(sink)
    except Exception:
        logging.getLogger(__name__).warning(
            '{"event":"telemetry_export_health",'
            '"reason_code":"configuration_failed","status":"disabled"}'
        )
        return None


def _content_safe_event(event: Mapping[str, object]) -> None:
    logging.getLogger(__name__).info(
        "%s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )


def _cloud_proxy_handler(
    upstream_api_url: str,
    *,
    opener: Callable[..., object] = urlopen,
) -> _LambdaHandler:
    """Keep the browser same-origin while calling the existing hosted gateway."""
    upstream = _validated_api_url(upstream_api_url, cloud=True)

    def handler(event: object, _context: object) -> dict[str, object]:
        if not isinstance(event, dict):
            return _proxy_error(400, "invalid_request")
        request_context = event.get("requestContext")
        http = (
            request_context.get("http") if isinstance(request_context, dict) else None
        )
        method = http.get("method") if isinstance(http, dict) else None
        path = event.get("rawPath")
        query = event.get("rawQueryString", "")
        if query != "" or type(method) is not str or type(path) is not str:
            return _proxy_error(400, "invalid_request")
        if method == "GET" and path == "/health":
            return _proxy_response(200, {"status": "ok", "synthetic": True})
        if method == "OPTIONS" and path == "/v1/demo":
            return {
                "statusCode": 204,
                "headers": {"content-type": "application/json"},
                "body": "",
            }
        if method != "POST" or path != "/v1/demo":
            return _proxy_error(
                405 if path in {"/health", "/v1/demo"} else 404,
                "method_not_allowed"
                if path in {"/health", "/v1/demo"}
                else "not_found",
            )
        body = event.get("body")
        headers = event.get("headers")
        if (
            type(body) is not str
            or not isinstance(headers, Mapping)
            or headers.get("content-type", "").casefold()
            not in {
                "application/json",
                "application/json; charset=utf-8",
                'application/json; charset="utf-8"',
            }
        ):
            return _proxy_error(400, "invalid_request")
        try:
            encoded = body.encode("utf-8")
        except UnicodeEncodeError:
            return _proxy_error(400, "invalid_request")
        if not encoded or len(encoded) > _MAX_REQUEST_BYTES:
            too_large = len(encoded) > _MAX_REQUEST_BYTES
            return _proxy_error(
                413 if too_large else 400,
                "request_too_large" if too_large else "invalid_request",
            )
        request = Request(
            upstream,
            data=encoded,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            response = opener(request, timeout=30)
            with response:  # type: ignore[attr-defined]
                status = response.status  # type: ignore[attr-defined]
                raw = response.read(128_001)  # type: ignore[attr-defined]
        except (OSError, URLError):
            return _proxy_error(503, "upstream_unavailable")
        if status != 200 or len(raw) > 128_000:
            return _proxy_error(503, "upstream_unavailable")
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _proxy_error(503, "upstream_unavailable")
        if not isinstance(payload, dict):
            return _proxy_error(503, "upstream_unavailable")
        return _proxy_response(200, payload)

    return handler


def _proxy_response(status: int, payload: Mapping[str, object]) -> dict[str, object]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(payload, sort_keys=True, separators=(",", ":")),
    }


def _proxy_error(status: int, code: str) -> dict[str, object]:
    return _proxy_response(status, {"error": {"code": code}})


def _bounded_identifier(value: str, *, label: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > 256 or _CONTROL.search(normalized):
        raise ValueError(f"{label} is invalid")
    return normalized


def _validated_api_url(value: str, *, cloud: bool) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ValueError("API URL is invalid") from None
    allowed_scheme = "https" if cloud else "http"
    allowed_host = None if cloud else "localhost"
    if (
        parsed.scheme != allowed_scheme
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/demo"
        or (allowed_host is not None and parsed.hostname != allowed_host)
        or (cloud and parsed.hostname in {"localhost", "127.0.0.1"})
    ):
        raise ValueError("API URL is invalid")
    return value


def _render_index(site_dir: Path, api_url: str, *, observability_mode: str) -> bytes:
    if observability_mode not in {"local", "cloud-aligned"}:
        raise ValueError("observability mode is invalid")
    source = (site_dir / "index.html").read_text(encoding="utf-8")
    replacement = rf"\g<1>{html.escape(api_url, quote=True)}\g<2>"
    rendered, count = _API_META.subn(replacement, source, count=1)
    if count != 1:
        raise RuntimeError("site API configuration marker is unavailable")
    mode_replacement = rf"\g<1>{html.escape(observability_mode, quote=True)}\g<2>"
    rendered, count = _OBSERVABILITY_MODE_META.subn(
        mode_replacement,
        rendered,
        count=1,
    )
    if count != 1:
        raise RuntimeError("site observability configuration marker is unavailable")
    return rendered.encode("utf-8")


def _handler_type(
    *,
    lambda_handler: _LambdaHandler,
    site_dir: Path,
    api_url: str,
    observability_mode: str,
) -> type[BaseHTTPRequestHandler]:
    index = _render_index(
        site_dir,
        api_url,
        observability_mode=observability_mode,
    )
    catalog = (site_dir / "demo-catalog.json").read_bytes()
    static_assets = {
        "/compliance.html": (
            (site_dir / "compliance.html").read_bytes(),
            "text/html; charset=utf-8",
        ),
        "/assets/favicon.svg": (
            (site_dir / "assets" / "favicon.svg").read_bytes(),
            "image/svg+xml",
        ),
        "/assets/gluevenir-mark.svg": (
            (site_dir / "assets" / "gluevenir-mark.svg").read_bytes(),
            "image/svg+xml",
        ),
        "/assets/social-preview.png": (
            (site_dir / "assets" / "social-preview.png").read_bytes(),
            "image/png",
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "GluevenirLocal/0.1"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if self.path in {"/", "/index.html"}:
                self._static(index, "text/html; charset=utf-8")
                return
            if self.path == "/demo-catalog.json":
                self._static(catalog, "application/json; charset=utf-8")
                return
            asset = static_assets.get(self.path)
            if asset is not None:
                self._static(*asset)
                return
            self._lambda("GET", path, b"")

        def do_POST(self) -> None:  # noqa: N802
            self._request_with_body("POST")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._request_with_body("OPTIONS")

        def _request_with_body(self, method: str) -> None:
            try:
                length = int(self.headers.get("content-length", "0"))
            except ValueError:
                length = -1
            if length < 0:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            body = self.rfile.read(min(length, _MAX_REQUEST_BYTES + 1))
            self._lambda(method, urlsplit(self.path).path, body)

        def _lambda(self, method: str, path: str, body: bytes) -> None:
            try:
                body_text = body.decode("utf-8")
            except UnicodeDecodeError:
                body_text = "\ud800"
            raw_headers: dict[str, str] = {}
            duplicate = False
            for name in self.headers:
                values = self.headers.get_all(name, failobj=[])
                if len(values) != 1 or name.casefold() in raw_headers:
                    duplicate = True
                    break
                raw_headers[name.casefold()] = values[0]
            event: dict[str, Any] = {
                "body": body_text,
                "headers": {} if duplicate else raw_headers,
                "isBase64Encoded": False,
                "rawPath": path,
                "rawQueryString": urlsplit(self.path).query,
                "requestContext": {"http": {"method": method}},
            }
            response = lambda_handler(event, None)
            status = response.get("statusCode")
            headers = response.get("headers", {})
            payload = response.get("body", "")
            if (
                type(status) is not int
                or not isinstance(headers, Mapping)
                or type(payload) is not str
            ):
                self.send_error(HTTPStatus.SERVICE_UNAVAILABLE)
                return
            encoded = payload.encode("utf-8")
            self.send_response(status)
            for name, value in headers.items():
                if type(name) is str and type(value) is str:
                    self.send_header(name, value)
            self.send_header("content-length", str(len(encoded)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            if method != "OPTIONS":
                self.wfile.write(encoded)

        def _static(self, body: bytes, content_type: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("referrer-policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            return

    return Handler


def _database_url_from_configuration() -> str:
    inline = os.environ.get("GLUEVENIR_DATABASE_URL")
    path = os.environ.get("GLUEVENIR_DATABASE_URL_FILE")
    if bool(inline) == bool(path):
        raise ValueError("exactly one database URL source is required")
    return inline or _read_secret_file(Path(path or ""), label="database URL")


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("local", "hybrid", "cloud-aligned"),
        required=True,
    )
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--site-dir", type=Path, default=Path("site"))
    parser.add_argument("--generate-signing-key", action="store_true")
    parser.add_argument("--upstream-api-url")
    args = parser.parse_args(argv)
    if args.bind not in {"0.0.0.0", "127.0.0.1"} or not 1024 <= args.port <= 65535:
        raise SystemExit("local listener configuration is invalid")
    origins = (
        f"http://localhost:{args.port}",
        f"http://127.0.0.1:{args.port}",
    )
    if args.mode == "cloud-aligned":
        if args.generate_signing_key:
            raise SystemExit("cloud-aligned viewer does not create a signing key")
        api_url = _validated_api_url(args.upstream_api_url or "", cloud=True)
        handler = _cloud_proxy_handler(api_url)
        api_url = _validated_api_url(
            f"http://localhost:{args.port}/v1/demo",
            cloud=False,
        )
    else:
        if args.upstream_api_url is not None:
            raise SystemExit("local runtime cannot configure an upstream API")
        signing_path = Path(
            os.environ.get(
                "GLUEVENIR_SIGNING_KEY_FILE",
                "/run/gluevenir-signing/receipt-ed25519.key",
            )
        )
        if args.generate_signing_key:
            _ensure_private_key(signing_path)
        handler = _local_lambda_handler(
            mode=args.mode,
            database_url=_database_url_from_configuration(),
            bedrock_token_path=Path(
                os.environ.get(
                    "GLUEVENIR_BEDROCK_TOKEN_FILE",
                    "/run/secrets/bedrock_api_key",
                )
            ),
            signing_key_path=signing_path,
            region=os.environ.get("AWS_REGION", "us-east-1"),
            guardrail_id=os.environ.get("GLUEVENIR_BEDROCK_GUARDRAIL_ID", ""),
            guardrail_version=os.environ.get(
                "GLUEVENIR_BEDROCK_GUARDRAIL_VERSION",
                "2",
            ),
            allowed_origins=origins,
        )
        api_url = _validated_api_url(
            f"http://localhost:{args.port}/v1/demo",
            cloud=False,
        )
    server = ThreadingHTTPServer(
        (args.bind, args.port),
        _handler_type(
            lambda_handler=handler,
            site_dir=args.site_dir,
            api_url=api_url,
            observability_mode=(
                "cloud-aligned" if args.mode == "cloud-aligned" else "local"
            ),
        ),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
