from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from gluevenir._local_server import (
    _application_sha256,
    _BedrockTokenProvider,
    _cloud_proxy_handler,
    _database_url,
    _ensure_private_key,
    _local_key_id,
    _local_otlp_batch_sink,
    _read_private_key,
    _read_secret_file,
    _render_index,
    _validated_api_url,
)

ROOT = Path(__file__).resolve().parents[1]


def _credentialed_test_url(sslmode: str) -> str:
    base = "postgresql://gluevenir_runtime" + ":secret@cluster.example:26257/"
    return f"{base}gluevenir?sslmode={sslmode}"


def test_secret_reader_is_bounded_and_never_echoes_value(tmp_path: Path) -> None:
    secret = tmp_path / "token"
    secret.write_text("super-sensitive-demo-token\n", encoding="utf-8")
    assert _read_secret_file(secret, label="test secret") == (
        "super-sensitive-demo-token"
    )

    secret.write_text("super-sensitive-demo-token\nextra", encoding="utf-8")
    with pytest.raises(ValueError, match="test secret file is invalid") as error:
        _read_secret_file(secret, label="test secret")
    assert "super-sensitive" not in str(error.value)


def test_bedrock_token_provider_is_service_scoped_and_redacted() -> None:
    provider = _BedrockTokenProvider("super-sensitive-demo-token")
    token = provider.load_token(signing_name="bedrock")
    assert token is not None and token.token == "super-sensitive-demo-token"
    assert provider.load_token(signing_name="another-service") is None
    assert "super-sensitive" not in repr(provider)


def test_database_modes_preserve_runtime_principal_and_tls_boundary() -> None:
    local = _database_url(
        "postgresql://gluevenir_runtime@cockroach:26257/gluevenir?sslmode=disable",
        mode="local",
    )
    assert local.username == "gluevenir_runtime"
    assert local.query == {"sslmode": "disable"}

    hybrid = _database_url(
        _credentialed_test_url("verify-full"),
        mode="hybrid",
    )
    assert hybrid.query == {
        "sslmode": "verify-full",
        "sslrootcert": "/etc/ssl/certs/ca-certificates.crt",
    }
    assert "secret" not in str(hybrid)

    invalid = (
        "postgresql://root@cockroach:26257/gluevenir?sslmode=disable",
        _credentialed_test_url("require"),
    )
    for value in invalid:
        with pytest.raises(ValueError):
            _database_url(value, mode="hybrid" if "example" in value else "local")


def test_local_signing_key_is_created_once_with_private_permissions(
    tmp_path: Path,
) -> None:
    path = tmp_path / "signing" / "receipt.key"
    _ensure_private_key(path)
    first = path.read_bytes()
    _ensure_private_key(path)

    assert len(first) == 32
    assert path.read_bytes() == first
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert _read_private_key(path).public_key() is not None
    first_key_id = _local_key_id(_read_private_key(path))
    assert first_key_id.startswith("gluevenir-local-")
    assert len(first_key_id) == len("gluevenir-local-") + 16

    second = tmp_path / "signing" / "second.key"
    _ensure_private_key(second)
    assert _local_key_id(_read_private_key(second)) != first_key_id

    path.chmod(0o440)
    with pytest.raises(ValueError, match="permissions"):
        _read_private_key(path)


def test_static_site_rewrites_only_the_api_configuration_marker(
    tmp_path: Path,
) -> None:
    source = (
        '<meta name="gluevenir-api-url" content="https://old.example/v1/demo">'
        '<meta name="gluevenir-observability-mode" content="hosted">'
        "<p>unchanged</p>"
    )
    (tmp_path / "index.html").write_text(source, encoding="utf-8")
    rendered = _render_index(
        tmp_path,
        "http://localhost:8765/v1/demo",
        observability_mode="local",
    ).decode()
    assert 'content="http://localhost:8765/v1/demo"' in rendered
    assert 'name="gluevenir-observability-mode" content="local"' in rendered
    assert rendered.endswith("<p>unchanged</p>")


def test_local_server_has_an_exact_public_static_asset_allowlist() -> None:
    source = (ROOT / "src" / "gluevenir" / "_local_server.py").read_text()

    for path in (
        '"/compliance.html"',
        '"/assets/favicon.svg"',
        '"/assets/gluevenir-mark.svg"',
        '"/assets/social-preview.png"',
    ):
        assert path in source
    assert '"/assets/" +' not in source


def test_api_url_validation_distinguishes_local_and_cloud() -> None:
    assert _validated_api_url(
        "http://localhost:8765/v1/demo",
        cloud=False,
    ).startswith("http://")
    assert _validated_api_url(
        "https://api.example/v1/demo",
        cloud=True,
    ).startswith("https://")
    for value, cloud in (
        ("http://api.example/v1/demo", True),
        ("https://localhost/v1/demo", True),
        ("http://127.0.0.1:8765/v1/demo", False),
        ("http://localhost:8765/v1/demo?token=no", False),
    ):
        with pytest.raises(ValueError):
            _validated_api_url(value, cloud=cloud)


class _UpstreamResponse:
    status = 200

    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = json.dumps(payload).encode()

    def __enter__(self) -> _UpstreamResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _maximum: int) -> bytes:
        return self._payload


def test_cloud_proxy_uses_hosted_gateway_without_forwarding_browser_origin() -> None:
    requests = []
    payload = {"public_result": {"decision": "ALLOW"}}

    def opener(request, *, timeout):
        requests.append((request, timeout))
        return _UpstreamResponse(payload)

    handler = _cloud_proxy_handler(
        "https://api.example/v1/demo",
        opener=opener,
    )
    body = json.dumps({"synthetic": True})
    response = handler(
        {
            "requestContext": {"http": {"method": "POST"}},
            "rawPath": "/v1/demo",
            "rawQueryString": "",
            "headers": {
                "content-type": "application/json",
                "origin": "http://localhost:8765",
            },
            "body": body,
        },
        None,
    )

    assert response["statusCode"] == 200
    assert json.loads(response["body"]) == payload
    request, timeout = requests[0]
    assert request.full_url == "https://api.example/v1/demo"
    assert request.data == body.encode()
    assert request.get_header("Origin") is None
    assert timeout == 30


def test_application_digest_is_content_binding_without_secret_material() -> None:
    digest = _application_sha256()
    assert len(digest) == 64
    int(digest, 16)
    assert "token" not in json.dumps({"digest": digest})


def test_local_otlp_sink_accepts_only_the_bounded_adapter_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gluevenir._local_server as module

    sentinel = object()
    captured = []
    monkeypatch.setenv(
        "GLUEVENIR_OTLP_TRACES_ENDPOINT",
        "http://collector:4318/v1/traces",
    )
    monkeypatch.delenv("GLUEVENIR_OTLP_AUTH_TOKEN_FILE", raising=False)

    def create(endpoint, **values):
        captured.append((endpoint, values))
        return sentinel

    monkeypatch.setattr(module, "_create_otlp_span_sink", create)
    configured = _local_otlp_batch_sink(lambda sink: ("configured", sink))
    assert configured == ("configured", sentinel)
    assert captured == [
        (
            "http://collector:4318/v1/traces",
            {"bearer_token": None, "allow_insecure_local": True},
        )
    ]
