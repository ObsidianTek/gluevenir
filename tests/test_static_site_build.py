from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from scripts.build_static_site import (
    StaticSiteBuildError,
    _render_index,
    build_static_site,
)
from scripts.generate_control_artifacts import generate_control_artifacts

ROOT = Path(__file__).resolve().parents[1]
VIEWER_BASE = "https://observe.example.test"


def _site_copy(tmp_path: Path) -> Path:
    source = tmp_path / "site"
    shutil.copytree(ROOT / "site", source)
    return source


def _build(tmp_path: Path, source: Path, suffix: str = "one") -> tuple[Path, Path]:
    output = tmp_path / f"staging-{suffix}"
    archive = tmp_path / f"site-{suffix}.zip"
    build_static_site(source, output, archive, VIEWER_BASE)
    return output, archive


def _generated_control_artifacts(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    selection = {
        "schema_version": "1.0",
        "last_modified": "2026-08-17T18:00:00Z",
        "document_version": "test",
        "synthetic_data": True,
        "public_safe": True,
        "component": {
            "title": "Fixture component",
            "type": "software",
            "description": "Fixture component description.",
            "claim_boundary": "Fixture boundary.",
        },
        "frameworks": [
            {
                "id": "fixture-framework",
                "name": "Fixture Framework",
                "version": "test",
                "reference": "https://example.test/framework",
                "controls": [
                    {
                        "id": "F.1",
                        "status": "accepted",
                        "contributions": ["provides_evidence"],
                        "project_interpretation": "Fixture implementation.",
                        "public_interpretation": "Fixture public interpretation.",
                        "evidence": [
                            {
                                "id": "fixture-evidence",
                                "description": "Fixture evidence",
                                "href": "../tests/fixture.py",
                            }
                        ],
                        "limitations": "Fixture boundary only.",
                    }
                ],
            }
        ],
    }
    selection_path = tmp_path / "fixture-selection.json"
    selection_path.write_text(json.dumps(selection), encoding="utf-8")
    output = tmp_path / "control-artifacts"
    generate_control_artifacts(selection_path, output)
    return output


def test_build_changes_only_empty_observability_meta_and_preserves_api(
    tmp_path: Path,
) -> None:
    source = _site_copy(tmp_path)
    original = (source / "index.html").read_bytes()
    output, archive = _build(tmp_path, source)
    rendered = (output / "index.html").read_bytes()

    expected = original.replace(
        b'<meta name="gluevenir-observability-url" content="">',
        b'<meta name="gluevenir-observability-url" '
        b'content="https://observe.example.test">',
    )
    assert rendered == expected
    assert b"sgyya5fpa2lco4rljupgjcpnou0sckgq.lambda-url.us-east-1.on.aws" in rendered
    assert archive.is_file()


def test_archive_is_deterministic_and_has_deployable_files_at_its_root(
    tmp_path: Path,
) -> None:
    source = _site_copy(tmp_path)
    first_output, first = _build(tmp_path, source, "one")
    second_output, second = _build(tmp_path, source, "two")

    assert (
        hashlib.sha256(first.read_bytes()).digest()
        == hashlib.sha256(second.read_bytes()).digest()
    )
    with zipfile.ZipFile(first) as bundle:
        assert bundle.namelist() == [
            "assets/favicon.svg",
            "assets/gluevenir-mark.svg",
            "assets/social-preview.png",
            "assets/social-preview.svg",
            "compliance.html",
            "demo-catalog.json",
            "index.html",
        ]
        assert all(not name.startswith("site/") for name in bundle.namelist())
        assert all(
            item.date_time == (1980, 1, 1, 0, 0, 0) for item in bundle.infolist()
        )
    assert first_output.is_dir()
    assert second_output.is_dir()


@pytest.mark.parametrize(
    "url",
    [
        "http://observe.example.test",
        "https://user@observe.example.test",
        "https://observe.example.test:443",
        "https://observe.example.test/admin",
        "https://observe.example.test?token=value",
        "https://observe.example.test/#fragment",
        "https://127.0.0.1",
        "https://localhost",
    ],
)
def test_build_rejects_non_origin_or_non_hosted_viewer_urls(
    tmp_path: Path, url: str
) -> None:
    source = _site_copy(tmp_path)
    with pytest.raises(StaticSiteBuildError, match="HTTPS DNS endpoint"):
        build_static_site(source, tmp_path / "out", tmp_path / "out.zip", url)


@pytest.mark.parametrize(
    "replacement",
    [
        "http://api.example.test/v1/demo",
        "https://user@api.example.test/v1/demo",
        "https://api.example.test:443/v1/demo",
        "https://api.example.test/v1/admin",
        "https://api.example.test/v1/demo?mode=test",
        "https://api.example.test/v1/demo#fragment",
        "https://127.0.0.1/v1/demo",
        "https://localhost/v1/demo",
    ],
)
def test_build_rejects_unreviewed_api_endpoint_shapes(
    tmp_path: Path, replacement: str
) -> None:
    source = _site_copy(tmp_path)
    index = source / "index.html"
    index.write_bytes(
        index.read_bytes().replace(
            b"https://sgyya5fpa2lco4rljupgjcpnou0sckgq.lambda-url.us-east-1.on.aws/v1/demo",
            replacement.encode("ascii"),
        )
    )
    with pytest.raises(StaticSiteBuildError, match="configured API URL"):
        _build(tmp_path, source)


def test_build_rejects_nonempty_or_conflicting_observability_placeholder(
    tmp_path: Path,
) -> None:
    source = _site_copy(tmp_path)
    index = source / "index.html"
    index.write_bytes(
        index.read_bytes().replace(
            b'<meta name="gluevenir-observability-url" content="">',
            b'<meta name="gluevenir-observability-url" content="https://old.test">',
        )
    )
    with pytest.raises(StaticSiteBuildError, match="must be empty"):
        _build(tmp_path, source)

    source = _site_copy(tmp_path / "second")
    index = source / "index.html"
    index.write_bytes(index.read_bytes() + b"\n__GLUEVENIR_OBSERVABILITY_URL__\n")
    with pytest.raises(StaticSiteBuildError, match="conflicting"):
        _build(tmp_path / "second", source)


def test_rendered_index_is_rescanned_for_secret_like_query_material() -> None:
    content = (
        b'<meta name="gluevenir-api-url" content="https://api.example.test/v1/demo">'
        b'<meta name="gluevenir-observability-url" content="">'
        b'<a href="/help?access_token=do-not-ship">'
    )
    with pytest.raises(StaticSiteBuildError, match="secret-like content"):
        _render_index(content, VIEWER_BASE)


def test_build_rejects_api_change_unexpected_files_symlinks_and_secret_material(
    tmp_path: Path,
) -> None:
    source = _site_copy(tmp_path)
    index = source / "index.html"
    index.write_bytes(
        index.read_bytes().replace(
            b'<meta name="gluevenir-api-url" content="https://',
            b'<meta name="gluevenir-api-url" content="http://',
        )
    )
    with pytest.raises(StaticSiteBuildError, match="API URL"):
        _build(tmp_path, source)

    source = _site_copy(tmp_path / "unexpected")
    (source / "notes.txt").write_text("not reviewed", encoding="utf-8")
    with pytest.raises(StaticSiteBuildError, match="allowlist mismatch"):
        _build(tmp_path / "unexpected", source)

    source = _site_copy(tmp_path / "symlink")
    (source / "assets" / "favicon.svg").unlink()
    (source / "assets" / "favicon.svg").symlink_to("gluevenir-mark.svg")
    with pytest.raises(StaticSiteBuildError, match="symlink"):
        _build(tmp_path / "symlink", source)

    source = _site_copy(tmp_path / "secret")
    catalog = source / "demo-catalog.json"
    catalog.write_bytes(catalog.read_bytes() + b'\n{"bearer_token":"do-not-ship"}')
    with pytest.raises(StaticSiteBuildError, match="secret-like content"):
        _build(tmp_path / "secret", source)

    source = _site_copy(tmp_path / "github-secret")
    catalog = source / "demo-catalog.json"
    catalog.write_bytes(
        catalog.read_bytes() + b"\nghp_" + b"012345678901234567890123456789"
    )
    with pytest.raises(StaticSiteBuildError, match="secret-like content"):
        _build(tmp_path / "github-secret", source)

    source = _site_copy(tmp_path / "query-secret")
    index = source / "index.html"
    index.write_bytes(index.read_bytes() + b'\n<a href="/help?api_key=do-not-ship">')
    with pytest.raises(StaticSiteBuildError, match="secret-like content"):
        _build(tmp_path / "query-secret", source)


def test_build_never_overwrites_existing_artifacts(tmp_path: Path) -> None:
    source = _site_copy(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(StaticSiteBuildError, match="must not already exist"):
        build_static_site(source, output, tmp_path / "out.zip", VIEWER_BASE)


def test_build_includes_exact_generated_compliance_and_oscal_artifacts(
    tmp_path: Path,
) -> None:
    source = _site_copy(tmp_path)
    controls = _generated_control_artifacts(tmp_path)
    output = tmp_path / "generated-staging"
    archive = tmp_path / "generated-site.zip"

    build_static_site(source, output, archive, VIEWER_BASE, controls)

    assert (output / "compliance.html").read_bytes() == (
        controls / "compliance.html"
    ).read_bytes()
    assert sorted(path.name for path in (output / "controls").iterdir()) == [
        "catalog-fixture-framework.json",
        "gluevenir-component-definition.json",
    ]
    with zipfile.ZipFile(archive) as bundle:
        assert "compliance.html" in bundle.namelist()
        assert "controls/catalog-fixture-framework.json" in bundle.namelist()
        assert "controls/gluevenir-component-definition.json" in bundle.namelist()


def test_build_rejects_tampered_or_unexpected_control_artifacts(tmp_path: Path) -> None:
    source = _site_copy(tmp_path)
    controls = _generated_control_artifacts(tmp_path)
    (controls / "notes.txt").write_text("not generated", encoding="utf-8")
    with pytest.raises(StaticSiteBuildError, match="unexpected control artifact"):
        build_static_site(
            source,
            tmp_path / "unexpected-control-out",
            tmp_path / "unexpected-control.zip",
            VIEWER_BASE,
            controls,
        )

    controls = _generated_control_artifacts(tmp_path / "tampered")
    page = controls / "compliance.html"
    page.write_bytes(page.read_bytes().replace(b"synthetic demonstration", b"demo"))
    with pytest.raises(StaticSiteBuildError, match="blanket disclaimer"):
        build_static_site(
            source,
            tmp_path / "tampered-control-out",
            tmp_path / "tampered-control.zip",
            VIEWER_BASE,
            controls,
        )


def test_build_rejects_source_symlink_and_explicit_traversal(tmp_path: Path) -> None:
    source = _site_copy(tmp_path)
    source_link = tmp_path / "site-link"
    source_link.symlink_to(source, target_is_directory=True)
    with pytest.raises(StaticSiteBuildError, match="source must not be a symlink"):
        build_static_site(
            source_link,
            tmp_path / "linked-out",
            tmp_path / "linked.zip",
            VIEWER_BASE,
        )

    with pytest.raises(StaticSiteBuildError, match="traversal"):
        build_static_site(
            source,
            tmp_path / "nested" / ".." / "out",
            tmp_path / "traversal.zip",
            VIEWER_BASE,
        )
