"""Build a deterministic, reviewed static-site bundle for Amplify Hosting.

The source directory is intentionally a tiny allowlisted artifact. The builder
changes the empty hosted-observability metadata value and may overlay an exact,
generator-produced compliance page plus OSCAL JSON. The configured API URL and
every other source byte are preserved.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit, urlunsplit

_EXPECTED_FILES = frozenset(
    {
        "assets/favicon.svg",
        "assets/gluevenir-mark.svg",
        "assets/social-preview.png",
        "assets/social-preview.svg",
        "demo-catalog.json",
        "compliance.html",
        "index.html",
    }
)
_OBSERVABILITY_META = re.compile(
    rb'(<meta\s+name="gluevenir-observability-url"\s+content=")([^"]*)(">)'
)
_API_META = re.compile(rb'<meta\s+name="gluevenir-api-url"\s+content="([^"]+)">')
_HOSTNAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_PROHIBITED_NAME_PARTS = frozenset(
    {
        ".env",
        ".git",
        "credentials",
        "id_rsa",
        "private",
        "secret",
        "token",
    }
)
_PROHIBITED_CONTENT = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        rb"\bABSK[A-Za-z0-9_+=/-]{20,}\b",
        rb"\bcckey_[A-Za-z0-9_-]{20,}\b",
        rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b",
        rb"\b(?:postgres|postgresql|cockroachdb)://[^\s<>\"']+",
        rb'"(?:private_key_b64|runtime_database_url|bearer_token)"\s*:',
        rb"[?&](?:access[_-]?token|api[_-]?key|password|secret|token)="
        rb"[^\s<>\"']{1,512}",
    )
)
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_CONTROL_CATALOG_NAME = re.compile(r"catalog-[A-Za-z_][A-Za-z0-9._-]*\.json")
_COMPLIANCE_DISCLAIMER = (
    b"Gluevenir is a synthetic demonstration and is not certified, compliant, "
    b"conformant, assessed, or audit-ready under any referenced framework."
)


class StaticSiteBuildError(ValueError):
    """The source or requested build does not satisfy the release contract."""


def _validated_https_dns_endpoint(
    value: str,
    *,
    label: str,
    allowed_paths: frozenset[str],
):
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        raise StaticSiteBuildError(
            f"{label} must be a reviewed HTTPS DNS endpoint"
        ) from None
    try:
        ipaddress.ip_address(parsed.hostname or "")
    except ValueError:
        is_ip_address = False
    else:
        is_ip_address = True
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in allowed_paths
        or parsed.hostname != parsed.hostname.lower()
        or len(parsed.hostname) > 253
        or is_ip_address
        or not _HOSTNAME.fullmatch(parsed.hostname)
    ):
        raise StaticSiteBuildError(
            f"{label} must be a reviewed HTTPS DNS endpoint with no credentials, "
            "port, unapproved path, query, or fragment"
        )
    return parsed


def _validated_viewer_base(value: str) -> str:
    parsed = _validated_https_dns_endpoint(
        value,
        label="observability URL",
        allowed_paths=frozenset({"", "/"}),
    )
    return urlunsplit(("https", parsed.hostname, "", "", ""))


def _validated_source_files(source: Path) -> dict[str, Path]:
    if not source.is_dir() or source.is_symlink():
        raise StaticSiteBuildError("site source must be a real directory")
    found: dict[str, Path] = {}
    for root, directories, filenames in os.walk(source, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            path = root_path / directory
            if path.is_symlink():
                raise StaticSiteBuildError(f"symlink is not allowed: {path}")
        for filename in filenames:
            path = root_path / filename
            relative = path.relative_to(source).as_posix()
            pure = PurePosixPath(relative)
            if pure.is_absolute() or ".." in pure.parts:
                raise StaticSiteBuildError(f"unsafe site path: {relative}")
            if path.is_symlink():
                raise StaticSiteBuildError(f"symlink is not allowed: {relative}")
            if not path.is_file():
                raise StaticSiteBuildError(
                    f"site entry must be a regular file: {relative}"
                )
            mode = path.stat(follow_symlinks=False).st_mode
            if not stat.S_ISREG(mode):
                raise StaticSiteBuildError(
                    f"site entry must be a regular file: {relative}"
                )
            lowered_parts = {part.lower() for part in pure.parts}
            if lowered_parts & _PROHIBITED_NAME_PARTS:
                raise StaticSiteBuildError(
                    f"secret-like filename is not allowed: {relative}"
                )
            found[relative] = path
    if set(found) != _EXPECTED_FILES:
        unexpected = sorted(set(found) - _EXPECTED_FILES)
        missing = sorted(_EXPECTED_FILES - set(found))
        raise StaticSiteBuildError(
            f"site file allowlist mismatch; unexpected={unexpected}, missing={missing}"
        )
    return found


def _reject_secret_material(relative: str, content: bytes) -> None:
    for pattern in _PROHIBITED_CONTENT:
        if pattern.search(content):
            raise StaticSiteBuildError(
                f"secret-like content is not allowed: {relative}"
            )


def _validated_control_artifacts(directory: Path) -> dict[str, bytes]:
    """Validate the exact release files emitted by the control generator."""

    if not directory.is_dir() or directory.is_symlink():
        raise StaticSiteBuildError("control artifacts must be a real directory")
    files: dict[str, bytes] = {}
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file():
            raise StaticSiteBuildError(
                f"control artifact must be a regular root file: {path.name}"
            )
        name = path.name
        if name not in {"compliance.html", "gluevenir-component-definition.json"}:
            if _CONTROL_CATALOG_NAME.fullmatch(name) is None:
                raise StaticSiteBuildError(f"unexpected control artifact: {name}")
        content = path.read_bytes()
        _reject_secret_material(name, content)
        files[name] = content
    required = {"compliance.html", "gluevenir-component-definition.json"}
    missing = sorted(required - set(files))
    if missing:
        raise StaticSiteBuildError(f"missing control artifacts: {missing}")
    page = files["compliance.html"]
    if page.count(_COMPLIANCE_DISCLAIMER) != 1:
        raise StaticSiteBuildError(
            "generated compliance page must contain one blanket disclaimer"
        )
    if (
        page.count(b"GLUEVENIR_COMPLIANCE_CONTENT_START") != 1
        or page.count(b"GLUEVENIR_COMPLIANCE_CONTENT_END") != 1
    ):
        raise StaticSiteBuildError("generated compliance page markers are invalid")
    documents: dict[str, dict[str, object]] = {}
    for name, content in files.items():
        if not name.endswith(".json"):
            continue
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise StaticSiteBuildError(
                f"invalid JSON control artifact: {name}"
            ) from error
        if not isinstance(document, dict):
            raise StaticSiteBuildError(f"OSCAL artifact must be an object: {name}")
        expected_root = (
            "component-definition" if name.startswith("gluevenir-") else "catalog"
        )
        if set(document) != {"$schema", expected_root}:
            raise StaticSiteBuildError(f"unexpected OSCAL document shape: {name}")
        documents[name] = document
        if name.startswith("catalog-"):
            framework_id = name.removeprefix("catalog-").removesuffix(".json")
            catalog = document["catalog"]
            if not isinstance(catalog, dict):
                raise StaticSiteBuildError(f"catalog root must be an object: {name}")
            controls = catalog.get("controls", [])
            if not isinstance(controls, list) or not all(
                isinstance(control, dict) for control in controls
            ):
                raise StaticSiteBuildError(f"catalog controls are invalid: {name}")
            source_values = [
                [
                    prop.get("value")
                    for prop in control.get("props", [])
                    if prop.get("name") == "source-framework"
                ]
                for control in controls
            ]
            if not controls or any(
                values != [framework_id] for values in source_values
            ):
                raise StaticSiteBuildError(
                    f"catalog filename does not match its framework: {name}"
                )
    component = documents["gluevenir-component-definition.json"]["component-definition"]
    if not isinstance(component, dict):
        raise StaticSiteBuildError("component-definition root must be an object")
    components = component.get("components", [])
    if not isinstance(components, list) or not all(
        isinstance(item, dict) for item in components
    ):
        raise StaticSiteBuildError("component-definition components are invalid")
    source_names = {
        implementation.get("source", "").removeprefix("./")
        for component_item in components
        for implementation in component_item.get("control-implementations", [])
        if isinstance(implementation, dict)
    }
    catalog_names = {name for name in documents if name.startswith("catalog-")}
    if source_names != catalog_names:
        raise StaticSiteBuildError(
            "OSCAL component sources and bundled catalogs must match exactly"
        )
    return files


def _render_index(content: bytes, viewer_base: str) -> bytes:
    api_matches = _API_META.findall(content)
    observability_matches = list(_OBSERVABILITY_META.finditer(content))
    if len(api_matches) != 1:
        raise StaticSiteBuildError("index must contain exactly one configured API URL")
    try:
        api_url = api_matches[0].decode("ascii")
    except UnicodeDecodeError:
        raise StaticSiteBuildError(
            "configured API URL is not a reviewed endpoint"
        ) from None
    _validated_https_dns_endpoint(
        api_url,
        label="configured API URL",
        allowed_paths=frozenset({"/v1/demo"}),
    )
    if len(observability_matches) != 1:
        raise StaticSiteBuildError(
            "index must contain exactly one observability URL placeholder"
        )
    if observability_matches[0].group(2):
        raise StaticSiteBuildError(
            "observability URL placeholder must be empty before the release build"
        )
    for conflict in (
        b"__GLUEVENIR_OBSERVABILITY_URL__",
        b"${GLUEVENIR_OBSERVABILITY_URL}",
        b"{{GLUEVENIR_OBSERVABILITY_URL}}",
    ):
        if conflict in content:
            raise StaticSiteBuildError("conflicting observability placeholder found")
    rendered = _OBSERVABILITY_META.sub(
        lambda match: match.group(1) + viewer_base.encode("ascii") + match.group(3),
        content,
        count=1,
    )
    if _API_META.findall(rendered) != api_matches:
        raise StaticSiteBuildError("configured API URL changed during the build")
    _reject_secret_material("index.html", rendered)
    return rendered


def build_static_site(
    source: Path,
    output_directory: Path,
    archive: Path,
    observability_url: str,
    control_artifacts_directory: Path | None = None,
) -> None:
    """Create an atomic staging directory and deterministic root-level ZIP."""

    for name, path in (
        ("source", source),
        ("output directory", output_directory),
        ("archive", archive),
    ):
        if ".." in path.parts:
            raise StaticSiteBuildError(f"{name} path must not contain traversal")
    if source.is_symlink():
        raise StaticSiteBuildError("site source must not be a symlink")
    source = source.resolve(strict=True)
    output_parent = output_directory.parent.resolve(strict=True)
    archive_parent = archive.parent.resolve(strict=True)
    if output_directory.exists() or archive.exists():
        raise StaticSiteBuildError(
            "output directory and archive must not already exist"
        )
    if output_directory.resolve() == archive.resolve():
        raise StaticSiteBuildError("output directory and archive must be distinct")
    if source == output_parent or source in output_parent.parents:
        raise StaticSiteBuildError(
            "output directory must not be inside the site source"
        )
    if source == archive_parent or source in archive_parent.parents:
        raise StaticSiteBuildError("archive must not be inside the site source")
    viewer_base = _validated_viewer_base(observability_url)
    source_files = _validated_source_files(source)
    control_artifacts = (
        _validated_control_artifacts(control_artifacts_directory)
        if control_artifacts_directory is not None
        else None
    )

    with tempfile.TemporaryDirectory(
        prefix="gluevenir-static-", dir=output_parent
    ) as temp:
        staging = Path(temp) / "staging"
        staging.mkdir(mode=0o755)
        rendered_files: dict[str, bytes] = {}
        for relative, source_file in sorted(source_files.items()):
            content = source_file.read_bytes()
            _reject_secret_material(relative, content)
            if relative == "index.html":
                content = _render_index(content, viewer_base)
            rendered_files[relative] = content
            destination = staging / relative
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            destination.write_bytes(content)
            destination.chmod(0o644)

        if control_artifacts is not None:
            rendered_files["compliance.html"] = control_artifacts["compliance.html"]
            compliance_destination = staging / "compliance.html"
            compliance_destination.write_bytes(control_artifacts["compliance.html"])
            compliance_destination.chmod(0o644)
            for name, content in sorted(control_artifacts.items()):
                if not name.endswith(".json"):
                    continue
                relative = f"controls/{name}"
                rendered_files[relative] = content
                destination = staging / relative
                destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                destination.write_bytes(content)
                destination.chmod(0o644)

        temporary_archive = Path(temp) / "site.zip"
        with zipfile.ZipFile(
            temporary_archive,
            mode="x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as bundle:
            for relative, content in sorted(rendered_files.items()):
                info = zipfile.ZipInfo(relative, date_time=_ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                bundle.writestr(info, content, compresslevel=9)
        shutil.move(staging, output_directory)
        shutil.move(temporary_archive, archive)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("site"))
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--observability-url", required=True)
    parser.add_argument("--control-artifacts-directory", type=Path)
    args = parser.parse_args()
    build_static_site(
        args.source,
        args.output_directory,
        args.archive,
        args.observability_url,
        args.control_artifacts_directory,
    )


if __name__ == "__main__":
    main()
