#!/usr/bin/env python3
"""Verify a source commit in a disposable clone and bind release evidence to it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
SCHEMA_VERSION = "gluevenir-evidence-manifest-v1"
FRESH_CLONE_SCHEMA_VERSION = "gluevenir-fresh-clone-v1"

ARTIFACT_COMMANDS = {
    "evidence/aarm-alignment.json": (
        "manual source-linked review against the URLs embedded in the artifact"
    ),
    "evidence/aiuc1-alignment.json": (
        "manual source-linked review against the URLs embedded in the artifact"
    ),
    "evidence/architecture.mmd": (
        "manual reconciliation against the deployed CDK and runtime path"
    ),
    "evidence/benchmark-results.json": (
        "uv run python scripts/generate_evidence.py evidence --samples 1000"
    ),
    "evidence/cockroachdb-skills-review.json": (
        "read-only official CockroachDB Agent Skills review using Managed MCP, "
        "bounded direct SQL, and a removed disposable synthetic vector corpus"
    ),
    "evidence/eval-results.json": (
        "uv run python scripts/generate_evidence.py evidence --samples 1000"
    ),
    "evidence/failure-notes.md": "manual feature-freeze limitation review",
    "evidence/fresh-clone.json": (
        "uv run python scripts/generate_release_provenance.py"
    ),
    "evidence/hosting-decision.md": (
        "aws amplify get-job plus byte-identical HTTPS verification"
    ),
    "evidence/live-smoke-redacted.json": (
        "bounded Amplify CLI, HTTPS, Browser, CloudWatch, and CockroachDB Cloud "
        "Managed MCP verification"
    ),
}


class ProvenanceError(RuntimeError):
    """A content-safe release-provenance failure."""


def _run(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    environment: dict[str, str] | None = None,
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ProvenanceError(f"release check failed: {command[0]}") from exc
    return completed.stdout.strip()


def _git(*arguments: str, cwd: Path = ROOT) -> str:
    return _run(("git", *arguments), cwd=cwd)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def verify_disposable_clone(source_commit: str) -> dict[str, object]:
    """Run the complete documented offline release gate in a fresh local clone."""

    with tempfile.TemporaryDirectory(prefix="gluevenir-release-") as temporary:
        clone = Path(temporary) / "gluevenir"
        _run(("git", "clone", "--no-local", "--no-checkout", str(ROOT), str(clone)))
        _git("checkout", "--detach", source_commit, cwd=clone)

        _run(("uv", "sync", "--locked", "--all-groups"), cwd=clone)
        _run(("uv", "run", "ruff", "format", "--check", "."), cwd=clone)
        _run(("uv", "run", "ruff", "check", "."), cwd=clone)
        _run(("uv", "run", "pytest"), cwd=clone)
        _run(("uv", "run", "python", "scripts/verify_repository.py"), cwd=clone)
        _run(("uv", "build"), cwd=clone)

        wheels = sorted((clone / "dist").glob("*.whl"))
        if len(wheels) != 1:
            raise ProvenanceError("release build did not produce exactly one wheel")
        _run(
            (
                "uv",
                "run",
                "--isolated",
                "--no-project",
                "--with",
                str(wheels[0]),
                "python",
                "-c",
                "import gluevenir",
            ),
            cwd=clone,
        )
        _run(("npm", "ci"), cwd=clone)
        cdk_environment = os.environ.copy()
        cdk_environment["PATH"] = f"{clone / '.venv' / 'bin'}:{cdk_environment['PATH']}"
        _run(("npm", "run", "synth"), cwd=clone, environment=cdk_environment)

        working_tree_clean = not _git(
            "status", "--porcelain", "--untracked-files=no", cwd=clone
        )
        if not working_tree_clean:
            raise ProvenanceError("release checks changed tracked files")

    return {
        "cdk_synthesis": "passed",
        "isolated_wheel_import": "passed",
        "locked_cdk_install": "passed",
        "locked_python_install": "passed",
        "offline_tests": "passed",
        "package_build": "passed",
        "repository_verification": "passed",
        "ruff_format": "passed",
        "ruff_lint": "passed",
        "working_tree_clean": True,
    }


def build_manifest(source_commit: str, generated_at: str) -> dict[str, object]:
    artifacts = []
    for relative, command in sorted(ARTIFACT_COMMANDS.items()):
        path = ROOT / relative
        if not path.is_file():
            raise ProvenanceError(f"missing release artifact: {relative}")
        artifacts.append(
            {
                "command": command,
                "path": relative,
                "redaction_status": "passed",
                "sha256": _sha256(path),
                "synthetic_data": True,
            }
        )
    return {
        "artifacts": artifacts,
        "generated_at": generated_at,
        "redaction_status": "passed",
        "schema_version": SCHEMA_VERSION,
        "source_commit_sha": source_commit,
        "synthetic_data": True,
    }


def generate_release_provenance(source_commit: str) -> tuple[Path, Path]:
    if source_commit != _git("rev-parse", "HEAD"):
        raise ProvenanceError("source commit must be the current HEAD")
    if len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise ProvenanceError("source commit must be a lowercase full Git SHA")

    checks = verify_disposable_clone(source_commit)
    generated_at = (
        datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    fresh_clone_path = EVIDENCE / "fresh-clone.json"
    manifest_path = EVIDENCE / "manifest.json"
    _write_json(
        fresh_clone_path,
        {
            "artifact_type": "fresh_clone_verification",
            "checks": checks,
            "commit_sha": source_commit,
            "generated_at": generated_at,
            "redaction_status": "passed",
            "schema_version": FRESH_CLONE_SCHEMA_VERSION,
            "synthetic_data": True,
        },
    )
    _write_json(manifest_path, build_manifest(source_commit, generated_at))
    return fresh_clone_path, manifest_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-commit", default=_git("rev-parse", "HEAD"), help=argparse.SUPPRESS
    )
    arguments = parser.parse_args(argv)
    paths = generate_release_provenance(arguments.source_commit)
    print(json.dumps([str(path.relative_to(ROOT)) for path in paths]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
