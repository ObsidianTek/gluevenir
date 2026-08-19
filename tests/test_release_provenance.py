from __future__ import annotations

import json
from pathlib import Path

import scripts.generate_release_provenance as provenance


def test_manifest_is_sorted_content_bound_and_public_safe(
    tmp_path: Path, monkeypatch
) -> None:
    root = tmp_path / "repo"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    commands = {
        "evidence/alpha.json": "generate alpha",
        "evidence/zulu.md": "review zulu",
    }
    (evidence / "alpha.json").write_text('{"synthetic_data":true}\n')
    (evidence / "zulu.md").write_text("synthetic evidence\n")
    monkeypatch.setattr(provenance, "ROOT", root)
    monkeypatch.setattr(provenance, "ARTIFACT_COMMANDS", commands)

    manifest = provenance.build_manifest("a" * 40, "2026-08-18T12:00:00Z")

    assert manifest["source_commit_sha"] == "a" * 40
    assert manifest["synthetic_data"] is True
    artifacts = manifest["artifacts"]
    assert [item["path"] for item in artifacts] == [
        "evidence/alpha.json",
        "evidence/zulu.md",
    ]
    assert all(len(item["sha256"]) == 64 for item in artifacts)
    assert "synthetic evidence" not in json.dumps(manifest)


def test_fresh_clone_check_names_are_bounded() -> None:
    expected = {
        "cdk_synthesis",
        "isolated_wheel_import",
        "locked_cdk_install",
        "locked_python_install",
        "offline_tests",
        "package_build",
        "repository_verification",
        "ruff_format",
        "ruff_lint",
        "working_tree_clean",
    }
    source = Path(provenance.__file__).read_text()
    assert all(f'"{name}"' in source for name in expected)
