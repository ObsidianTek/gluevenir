from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_repository.py"
ACCOUNT = "908172" + "635449"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_repository_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_cdk_context_is_ignored_and_rejected_if_tracked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "cdk.context.json" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    module = _module()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    context = tmp_path / "cdk.context.json"
    context.write_text(
        f'{{"availability-zones:account={ACCOUNT}:region=us-east-1": []}}',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="forbidden tracked artifact"):
        module.verify_tracked_files([context])


@pytest.mark.parametrize(
    "content",
    (
        f"availability-zones:account={ACCOUNT}:region=us-east-1",
        f'{{"account":"{ACCOUNT}"}}',
        f"arn:aws:iam::{ACCOUNT}:role/generated-role",
        f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/image",
    ),
)
def test_embedded_aws_account_identifiers_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: str,
) -> None:
    module = _module()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    artifact = tmp_path / "generated.txt"
    artifact.write_text(content, encoding="utf-8")

    with pytest.raises(SystemExit, match="AWS account identifier"):
        module.verify_tracked_files([artifact])


def test_synthetic_uuid_identifiers_do_not_trigger_account_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    artifact = tmp_path / "synthetic.txt"
    artifact.write_text(
        "tenant=11111111-1111-4111-8111-111111111111",
        encoding="utf-8",
    )

    module.verify_tracked_files([artifact])


def test_documented_synthetic_aws_account_identifier_is_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _module()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    artifact = tmp_path / "synthetic-arn.txt"
    synthetic_account = "111122" + "223333"
    artifact.write_text(
        f"arn:aws:secretsmanager:us-east-1:{synthetic_account}:secret:synthetic",
        encoding="utf-8",
    )

    module.verify_tracked_files([artifact])
