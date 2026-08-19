"""Verify repository safety and foundation evidence without network access."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    ".dockerignore",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "cdk.json",
    "evidence/claim-boundary.md",
    "evidence/aarm-alignment.json",
    "evidence/aiuc1-alignment.json",
    "evidence/architecture.mmd",
    "evidence/benchmark-results.json",
    "evidence/cockroachdb-skills-review.json",
    "evidence/dependency-manifest.txt",
    "evidence/eligibility.md",
    "evidence/hosting-decision.md",
    "evidence/eval-results.json",
    "evidence/failure-notes.md",
    "evidence/fresh-clone.json",
    "evidence/live-smoke-redacted.json",
    "evidence/manifest.json",
    "evidence/third-party-notices.md",
    "infra/app.py",
    "infra/assets_stack.py",
    "infra/gluevenir_stack.py",
    "package-lock.json",
    "package.json",
    "pyproject.toml",
    "scripts/generate_evidence.py",
    "scripts/generate_release_provenance.py",
    "scripts/build_static_site.py",
    "site/index.html",
    "uv.lock",
}
FORBIDDEN_PARTS = {
    ".private",
    ".env",
    "Personal-Baseline.md",
    "cdk.context.json",
    "secrets.zsh",
}
SECRET_PATTERNS = {
    "private key": re.compile("-----BEGIN " + "(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Bedrock API key": re.compile(r"\bABSK[A-Za-z0-9_+=/-]{20,}\b"),
    "CockroachDB API key": re.compile(r"\bcckey_[A-Za-z0-9_-]{20,}\b"),
    "credentialed database URL": re.compile(r"postgres(?:ql)?://[^:/\s]+:[^@\s]+@"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
}
AWS_ACCOUNT_IDENTIFIER = re.compile(
    r"(?:"
    r"arn:aws(?:-[a-z0-9-]+)?:[^:\s]*:[^:\s]*:([0-9]{12}):"
    r"|\baccount[\"']?\s*[=:]\s*[\"']?([0-9]{12})\b"
    r"|\b([0-9]{12})\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\b"
    r")",
    re.IGNORECASE,
)
SYNTHETIC_AWS_ACCOUNT_IDS = frozenset(
    {
        "111111111111",
        "111122223333",
        "123456789012",
    }
)


def tracked_paths() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item for item in result.stdout.decode().split("\0") if item]


def verify_required_files() -> None:
    missing = sorted(path for path in REQUIRED if not (ROOT / path).is_file())
    if missing:
        raise SystemExit(f"missing required files: {', '.join(missing)}")


def verify_tracked_files(paths: list[Path]) -> None:
    for path in paths:
        relative = path.relative_to(ROOT)
        if FORBIDDEN_PARTS.intersection(relative.parts):
            raise SystemExit(f"forbidden tracked artifact: {relative}")
        if not path.is_file() or path.suffix in {".png", ".zip"}:
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                raise SystemExit(f"possible {label} in {relative}")
        for match in AWS_ACCOUNT_IDENTIFIER.finditer(text):
            account_id = next(group for group in match.groups() if group is not None)
            if account_id not in SYNTHETIC_AWS_ACCOUNT_IDS:
                raise SystemExit(f"possible AWS account identifier in {relative}")


def verify_migrations() -> None:
    migrations = ROOT / "migrations"
    required = {
        ROOT / "alembic.ini",
        migrations / "env.py",
        migrations / "script.py.mako",
    }
    missing = sorted(
        str(path.relative_to(ROOT)) for path in required if not path.is_file()
    )
    if missing:
        raise SystemExit(f"missing Alembic files: {', '.join(missing)}")

    heads = subprocess.run(
        [sys.executable, "-m", "alembic", "heads"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if len(heads) != 1 or not heads[0].endswith("(head)"):
        raise SystemExit("Alembic must have exactly one migration head")

    offline_env = os.environ.copy()
    offline_env["DATABASE_URL"] = (
        "cockroachdb+psycopg://offline@localhost:26257/defaultdb"
    )
    rendered = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=ROOT,
        env=offline_env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.lower()
    required_sql = {
        "create table memory_records",
        "create vector index memory_recall_idx",
        "enable row level security",
        "force row level security",
        "add column purpose_scopes string[]",
        "add column audience_scopes string[]",
        "add column expires_at timestamptz",
        "create table pending_memory_actions",
    }
    missing_sql = sorted(
        fragment for fragment in required_sql if fragment not in rendered
    )
    if missing_sql:
        raise SystemExit(f"offline migration output missing: {', '.join(missing_sql)}")


def verify_dependency_manifest() -> None:
    command = [
        "uv",
        "export",
        "--locked",
        "--all-groups",
        "--no-hashes",
        "--no-annotate",
        "--no-header",
        "--no-emit-project",
    ]
    generated = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    recorded = (ROOT / "evidence/dependency-manifest.txt").read_text()
    if recorded != generated:
        raise SystemExit("dependency manifest drift; regenerate it from uv.lock")


def verify_cdk_lock() -> None:
    package = json.loads((ROOT / "package.json").read_text())
    lock = json.loads((ROOT / "package-lock.json").read_text())
    expected = package.get("devDependencies", {}).get("aws-cdk")
    locked = (
        lock.get("packages", {}).get("", {}).get("devDependencies", {}).get("aws-cdk")
    )
    if not expected or expected != locked:
        raise SystemExit("AWS CDK CLI lock drift")


def verify_evidence() -> None:
    evaluation = json.loads((ROOT / "evidence/eval-results.json").read_text())
    if (
        evaluation.get("artifact_type") != "offline_evaluation"
        or evaluation.get("synthetic_data") is not True
        or any(
            item.get("passed") is not True
            for item in evaluation.get("decision_scenarios", [])
        )
        or any(
            item.get("passed") is not True
            for item in evaluation.get("security_checks", [])
        )
    ):
        raise SystemExit("offline evaluation evidence is incomplete or failed")

    benchmark = json.loads((ROOT / "evidence/benchmark-results.json").read_text())
    if (
        benchmark.get("artifact_type") != "offline_benchmark"
        or benchmark.get("synthetic_data") is not True
        or benchmark.get("model_latency_included") is not False
    ):
        raise SystemExit("offline benchmark evidence is invalid")

    live = json.loads((ROOT / "evidence/live-smoke-redacted.json").read_text())
    decisions = live.get("lambda_demo", {}).get("decisions", [])
    if (
        live.get("artifact_type") != "redacted_live_smoke"
        or live.get("synthetic_data") is not True
        or live.get("redaction_status") != "passed"
        or {item.get("decision") for item in decisions}
        != {"ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER"}
        or any(
            item.get("receipt_decision_matched") is not True
            or item.get("signature_verified") is not True
            for item in decisions
        )
        or live.get("managed_mcp", {}).get("selected_memory_text") is not False
        or live.get("managed_mcp", {}).get("selected_prompt_or_answer") is not False
    ):
        raise SystemExit("redacted live-smoke evidence is incomplete or unsafe")

    skills = json.loads((ROOT / "evidence/cockroachdb-skills-review.json").read_text())
    representative_plan = (
        skills.get("live_checks", {})
        .get("vector_plans", {})
        .get("representative_disposable_corpus", {})
    )
    if (
        skills.get("artifact_type") != "cockroachdb_agent_skills_build_review"
        or skills.get("synthetic_data") is not True
        or skills.get("summary", {}).get("applied_skill_count") != 14
        or len(skills.get("skills", [])) != 14
        or skills.get("claim_boundary", {}).get("runtime_integration") is not False
        or skills.get("claim_boundary", {}).get("sponsor_tool_claim") is not False
        or representative_plan.get("vector_search_operator") is not True
        or representative_plan.get("vector_index_named_in_plan") is not True
        or representative_plan.get("cleaned_up") is not True
    ):
        raise SystemExit("CockroachDB skills review evidence is invalid")

    manifest = json.loads((ROOT / "evidence/manifest.json").read_text())
    if (
        manifest.get("schema_version") != "gluevenir-evidence-manifest-v1"
        or manifest.get("synthetic_data") is not True
        or manifest.get("redaction_status") != "passed"
        or not re.fullmatch(r"[0-9a-f]{40}", manifest.get("source_commit_sha", ""))
    ):
        raise SystemExit("evidence manifest metadata is invalid")
    fresh_clone = json.loads((ROOT / "evidence/fresh-clone.json").read_text())
    source_commit = manifest["source_commit_sha"]
    if fresh_clone.get("commit_sha") != source_commit:
        raise SystemExit("fresh-clone and manifest provenance do not match")
    try:
        changed_since_source = set(
            subprocess.run(
                ["git", "diff", "--name-only", f"{source_commit}..HEAD"],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit("evidence source commit is not available") from exc
    allowed_provenance_changes = {
        ".github/workflows/ci.yml",
        "evidence/benchmark-results.json",
        "evidence/eval-results.json",
        "evidence/fresh-clone.json",
        "evidence/manifest.json",
        "README.md",
        "scripts/generate_release_provenance.py",
        "scripts/verify_repository.py",
        "tests/test_release_provenance.py",
    }
    unexpected_changes = sorted(changed_since_source - allowed_provenance_changes)
    if unexpected_changes:
        raise SystemExit(
            "evidence provenance is stale for source changes: "
            + ", ".join(unexpected_changes)
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 10:
        raise SystemExit("evidence manifest artifact set is invalid")
    for artifact in artifacts:
        relative = artifact.get("path")
        if (
            not isinstance(relative, str)
            or not relative.startswith("evidence/")
            or artifact.get("synthetic_data") is not True
            or artifact.get("redaction_status") != "passed"
            or not artifact.get("command")
        ):
            raise SystemExit("evidence manifest artifact metadata is invalid")
        path = ROOT / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != artifact.get("sha256"):
            raise SystemExit(f"evidence manifest hash mismatch: {relative}")


def main() -> None:
    verify_required_files()
    verify_tracked_files(tracked_paths())
    verify_migrations()
    verify_dependency_manifest()
    verify_cdk_lock()
    verify_evidence()
    print("repository verification passed")


if __name__ == "__main__":
    main()
