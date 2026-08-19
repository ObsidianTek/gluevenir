from __future__ import annotations

import json
from pathlib import Path

from aws_cdk import App, LegacyStackSynthesizer
from aws_cdk.assertions import Match, Template

from infra.assets_stack import GluevenirAssetsStack
from infra.gluevenir_stack import GluevenirStack

ROOT = Path(__file__).resolve().parents[1]


def _template() -> Template:
    app = App(context={"region": "us-east-1"})
    return Template.from_stack(GluevenirStack(app, "TestGluevenir"))


def test_asset_stack_has_only_private_stores_and_no_roles() -> None:
    app = App(context={"region": "us-east-1"})
    template = Template.from_stack(
        GluevenirAssetsStack(
            app,
            "TestAssets",
            synthesizer=LegacyStackSynthesizer(),
        )
    )
    template.resource_count_is("AWS::S3::Bucket", 1)
    template.resource_count_is("AWS::ECR::Repository", 1)
    template.resource_count_is("AWS::IAM::Role", 0)
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "BucketEncryption": Match.any_value(),
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        },
    )
    template.has_resource_properties(
        "AWS::ECR::Repository",
        {
            "ImageScanningConfiguration": {"ScanOnPush": True},
            "ImageTagMutability": "IMMUTABLE",
        },
    )
    assert "KmsKey" not in json.dumps(template.to_json())


def test_stack_has_two_empty_retained_secrets_and_no_secret_values() -> None:
    template = _template()
    template.resource_count_is("AWS::SecretsManager::Secret", 2)
    template.has_resource(
        "AWS::SecretsManager::Secret",
        {
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": Match.not_(
                Match.object_like(
                    {
                        "SecretString": Match.any_value(),
                        "GenerateSecretString": Match.any_value(),
                    }
                )
            ),
        },
    )
    rendered = json.dumps(template.to_json())
    assert "GLUEVENIR_RUNTIME_DATABASE_URL" not in rendered
    assert "GLUEVENIR_SIGNING_PRIVATE_KEY_B64" not in rendered


def test_runtime_role_is_exact_and_has_no_broad_actions() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::IAM::Role",
        {
            "AssumeRolePolicyDocument": {
                "Statement": [
                    Match.object_like(
                        {
                            "Action": "sts:AssumeRole",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                        }
                    )
                ]
            },
            "RoleName": "gluevenir-bio-poc-runtime",
        },
    )
    rendered = json.dumps(template.to_json())
    assert '"Action": "*"' not in rendered
    assert '"Resource": "*"' not in rendered
    for action in (
        "bedrock:ApplyGuardrail",
        "bedrock:InvokeModel",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "secretsmanager:GetSecretValue",
    ):
        assert action in rendered


def test_lambda_is_amd64_bounded_and_uses_secret_arns() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Architectures": ["x86_64"],
            "FunctionName": "gluevenir-bio-poc",
            "MemorySize": 3008,
            "PackageType": "Image",
            "Timeout": 30,
            "Environment": {
                "Variables": Match.object_like(
                    {
                        "GLUEVENIR_COCKROACH_SECRET_ARN": Match.any_value(),
                        "GLUEVENIR_DEPLOYMENT_REVISION": {"Ref": "RuntimeRevision"},
                        "GLUEVENIR_SIGNING_SECRET_ARN": Match.any_value(),
                        "GLUEVENIR_SSL_ROOT_CERT": ("/etc/pki/tls/certs/ca-bundle.crt"),
                    }
                )
            },
        },
    )
    rendered = json.dumps(template.to_json())
    assert "ReservedConcurrentExecutions" not in rendered
    assert "GLUEVENIR_DATABASE" not in rendered


def test_public_url_requires_both_post_2025_permissions() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::Lambda::Url", {"AuthType": "NONE", "InvokeMode": "BUFFERED"}
    )
    template.has_resource_properties(
        "AWS::Lambda::Permission",
        {
            "Action": "lambda:InvokeFunctionUrl",
            "FunctionUrlAuthType": "NONE",
            "Principal": "*",
        },
    )
    template.has_resource_properties(
        "AWS::Lambda::Permission",
        {
            "Action": "lambda:InvokeFunction",
            "InvokedViaFunctionUrl": True,
            "Principal": "*",
        },
    )


def test_lambda_image_pins_the_presidio_english_model() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"presidio-analyzer==2.2.360"' in project
    assert "en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl" in dockerfile
    assert "en_core_web_lg" not in dockerfile


def test_runtime_can_receive_exact_observability_endpoint_and_secret() -> None:
    app = App(context={"region": "us-east-1"})
    template = Template.from_stack(
        GluevenirStack(
            app,
            "ObservedRuntime",
            otlp_traces_endpoint=("https://telemetry.example.test/otlp/v1/traces"),
            otlp_auth_secret_arn=(
                "arn:aws:secretsmanager:us-east-1:111122223333:secret:gluevenir-otlp"
            ),
        )
    )
    rendered = json.dumps(template.to_json())
    assert "GLUEVENIR_OTLP_TRACES_ENDPOINT" in rendered
    assert "https://telemetry.example.test/otlp/v1/traces" in rendered
    assert "GLUEVENIR_OTLP_AUTH_SECRET_ARN" in rendered
    assert "secret:gluevenir-otlp" in rendered
