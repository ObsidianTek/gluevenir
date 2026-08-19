"""Minimal repeatable AWS infrastructure for the synthetic public demo."""

from pathlib import Path

from aws_cdk import (
    Aws,
    CfnOutput,
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

_ROOT = Path(__file__).resolve().parents[1]
_TITAN_MODEL = "amazon.titan-embed-text-v2:0"
_NOVA_MODEL = "amazon.nova-lite-v1:0"


class GluevenirStack(Stack):
    """Deploy one bounded Lambda runtime and its private dependencies."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        otlp_traces_endpoint: str | None = None,
        otlp_auth_secret_arn: str | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        if (otlp_traces_endpoint is None) != (otlp_auth_secret_arn is None):
            raise ValueError("OTLP endpoint and secret ARN must be configured together")

        guardrail_id = CfnParameter(
            self,
            "GuardrailId",
            type="String",
            description="Existing Gluevenir Bedrock Guardrail identifier",
            allowed_pattern=r"[a-z0-9]{1,64}",
        )
        guardrail_version = CfnParameter(
            self,
            "GuardrailVersion",
            type="String",
            default="2",
            allowed_pattern=r"[0-9]{1,8}",
        )
        app_sha256 = CfnParameter(
            self,
            "AppSha256",
            type="String",
            description="SHA-256 of the deployed application source",
            allowed_pattern=r"[0-9a-f]{64}",
        )
        runtime_revision = CfnParameter(
            self,
            "RuntimeRevision",
            type="String",
            default="1",
            description="Non-secret revision incremented after secret rotation",
            allowed_pattern=r"[1-9][0-9]{0,7}",
        )
        generated_origin = CfnParameter(
            self,
            "GeneratedOrigin",
            type="String",
            description="Exact generated Amplify HTTPS origin",
            allowed_pattern=r"https://[a-z0-9.-]+\.amplifyapp\.com",
        )
        branded_origin = CfnParameter(
            self,
            "BrandedOrigin",
            type="String",
            default="https://gluevenir.obsidiantek.io",
            description="Exact branded HTTPS origin",
            allowed_pattern=r"https://[a-z0-9.-]+",
        )

        cockroach_secret = secretsmanager.CfnSecret(
            self,
            "CockroachRuntimeSecret",
            name="gluevenir/poc/cockroach-runtime",
            description="Non-owner CockroachDB runtime URL for Gluevenir Bio",
        )
        signing_secret = secretsmanager.CfnSecret(
            self,
            "ReceiptSigningSecret",
            name="gluevenir/poc/receipt-signing",
            description="Ed25519 receipt-signing key for Gluevenir Bio",
        )
        cockroach_secret.apply_removal_policy(RemovalPolicy.RETAIN)
        signing_secret.apply_removal_policy(RemovalPolicy.RETAIN)

        log_group = logs.LogGroup(
            self,
            "RuntimeLogGroup",
            log_group_name="/aws/lambda/gluevenir-bio-poc",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.RETAIN,
        )
        role = iam.Role(
            self,
            "RuntimeRole",
            role_name="gluevenir-bio-poc-runtime",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Least-privilege runtime role for Gluevenir Bio",
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="WriteOwnLogs",
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"{log_group.log_group_arn}:*"],
            )
        )
        deployment_secret_arns = [cockroach_secret.ref, signing_secret.ref]
        if otlp_auth_secret_arn is not None:
            deployment_secret_arns.append(otlp_auth_secret_arn)
        role.add_to_policy(
            iam.PolicyStatement(
                sid="ReadExactDeploymentSecrets",
                actions=["secretsmanager:GetSecretValue"],
                resources=deployment_secret_arns,
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="InvokeExactFoundationModels",
                actions=["bedrock:InvokeModel"],
                resources=[
                    _foundation_model_arn(_TITAN_MODEL),
                    _foundation_model_arn(_NOVA_MODEL),
                ],
            )
        )
        role.add_to_policy(
            iam.PolicyStatement(
                sid="ApplyExactGuardrail",
                actions=["bedrock:ApplyGuardrail"],
                resources=[
                    (
                        f"arn:{Aws.PARTITION}:bedrock:{Aws.REGION}:"
                        f"{Aws.ACCOUNT_ID}:guardrail/{guardrail_id.value_as_string}"
                    )
                ],
            )
        )

        runtime_environment = {
            "GLUEVENIR_ALLOWED_ORIGINS": (
                f"{generated_origin.value_as_string},{branded_origin.value_as_string}"
            ),
            "GLUEVENIR_APP_SHA256": app_sha256.value_as_string,
            "GLUEVENIR_BEDROCK_GUARDRAIL_ID": guardrail_id.value_as_string,
            "GLUEVENIR_BEDROCK_GUARDRAIL_VERSION": (guardrail_version.value_as_string),
            "GLUEVENIR_COCKROACH_SECRET_ARN": cockroach_secret.ref,
            "GLUEVENIR_DEPLOYMENT_REVISION": runtime_revision.value_as_string,
            "GLUEVENIR_SIGNING_KEY_ID": "gluevenir-bio-agent-dev-01",
            "GLUEVENIR_SIGNING_SECRET_ARN": signing_secret.ref,
            "GLUEVENIR_SSL_ROOT_CERT": "/etc/pki/tls/certs/ca-bundle.crt",
        }
        if otlp_traces_endpoint is not None and otlp_auth_secret_arn is not None:
            runtime_environment.update(
                {
                    "GLUEVENIR_OTLP_TRACES_ENDPOINT": otlp_traces_endpoint,
                    "GLUEVENIR_OTLP_AUTH_SECRET_ARN": otlp_auth_secret_arn,
                }
            )

        function = lambda_.DockerImageFunction(
            self,
            "Runtime",
            function_name="gluevenir-bio-poc",
            description="Gluevenir Bio synthetic demo API",
            architecture=lambda_.Architecture.X86_64,
            code=lambda_.DockerImageCode.from_image_asset(
                str(_ROOT), platform=ecr_assets.Platform.LINUX_AMD64
            ),
            role=role,
            log_group=log_group,
            # Presidio plus the pinned spaCy model must initialize inside the
            # browser's bounded first-request window. Lambda allocates CPU with
            # memory; the verified 1 GiB configuration exhausted the complete
            # 30-second invoke during a cold start. This account's Lambda API
            # accepts at most 3,008 MiB.
            memory_size=3008,
            timeout=Duration.seconds(30),
            environment=runtime_environment,
        )
        function.node.add_dependency(cockroach_secret, signing_secret, log_group)

        function_url = lambda_.CfnUrl(
            self,
            "PublicFunctionUrl",
            auth_type="NONE",
            invoke_mode="BUFFERED",
            target_function_arn=function.function_name,
        )
        lambda_.CfnPermission(
            self,
            "PublicInvokeFunctionUrl",
            action="lambda:InvokeFunctionUrl",
            function_name=function.function_name,
            function_url_auth_type="NONE",
            principal="*",
        ).add_dependency(function_url)
        lambda_.CfnPermission(
            self,
            "PublicInvokeFunctionViaUrl",
            action="lambda:InvokeFunction",
            function_name=function.function_name,
            invoked_via_function_url=True,
            principal="*",
        ).add_dependency(function_url)

        for key, value in {
            "Environment": "poc",
            "ManagedBy": "aws-cdk",
            "Project": "gluevenir",
            "SyntheticOnly": "true",
        }.items():
            Tags.of(self).add(key, value)

        CfnOutput(self, "FunctionUrl", value=function_url.attr_function_url)
        CfnOutput(self, "CockroachSecretArn", value=cockroach_secret.ref)
        CfnOutput(self, "SigningSecretArn", value=signing_secret.ref)


def _foundation_model_arn(model_id: str) -> str:
    return f"arn:{Aws.PARTITION}:bedrock:{Aws.REGION}::foundation-model/{model_id}"
