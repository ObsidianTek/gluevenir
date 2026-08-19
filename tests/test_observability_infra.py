from __future__ import annotations

import json
import re
from pathlib import Path

from aws_cdk import App
from aws_cdk.assertions import Match, Template

from infra.observability_stack import GluevenirObservabilityStack

ROOT = Path(__file__).resolve().parents[1]


def _template() -> Template:
    return Template.from_stack(GluevenirObservabilityStack(App(), "Observability"))


def _rendered() -> tuple[dict[str, object], str]:
    rendered = _template().to_json()
    return rendered, json.dumps(rendered, sort_keys=True)


def test_shared_cdk_entry_point_includes_observability_stack() -> None:
    source = (ROOT / "infra" / "app.py").read_text(encoding="utf-8")
    assert "GluevenirObservabilityStack(" in source
    assert '"GluevenirObservability"' in source
    assert '@aws-cdk/core:defaultCrossStackReferences", "strong"' in source


def test_stack_is_one_cost_bounded_ephemeral_plane() -> None:
    template = _template()
    template.resource_count_is("AWS::EC2::NatGateway", 0)
    template.resource_count_is("AWS::EC2::EIP", 0)
    template.resource_count_is("AWS::ECS::Cluster", 1)
    template.resource_count_is("AWS::ECS::Service", 1)
    template.resource_count_is("AWS::ECS::TaskDefinition", 1)
    template.resource_count_is("AWS::ElasticLoadBalancingV2::LoadBalancer", 1)
    template.has_resource_properties(
        "AWS::ECS::Service",
        {
            "DesiredCount": 1,
            "EnableExecuteCommand": False,
            "DeploymentConfiguration": Match.object_like(
                {"MaximumPercent": 100, "MinimumHealthyPercent": 0}
            ),
        },
    )
    template.has_resource_properties(
        "AWS::ECS::TaskDefinition",
        {
            "Cpu": "2048",
            "Memory": "4096",
            "NetworkMode": "awsvpc",
            "RequiresCompatibilities": ["FARGATE"],
        },
    )
    rendered, _ = _rendered()
    task = next(
        resource
        for resource in rendered["Resources"].values()  # type: ignore[index,union-attr]
        if resource["Type"] == "AWS::ECS::TaskDefinition"  # type: ignore[index]
    )
    assert "EphemeralStorage" not in task["Properties"]  # AWS default is 20 GiB


def test_logs_are_short_lived_encrypted_and_deletion_friendly() -> None:
    template = _template()
    template.resource_count_is("AWS::Logs::LogGroup", 5)
    template.has_resource(
        "AWS::Logs::LogGroup",
        {
            "DeletionPolicy": "Delete",
            "UpdateReplacePolicy": "Delete",
            "Properties": {
                "KmsKeyId": Match.any_value(),
                "RetentionInDays": 1,
            },
        },
    )
    template.has_resource_properties("AWS::KMS::Key", {"EnableKeyRotation": True})
    _, rendered = _rendered()
    assert "AllowExactCloudWatchLogsUse" in rendered
    assert "kms:EncryptionContext:aws:logs:arn" in rendered
    assert "log-group:/gluevenir/observability/*" in rendered


def test_metrics_retention_and_trace_memory_have_real_explicit_bounds() -> None:
    _, rendered = _rendered()
    for value in (
        '"GLUEVENIR_RETENTION_TIME", "Value": "24h"',
        '"GLUEVENIR_RETENTION_SIZE", "Value": "1GB"',
        '"GLUEVENIR_TRACE_MAX_LIFETIME_SECONDS", "Value": "86400"',
        '"MEMORY_MAX_TRACES", "Value": "5000"',
        '"SPAN_STORAGE_TYPE", "Value": "memory"',
    ):
        assert value in rendered
    assert rendered.count('"GLUEVENIR_RETENTION_TIME", "Value": "24h"') == 1
    assert rendered.count('"GLUEVENIR_SYNTHETIC_ONLY", "Value": "true"') == 5


def test_only_viewer_port_is_reachable_from_public_load_balancer() -> None:
    rendered, serialized = _rendered()
    task = next(
        resource
        for resource in rendered["Resources"].values()  # type: ignore[index,union-attr]
        if resource["Type"] == "AWS::ECS::TaskDefinition"  # type: ignore[index]
    )
    containers = task["Properties"]["ContainerDefinitions"]
    port_mapped = [
        container
        for container in containers
        if container.get("PortMappings") is not None
    ]
    assert [
        (container["Name"], container["PortMappings"]) for container in port_mapped
    ] == [
        (
            "viewer",
            [
                {
                    "ContainerPort": 8080,
                    "Protocol": "tcp",
                }
            ],
        )
    ]
    for port in (3000, 4317, 4318, 9090, 13133, 16686):
        assert f'"FromPort": {port}' not in serialized
        assert f'"ContainerPort": {port}' not in serialized


def test_public_listener_is_tls_read_only_and_has_no_admin_route() -> None:
    template = _template()
    template.has_resource_properties(
        "AWS::ElasticLoadBalancingV2::Listener",
        {
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "Certificates": [{"CertificateArn": {"Ref": "CertificateArn"}}],
            "DefaultActions": [
                Match.object_like(
                    {
                        "Type": "fixed-response",
                        "FixedResponseConfig": {"StatusCode": "404"},
                    }
                )
            ],
        },
    )
    _, serialized = _rendered()
    listener_rule_count = sum(
        resource["Type"] == "AWS::ElasticLoadBalancingV2::ListenerRule"
        for resource in _rendered()[0]["Resources"].values()  # type: ignore[index,union-attr]
    )
    assert listener_rule_count == 15
    assert (
        serialized.count('"HostHeaderConfig": {"Values": [{"Ref": "PublicHostname"}]}')
        == listener_rule_count
    )
    assert '"HttpRequestMethodConfig": {"Values": ["GET", "HEAD"]}' in serialized
    dashboard_tokens = (
        "9e978d5eafa627ea61946044a80f3a41",
        "9ab2bc2d01e29b2c642e14ccba48b9de",
        "df2d55ae6508a21e8f5f0a083cb455ed",
        "ba2e6408c254887fc6567c71efa533f0",
        "e8827e00c81371176c524f34461e67d8",
    )
    for token in dashboard_tokens:
        assert f"/public-dashboards/{token}" in serialized
        assert f"/api/public/dashboards/{token}" in serialized
        assert f"/api/public/dashboards/{token}/annotations" in serialized
        assert f"/api/public/dashboards/{token}/panels/*/query" in serialized
    assert "/public-dashboards/*" not in serialized
    assert '"/api/public/dashboards/*"' not in serialized
    assert '"/api/public/dashboards/*/annotations"' not in serialized
    assert "/grafana/" not in serialized
    assert "/traces/*" in serialized
    assert "/jaeger/*" in serialized
    for prohibited in ("/admin", "/login", "grafana/api/ds/query", "ANY"):
        assert prohibited not in serialized
    assert '"GLUEVENIR_PUBLIC_VIEW_MODE", "Value": "external_share_read_only"' in (
        serialized
    )
    assert '"GF_AUTH_ANONYMOUS_ENABLED", "Value": "false"' in serialized
    assert '"GF_SERVER_DOMAIN", "Value": {"Ref": "PublicHostname"}' in serialized
    assert (
        '"GF_SERVER_ROOT_URL", "Value": {"Fn::Join": '
        '["", ["https://", {"Ref": "PublicHostname"}, "/"]]}'
    ) in serialized
    assert '"GF_SERVER_SERVE_FROM_SUB_PATH", "Value": "false"' in serialized


def test_each_listener_rule_stays_within_alb_condition_value_quota() -> None:
    rendered, _ = _rendered()
    listener_rules = [
        resource
        for resource in rendered["Resources"].values()  # type: ignore[index,union-attr]
        if resource["Type"] == "AWS::ElasticLoadBalancingV2::ListenerRule"  # type: ignore[index]
    ]

    assert len(listener_rules) == 15
    for rule in listener_rules:
        value_count = sum(
            len(value["Values"])
            for condition in rule["Properties"]["Conditions"]
            for key, value in condition.items()
            if key.endswith("Config")
        )
        assert value_count <= 5


def test_new_annotation_routes_use_reserved_listener_priorities() -> None:
    rendered, _ = _rendered()
    annotation_rules = [
        resource
        for logical_id, resource in rendered["Resources"].items()  # type: ignore[union-attr]
        if resource["Type"] == "AWS::ElasticLoadBalancingV2::ListenerRule"  # type: ignore[index]
        and "PublicGrafanaDashboardAnnotations" in logical_id
    ]
    assert sorted(rule["Properties"]["Priority"] for rule in annotation_rules) == [
        36,
        37,
        38,
    ]


def test_stack_outputs_exact_static_site_viewer_base() -> None:
    rendered, serialized = _rendered()
    output = rendered["Outputs"]["StaticSiteObservabilityBaseUrl"]  # type: ignore[index]
    assert output["Value"] == {  # type: ignore[index]
        "Fn::Join": ["", ["https://", {"Ref": "PublicHostname"}]]
    }
    assert (
        "scripts/build_static_site.py --observability-url"
        in output[  # type: ignore[index]
            "Description"
        ]
    )
    assert "PublicViewsUrl" not in serialized


def test_otlp_is_forwarded_only_to_bearer_authenticating_viewer() -> None:
    _, serialized = _rendered()
    assert '"HttpRequestMethodConfig": {"Values": ["POST"]}' in serialized
    assert "/otlp/v1/traces" in serialized
    assert "/otlp/v1/metrics" not in serialized
    assert "bearer_authenticated_proxy" in serialized
    assert '"ContainerName": "viewer"' in serialized
    assert '"Name": "GLUEVENIR_OTLP_BEARER_TOKEN"' in serialized
    assert '"ValueFrom"' in serialized
    assert '"PasswordLength": 48' in serialized
    assert '"GenerateStringKey": "bearer_token"' in serialized
    assert '"SecretString"' not in serialized


def test_task_role_and_execution_policy_are_least_privilege() -> None:
    rendered, serialized = _rendered()
    assert '"Action": "*"' not in serialized
    assert '"Principal": {"Service": "ecs-tasks.amazonaws.com"}' in serialized
    policies = [
        resource["Properties"]["PolicyDocument"]["Statement"]
        for resource in rendered["Resources"].values()  # type: ignore[index,union-attr]
        if resource["Type"] == "AWS::IAM::Policy"  # type: ignore[index]
    ]
    statements = [statement for policy in policies for statement in policy]
    wildcard_statements = [s for s in statements if s.get("Resource") == "*"]
    assert len(wildcard_statements) == 1
    assert wildcard_statements[0]["Action"] == "ecr:GetAuthorizationToken"
    assert "ssm:" not in serialized
    assert "secretsmanager:GetSecretValue" in serialized
    assert "secretsmanager:DescribeSecret" in serialized


def test_all_task_containers_have_health_checks_and_healthy_dependencies() -> None:
    rendered, serialized = _rendered()
    task = next(
        resource
        for resource in rendered["Resources"].values()  # type: ignore[index,union-attr]
        if resource["Type"] == "AWS::ECS::TaskDefinition"  # type: ignore[index]
    )
    containers = task["Properties"]["ContainerDefinitions"]
    assert len(containers) == 5
    assert all("HealthCheck" in container for container in containers)
    viewer = next(
        container for container in containers if container["Name"] == "viewer"
    )
    assert {item["Condition"] for item in viewer["DependsOn"]} == {"HEALTHY"}
    assert len(viewer["DependsOn"]) == 4
    assert "127.0.0.1:13133" in serialized
    assert "127.0.0.1:9090/-/ready" in serialized
    assert "127.0.0.1:3000/api/health" in serialized
    assert "127.0.0.1:16686/jaeger/" in serialized


def test_images_are_immutable_amd64_assets_and_tls_inputs_have_no_defaults() -> None:
    rendered, serialized = _rendered()
    parameters = rendered["Parameters"]  # type: ignore[index]
    assert not any(name.endswith("ImageUri") for name in parameters)
    assert serialized.count('"Image": {"Fn::Sub": "${AWS::AccountId}.dkr.ecr.') == 5
    source = (ROOT / "infra" / "observability_stack.py").read_text(encoding="utf-8")
    assert "platform=ecr_assets.Platform.LINUX_AMD64" in source
    assert "directory=str(_OBSERVABILITY_ROOT)" in source
    assert 'file=f"aws/{name.lower()}/Dockerfile"' in source
    assert "Default" not in parameters["CertificateArn"]  # type: ignore[index]
    assert "Default" not in parameters["PublicHostname"]  # type: ignore[index]
    assert not re.search(r"(?<!\[0-9\]\{)\b\d{12}\b", serialized)
    assert ".obsidiantek.io" not in serialized


def test_no_sensitive_payload_or_verbose_logging_configuration_is_synthesized() -> None:
    _, rendered = _rendered()
    lowered = rendered.lower()
    for prohibited in (
        "prompt_text",
        "answer_text",
        "memory_content",
        "detector_match",
        "guardrail_body",
        "tenant_id",
        "access_token",
        "private_key",
    ):
        assert prohibited not in lowered
    assert "method,path,status,duration_ms" in rendered
    assert '"OTEL_LOG_LEVEL", "Value": "error"' in rendered
    assert '"GF_LOG_LEVEL", "Value": "warn"' in rendered
