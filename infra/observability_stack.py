"""Bounded AWS observability infrastructure for synthetic demo telemetry.

Only the reverse-proxy/viewer container is reachable through the public load
balancer. Collector, metrics, Grafana, and trace-backend ports remain task-local.
The viewer must authenticate OTLP bearer tokens before proxying bounded spans.
"""

from __future__ import annotations

from pathlib import Path

from aws_cdk import (
    Aws,
    CfnOutput,
    CfnParameter,
    Duration,
    Fn,
    RemovalPolicy,
    Stack,
    Tags,
)
from aws_cdk import aws_certificatemanager as acm
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr_assets as ecr_assets
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_kms as kms
from aws_cdk import aws_logs as logs
from aws_cdk import aws_secretsmanager as secretsmanager
from constructs import Construct

_VIEWER_PORT = 8080
_OBSERVABILITY_ROOT = Path(__file__).resolve().parents[1] / "observability"
_PUBLIC_DASHBOARD_TOKENS = (
    "9e978d5eafa627ea61946044a80f3a41",
    "9ab2bc2d01e29b2c642e14ccba48b9de",
    "df2d55ae6508a21e8f5f0a083cb455ed",
    "ba2e6408c254887fc6567c71efa533f0",
    "e8827e00c81371176c524f34461e67d8",
)


class GluevenirObservabilityStack(Stack):
    """Run one deletion-friendly, synthetic-only observability task."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        public_hostname = CfnParameter(
            self,
            "PublicHostname",
            type="String",
            description="Reviewed DNS hostname for the public synthetic views",
            allowed_pattern=r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?",
        )
        certificate_arn = CfnParameter(
            self,
            "CertificateArn",
            type="String",
            description="Existing ACM certificate for the reviewed public hostname",
            allowed_pattern=(
                r"arn:[a-z0-9-]+:acm:[a-z0-9-]+:[0-9]{12}:certificate/"
                r"[0-9a-f-]{36}"
            ),
        )
        image_assets = {
            name: ecr_assets.DockerImageAsset(
                self,
                f"{name}Image",
                directory=str(_OBSERVABILITY_ROOT),
                file=f"aws/{name.lower()}/Dockerfile",
                platform=ecr_assets.Platform.LINUX_AMD64,
            )
            for name in ("Viewer", "Collector", "Metrics", "Grafana", "Trace")
        }
        ingest_secret = secretsmanager.Secret(
            self,
            "OtlpIngestSecret",
            secret_name="gluevenir/poc/otlp-ingest",
            description="Bearer token for bounded Gluevenir OTLP ingestion",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                secret_string_template='{"schema":"gluevenir.otlp.auth.v1"}',
                generate_string_key="bearer_token",
                exclude_punctuation=True,
                password_length=48,
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )
        self.ingest_secret_arn = ingest_secret.secret_arn
        self.traces_endpoint = (
            f"https://{public_hostname.value_as_string}/otlp/v1/traces"
        )

        vpc = ec2.Vpc(
            self,
            "Vpc",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public-runtime",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                )
            ],
        )
        cluster = ecs.Cluster(
            self,
            "Cluster",
            vpc=vpc,
            container_insights_v2=ecs.ContainerInsights.DISABLED,
            enable_fargate_capacity_providers=False,
        )

        log_key = kms.Key(
            self,
            "LogKey",
            alias="alias/gluevenir-observability-demo-logs",
            description="Synthetic-only Gluevenir observability log encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY,
        )
        log_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowExactCloudWatchLogsUse",
                principals=[
                    iam.ServicePrincipal(f"logs.{Aws.REGION}.{Aws.URL_SUFFIX}")
                ],
                actions=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*",
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": (
                            f"arn:{Aws.PARTITION}:logs:{Aws.REGION}:"
                            f"{Aws.ACCOUNT_ID}:log-group:/gluevenir/observability/*"
                        )
                    }
                },
            )
        )
        log_groups = {
            name: logs.LogGroup(
                self,
                f"{name}LogGroup",
                log_group_name=f"/gluevenir/observability/{name.lower()}",
                encryption_key=log_key,
                retention=logs.RetentionDays.ONE_DAY,
                removal_policy=RemovalPolicy.DESTROY,
            )
            for name in ("Viewer", "Collector", "Metrics", "Grafana", "Trace")
        }

        execution_role = iam.Role(
            self,
            "ExecutionRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
            description="Pull immutable images and write exact observability logs",
        )
        ingest_secret.grant_read(execution_role)

        task = ecs.FargateTaskDefinition(
            self,
            "Task",
            cpu=2048,
            memory_limit_mib=4096,
            execution_role=execution_role,
            family="gluevenir-observability-demo",
        )
        task.node.default_child.cfn_options.metadata = {  # type: ignore[union-attr]
            "DataBoundary": "Synthetic telemetry only; no request or model bodies",
            "NetworkBoundary": (
                "Only viewer port 8080 may receive load-balancer traffic"
            ),
            "StorageBoundary": "Default encrypted 20-GiB ephemeral Fargate storage",
        }

        viewer = self._add_container(
            task,
            "Viewer",
            ecs.ContainerImage.from_docker_image_asset(image_assets["Viewer"]),
            log_groups["Viewer"],
            cpu=256,
            memory=384,
            environment={
                "GLUEVENIR_SYNTHETIC_ONLY": "true",
                "GLUEVENIR_PUBLIC_VIEW_MODE": "external_share_read_only",
                "GLUEVENIR_ADMIN_ROUTES": "disabled",
                "GLUEVENIR_OTLP_INGESTION": "bearer_authenticated_proxy",
                "GLUEVENIR_MAX_REQUEST_BYTES": "65536",
                "GLUEVENIR_ACCESS_LOG_FIELDS": "method,path,status,duration_ms",
            },
            port=_VIEWER_PORT,
            secrets={
                "GLUEVENIR_OTLP_BEARER_TOKEN": ecs.Secret.from_secrets_manager(
                    ingest_secret,
                    "bearer_token",
                )
            },
            health_command=("wget -q -O - http://127.0.0.1:8080/healthz >/dev/null"),
        )
        collector = self._add_container(
            task,
            "Collector",
            ecs.ContainerImage.from_docker_image_asset(image_assets["Collector"]),
            log_groups["Collector"],
            cpu=384,
            memory=640,
            environment={
                "GLUEVENIR_SYNTHETIC_ONLY": "true",
                "GLUEVENIR_TELEMETRY_SCHEMA": "gluevenir.telemetry.span.v1",
                "GLUEVENIR_EXPORT_FAILURE_MODE": "non_authoritative",
                "OTEL_LOG_LEVEL": "error",
            },
            health_command=("wget -q -O - http://127.0.0.1:13133/ >/dev/null"),
        )
        metrics = self._add_container(
            task,
            "Metrics",
            ecs.ContainerImage.from_docker_image_asset(image_assets["Metrics"]),
            log_groups["Metrics"],
            cpu=512,
            memory=768,
            environment={
                "GLUEVENIR_SYNTHETIC_ONLY": "true",
                "GLUEVENIR_RETENTION_TIME": "24h",
                "GLUEVENIR_RETENTION_SIZE": "1GB",
                "GLUEVENIR_QUERY_LOG": "disabled",
            },
            health_command=("wget -q -O - http://127.0.0.1:9090/-/ready >/dev/null"),
        )
        grafana = self._add_container(
            task,
            "Grafana",
            ecs.ContainerImage.from_docker_image_asset(image_assets["Grafana"]),
            log_groups["Grafana"],
            cpu=384,
            memory=768,
            environment={
                "GLUEVENIR_SYNTHETIC_ONLY": "true",
                "GF_AUTH_ANONYMOUS_ENABLED": "false",
                "GF_AUTH_DISABLE_LOGIN_FORM": "true",
                "GF_USERS_ALLOW_SIGN_UP": "false",
                "GF_EXPLORE_ENABLED": "false",
                "GF_ALERTING_ENABLED": "false",
                "GF_UNIFIED_ALERTING_ENABLED": "false",
                "GF_ANALYTICS_REPORTING_ENABLED": "false",
                "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
                "GF_LOG_LEVEL": "warn",
                "GF_SERVER_DOMAIN": public_hostname.value_as_string,
                "GF_SERVER_ROOT_URL": Fn.join(
                    "",
                    ["https://", public_hostname.value_as_string, "/"],
                ),
                "GF_SERVER_SERVE_FROM_SUB_PATH": "false",
            },
            health_command=("wget -q -O - http://127.0.0.1:3000/api/health >/dev/null"),
        )
        trace = self._add_container(
            task,
            "Trace",
            ecs.ContainerImage.from_docker_image_asset(image_assets["Trace"]),
            log_groups["Trace"],
            cpu=384,
            memory=768,
            environment={
                "GLUEVENIR_SYNTHETIC_ONLY": "true",
                "GLUEVENIR_TRACE_MAX_LIFETIME_SECONDS": "86400",
                "MEMORY_MAX_TRACES": "5000",
                "SPAN_STORAGE_TYPE": "memory",
                "COLLECTOR_OTLP_ENABLED": "false",
                "LOG_LEVEL": "error",
            },
            health_command=("wget -q -O - http://127.0.0.1:16686/jaeger/ >/dev/null"),
        )
        viewer.add_container_dependencies(
            *(
                ecs.ContainerDependency(
                    container=container,
                    condition=ecs.ContainerDependencyCondition.HEALTHY,
                )
                for container in (collector, metrics, grafana, trace)
            )
        )

        service_security_group = ec2.SecurityGroup(
            self,
            "ServiceSecurityGroup",
            vpc=vpc,
            description="Only the public load balancer may reach the viewer",
            allow_all_outbound=False,
        )
        load_balancer_security_group = ec2.SecurityGroup(
            self,
            "LoadBalancerSecurityGroup",
            vpc=vpc,
            description="TLS ingress to synthetic read-only views",
            allow_all_outbound=False,
        )
        load_balancer_security_group.add_ingress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Public HTTPS views"
        )
        load_balancer_security_group.add_egress_rule(
            service_security_group,
            ec2.Port.tcp(_VIEWER_PORT),
            "Only the task-local reverse proxy/viewer",
        )
        service_security_group.add_ingress_rule(
            load_balancer_security_group,
            ec2.Port.tcp(_VIEWER_PORT),
            "Only the public load balancer",
        )
        for port in (53,):
            service_security_group.add_egress_rule(
                ec2.Peer.any_ipv4(), ec2.Port.udp(port), "VPC DNS resolution"
            )
            service_security_group.add_egress_rule(
                ec2.Peer.any_ipv4(), ec2.Port.tcp(port), "VPC DNS fallback"
            )
        service_security_group.add_egress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "Pull immutable images"
        )

        service = ecs.FargateService(
            self,
            "Service",
            cluster=cluster,
            task_definition=task,
            desired_count=1,
            assign_public_ip=True,
            security_groups=[service_security_group],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            min_healthy_percent=0,
            max_healthy_percent=100,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            enable_execute_command=False,
        )

        load_balancer = elbv2.ApplicationLoadBalancer(
            self,
            "PublicLoadBalancer",
            vpc=vpc,
            internet_facing=True,
            security_group=load_balancer_security_group,
            deletion_protection=False,
            drop_invalid_header_fields=True,
        )
        certificate = acm.Certificate.from_certificate_arn(
            self, "Certificate", certificate_arn.value_as_string
        )
        listener = load_balancer.add_listener(
            "HttpsListener",
            port=443,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            certificates=[certificate],
            ssl_policy=elbv2.SslPolicy.RECOMMENDED_TLS,
            default_action=elbv2.ListenerAction.fixed_response(
                status_code=404,
                content_type="text/plain",
                message_body="Not found",
            ),
        )
        target_group = elbv2.ApplicationTargetGroup(
            self,
            "ViewerTargetGroup",
            vpc=vpc,
            port=_VIEWER_PORT,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.IP,
            deregistration_delay=Duration.seconds(30),
            health_check=elbv2.HealthCheck(
                enabled=True,
                path="/healthz",
                healthy_http_codes="200",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
            ),
        )
        target_group.add_target(
            service.load_balancer_target(
                container_name=viewer.container_name,
                container_port=_VIEWER_PORT,
            )
        )
        public_dashboard_pages = [
            f"/public-dashboards/{token}" for token in _PUBLIC_DASHBOARD_TOKENS
        ]
        public_dashboard_apis = [
            f"/api/public/dashboards/{token}" for token in _PUBLIC_DASHBOARD_TOKENS
        ]
        public_dashboard_annotations = [
            f"{path}/annotations" for path in public_dashboard_apis
        ]
        public_dashboard_queries = [
            f"{path}/panels/*/query" for path in public_dashboard_apis
        ]

        def add_exact_path_actions(
            construct_prefix: str,
            *,
            first_priority: int,
            methods: tuple[str, ...],
            paths: list[str],
        ) -> int:
            # ALB permits at most five total condition values per rule. One
            # host value plus the method values leaves this many exact paths.
            paths_per_rule = 5 - 1 - len(methods)
            if paths_per_rule < 1:
                raise ValueError("listener method set leaves no exact path capacity")
            chunks = [
                paths[index : index + paths_per_rule]
                for index in range(0, len(paths), paths_per_rule)
            ]
            for offset, path_chunk in enumerate(chunks):
                listener.add_action(
                    f"{construct_prefix}Part{offset + 1}",
                    priority=first_priority + offset,
                    conditions=[
                        elbv2.ListenerCondition.host_headers(
                            [public_hostname.value_as_string]
                        ),
                        elbv2.ListenerCondition.http_request_methods(list(methods)),
                        elbv2.ListenerCondition.path_patterns(path_chunk),
                    ],
                    action=elbv2.ListenerAction.forward([target_group]),
                )
            return first_priority + len(chunks)

        next_priority = add_exact_path_actions(
            "PublicGrafanaDashboardPages",
            first_priority=10,
            methods=("GET", "HEAD"),
            paths=public_dashboard_pages,
        )
        next_priority = add_exact_path_actions(
            "PublicGrafanaDashboardApis",
            first_priority=next_priority,
            methods=("GET", "HEAD"),
            paths=public_dashboard_apis,
        )
        next_priority = add_exact_path_actions(
            "PublicStaticAssetsAndTraces",
            first_priority=next_priority,
            methods=("GET", "HEAD"),
            paths=["/public/*", "/traces", "/traces/*"],
        )
        next_priority = add_exact_path_actions(
            "PublicGrafanaStoredQueries",
            first_priority=next_priority,
            methods=("POST",),
            paths=public_dashboard_queries,
        )
        add_exact_path_actions(
            "AuthenticatedOtlpIngress",
            first_priority=next_priority,
            methods=("POST",),
            paths=["/otlp/v1/traces"],
        )
        # Keep the original rule priorities stable during the live stack
        # update. New exact routes use an unused range so CloudFormation can
        # create them before updating the task without priority collisions.
        add_exact_path_actions(
            "PublicJaegerUi",
            first_priority=33,
            methods=("GET", "HEAD"),
            paths=["/jaeger", "/jaeger/*"],
        )
        add_exact_path_actions(
            "PublicGrafanaDashboardAnnotations",
            first_priority=36,
            methods=("GET", "HEAD"),
            paths=public_dashboard_annotations,
        )

        for key, value in {
            "CostBound": "one-fargate-task-one-alb-no-nat",
            "Environment": "poc",
            "ManagedBy": "aws-cdk",
            "Project": "gluevenir",
            "SyntheticOnly": "true",
        }.items():
            Tags.of(self).add(key, value)

        CfnOutput(
            self,
            "StaticSiteObservabilityBaseUrl",
            value=f"https://{public_hostname.value_as_string}",
            description=(
                "Exact HTTPS origin for scripts/build_static_site.py "
                "--observability-url"
            ),
        )
        CfnOutput(
            self,
            "LoadBalancerDnsName",
            value=load_balancer.load_balancer_dns_name,
        )

    def _add_container(
        self,
        task: ecs.FargateTaskDefinition,
        name: str,
        image: ecs.ContainerImage,
        log_group: logs.ILogGroup,
        *,
        cpu: int,
        memory: int,
        environment: dict[str, str],
        port: int | None = None,
        secrets: dict[str, ecs.Secret] | None = None,
        health_command: str | None = None,
    ) -> ecs.ContainerDefinition:
        container = task.add_container(
            name,
            container_name=name.lower(),
            image=image,
            cpu=cpu,
            memory_reservation_mib=memory,
            essential=True,
            environment=environment,
            secrets=secrets,
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="synthetic-only",
                log_group=log_group,
            ),
            health_check=(
                ecs.HealthCheck(
                    command=["CMD-SHELL", f"{health_command} || exit 1"],
                    interval=Duration.seconds(30),
                    timeout=Duration.seconds(5),
                    retries=3,
                    start_period=Duration.seconds(30),
                )
                if health_command is not None
                else None
            ),
            stop_timeout=Duration.seconds(30),
        )
        if port is not None:
            container.add_port_mappings(
                ecs.PortMapping(container_port=port, protocol=ecs.Protocol.TCP)
            )
        return container
