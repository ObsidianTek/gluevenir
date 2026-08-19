"""Synthesize the Gluevenir Bio AWS deployment."""

from aws_cdk import (
    App,
    CliCredentialsStackSynthesizer,
    Environment,
    LegacyStackSynthesizer,
)

from infra.assets_stack import GluevenirAssetsStack
from infra.gluevenir_stack import GluevenirStack
from infra.observability_stack import GluevenirObservabilityStack


def main() -> None:
    app = App()
    app.node.set_context("@aws-cdk/core:defaultCrossStackReferences", "strong")
    environment = Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region") or "us-east-1",
    )
    assets = GluevenirAssetsStack(
        app,
        "GluevenirAssets",
        description="Private deployment assets for Gluevenir",
        env=environment,
        synthesizer=LegacyStackSynthesizer(),
    )
    observability = GluevenirObservabilityStack(
        app,
        "GluevenirObservability",
        description="Synthetic-only Gluevenir observability plane",
        env=environment,
        synthesizer=CliCredentialsStackSynthesizer(
            file_assets_bucket_name=(
                "gluevenir-cdk-assets-${AWS::AccountId}-${AWS::Region}"
            ),
            image_assets_repository_name="gluevenir-cdk-assets",
        ),
    )
    observability.add_dependency(assets)
    runtime = GluevenirStack(
        app,
        "GluevenirBioPoc",
        description="Gluevenir Bio synthetic hackathon demonstration",
        env=environment,
        synthesizer=CliCredentialsStackSynthesizer(
            file_assets_bucket_name=(
                "gluevenir-cdk-assets-${AWS::AccountId}-${AWS::Region}"
            ),
            image_assets_repository_name="gluevenir-cdk-assets",
        ),
        otlp_traces_endpoint=observability.traces_endpoint,
        otlp_auth_secret_arn=observability.ingest_secret_arn,
    )
    runtime.add_dependency(assets)
    runtime.add_dependency(observability)
    app.synth()


if __name__ == "__main__":
    main()
