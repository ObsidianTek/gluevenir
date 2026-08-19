"""Private asset stores for CLI-credential CDK deployments."""

from aws_cdk import Aws, Fn, RemovalPolicy, Stack, Tags
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_s3 as s3
from constructs import Construct


class GluevenirAssetsStack(Stack):
    """Create only private S3/ECR staging resources, with no IAM roles."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: object) -> None:
        super().__init__(scope, construct_id, **kwargs)

        bucket = s3.Bucket(
            self,
            "AssetBucket",
            bucket_name=Fn.join(
                "-", ["gluevenir-cdk-assets", Aws.ACCOUNT_ID, Aws.REGION]
            ),
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
        )
        repository = ecr.Repository(
            self,
            "AssetRepository",
            repository_name="gluevenir-cdk-assets",
            encryption=ecr.RepositoryEncryption.AES_256,
            image_scan_on_push=True,
            image_tag_mutability=ecr.TagMutability.IMMUTABLE,
            removal_policy=RemovalPolicy.RETAIN,
        )
        repository.add_lifecycle_rule(max_image_count=50)
        bucket.node.default_child.cfn_options.metadata = {  # type: ignore[union-attr]
            "Purpose": "CDK file assets; no application data"
        }

        for key, value in {
            "Environment": "poc",
            "ManagedBy": "aws-cdk",
            "Project": "gluevenir",
            "SyntheticOnly": "true",
        }.items():
            Tags.of(self).add(key, value)
