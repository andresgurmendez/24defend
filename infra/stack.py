"""Single-stack CDK infrastructure for 24Defend backend."""

from constructs import Construct
import aws_cdk as cdk
from aws_cdk import (
    Stack,
    RemovalPolicy,
    Duration,
    CfnOutput,
    aws_dynamodb as dynamodb,
    aws_ecr as ecr,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_iam as iam,
    aws_s3 as s3,
    aws_secretsmanager as secretsmanager,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_logs as logs,
    aws_ecr_assets,
)


class DefendStack(Stack):
    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        env_name: str,
        env_config: dict,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        is_prod = env_name == "prod"
        prefix = f"defend-{env_name}"

        # ---------------------------------------------------------------
        # VPC — 2 AZs, public + private subnets
        # ---------------------------------------------------------------
        vpc = ec2.Vpc(
            self,
            "Vpc",
            vpc_name=f"{prefix}-vpc",
            max_azs=2,
            nat_gateways=1,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
            ],
        )

        # ---------------------------------------------------------------
        # DynamoDB table
        # ---------------------------------------------------------------
        table = dynamodb.Table(
            self,
            "DomainsTable",
            table_name="24defend-domains",
            partition_key=dynamodb.Attribute(
                name="domain", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.RETAIN if is_prod else RemovalPolicy.DESTROY,
        )

        # ---------------------------------------------------------------
        # ECR repository
        # ---------------------------------------------------------------
        ecr_repo = ecr.Repository(
            self,
            "EcrRepo",
            repository_name=f"{prefix}-backend",
            removal_policy=RemovalPolicy.RETAIN if is_prod else RemovalPolicy.DESTROY,
            lifecycle_rules=[
                ecr.LifecycleRule(
                    max_image_count=20,
                    description="Keep last 20 images",
                ),
            ],
        )

        # ---------------------------------------------------------------
        # S3 bucket for bloom filters
        # ---------------------------------------------------------------
        bloom_bucket = s3.Bucket(
            self,
            "BloomBucket",
            bucket_name=f"24defend-bloomfilter-{env_name}",
            removal_policy=RemovalPolicy.RETAIN,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        )

        # ---------------------------------------------------------------
        # CloudFront distribution for bloom filter downloads
        # ---------------------------------------------------------------
        distribution = cloudfront.Distribution(
            self,
            "BloomCdn",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(bloom_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
            ),
            comment=f"{prefix} bloom filter CDN",
        )

        # ---------------------------------------------------------------
        # Secrets Manager — API keys
        # ---------------------------------------------------------------
        api_key_secret = secretsmanager.Secret(
            self,
            "ApiKeySecret",
            secret_name=f"{prefix}/api-key",
            description="DEFEND_API_KEY for 24Defend backend",
        )

        serper_secret = secretsmanager.Secret(
            self,
            "SerperSecret",
            secret_name=f"{prefix}/serper-api-key",
            description="DEFEND_SERPER_API_KEY for Google search",
        )

        # ---------------------------------------------------------------
        # ECS cluster
        # ---------------------------------------------------------------
        cluster = ecs.Cluster(
            self,
            "Cluster",
            cluster_name=f"{prefix}-cluster",
            vpc=vpc,
        )

        # ---------------------------------------------------------------
        # Task execution role (ECR pull, logs, secrets)
        # ---------------------------------------------------------------
        # Handled automatically by CDK via ecs_patterns

        # ---------------------------------------------------------------
        # Task role — what the container can do at runtime
        # ---------------------------------------------------------------
        task_role = iam.Role(
            self,
            "TaskRole",
            role_name=f"{prefix}-task-role",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )

        # DynamoDB access
        table.grant_read_write_data(task_role)
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:ListTables", "dynamodb:DescribeTable"],
                resources=["*"],
            )
        )

        # S3 access for bloom filters
        bloom_bucket.grant_read_write(task_role)

        # Bedrock invoke access
        task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeModel",
                    "bedrock:InvokeModelWithResponseStream",
                ],
                resources=["*"],
            )
        )

        # ---------------------------------------------------------------
        # Fargate service behind ALB
        # ---------------------------------------------------------------
        fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            "Service",
            cluster=cluster,
            service_name=f"{prefix}-backend",
            cpu=env_config["fargate_cpu"],
            memory_limit_mib=env_config["fargate_memory"],
            desired_count=env_config["desired_count"],
            public_load_balancer=True,
            assign_public_ip=False,
            task_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
            ),
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_asset("../backend", platform=cdk.aws_ecr_assets.Platform.LINUX_AMD64),
                container_port=8080,
                task_role=task_role,
                environment={
                    "DEFEND_ENV": env_name,
                    "DEFEND_AWS_REGION": env_config["region"],
                    "DEFEND_BEDROCK_REGION": env_config["region"],
                    "DEFEND_BEDROCK_MODEL_ID": env_config["bedrock_model_id"],
                    "DEFEND_DYNAMODB_TABLE": table.table_name,
                    "DEFEND_S3_BUCKET": bloom_bucket.bucket_name,
                },
                secrets={
                    "DEFEND_API_KEY": ecs.Secret.from_secrets_manager(api_key_secret),
                    "DEFEND_SERPER_API_KEY": ecs.Secret.from_secrets_manager(serper_secret),
                },
                log_driver=ecs.LogDrivers.aws_logs(
                    stream_prefix="defend",
                    log_retention=logs.RetentionDays.TWO_WEEKS
                    if not is_prod
                    else logs.RetentionDays.THREE_MONTHS,
                ),
            ),
        )

        # Health check
        fargate_service.target_group.configure_health_check(
            path="/health",
            healthy_http_codes="200",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
        )

        # ---------------------------------------------------------------
        # Outputs
        # ---------------------------------------------------------------
        CfnOutput(self, "AlbUrl", value=f"http://{fargate_service.load_balancer.load_balancer_dns_name}")
        CfnOutput(self, "EcrRepoUri", value=ecr_repo.repository_uri)
        CfnOutput(self, "DynamoTableName", value=table.table_name)
        CfnOutput(self, "BloomBucketName", value=bloom_bucket.bucket_name)
        CfnOutput(self, "CloudFrontDomain", value=distribution.distribution_domain_name)
        CfnOutput(self, "ApiKeySecretArn", value=api_key_secret.secret_arn)
        CfnOutput(self, "SerperSecretArn", value=serper_secret.secret_arn)
