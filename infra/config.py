"""Environment configuration for 24Defend infrastructure."""

ENVIRONMENTS = {
    "dev": {
        "account": "081856108753",
        "region": "us-east-1",
        "fargate_cpu": 256,
        "fargate_memory": 512,
        "desired_count": 1,
        "bedrock_model_id": "us.anthropic.claude-sonnet-4-6",
    },
    "prod": {
        "account": "PLACEHOLDER",
        "region": "us-east-1",
        "fargate_cpu": 512,
        "fargate_memory": 1024,
        "desired_count": 2,
        "bedrock_model_id": "us.anthropic.claude-sonnet-4-6",
    },
}
