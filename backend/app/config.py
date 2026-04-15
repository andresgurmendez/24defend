from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # AWS
    aws_region: str = "us-east-1"
    aws_account_id: str = "487542878969"  # dev account
    aws_profile: str | None = None  # set to use a named profile instead of env vars

    # DynamoDB
    dynamodb_table: str = "24defend-domains"
    dynamodb_endpoint: str | None = None  # "http://localhost:8000" for local

    # S3
    s3_bucket: str = "24defend-bloomfilter"

    # Bloom filters
    bloom_filter_size: int = 100_000
    bloom_filter_fp_rate: float = 0.001
    bloom_dir: str = "/app/data/bloom"

    # Auth
    api_key: str = "dev-api-key-change-me"

    # Bedrock LLM
    bedrock_model_id: str = "us.anthropic.claude-sonnet-4-6"
    bedrock_region: str = "us-east-1"

    # Serper (Google search API)
    serper_api_key: str | None = None

    # Environment
    env: str = "dev"  # "dev" | "prod"

    model_config = {"env_prefix": "DEFEND_"}


settings = Settings()
