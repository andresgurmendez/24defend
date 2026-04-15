from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    aws_region: str = "sa-east-1"
    dynamodb_table: str = "24defend-domains"
    dynamodb_endpoint: str | None = None  # set to "http://localhost:8000" for local DynamoDB
    s3_bucket: str = "24defend-bloomfilter"
    bloom_filter_size: int = 100_000  # expected number of entries
    bloom_filter_fp_rate: float = 0.001  # 0.1% false positive rate
    api_key: str = "dev-api-key-change-me"  # simple auth for admin endpoints
    bloom_dir: str = "/app/data/bloom"  # directory for persisted bloom filter files

    model_config = {"env_prefix": "DEFEND_"}


settings = Settings()
