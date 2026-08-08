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

    # Dashboard auth — a *separate*, read-only credential from api_key.
    # POST /telemetry/login exchanges this for an HttpOnly session cookie;
    # the admin api_key above is never sent to or stored by the dashboard
    # SPA, so a dashboard XSS can't escalate to /admin/* (PR #14 review
    # findings #1/#2).
    dashboard_api_key: str = "dev-dashboard-key-change-me"

    # HMAC key signing dashboard session cookies (see app.auth). Must be a
    # long random value in prod, set via Secrets Manager like api_key.
    session_secret: str = "dev-session-secret-change-me"

    # CORS — origins allowed to call the API from a browser (internal dashboard).
    # Comma-separated in the env var, e.g. "https://dashboard.24defend.com,http://localhost:5173"
    # Default is prod-only on purpose — a deploy that forgets to set this
    # explicitly must NOT silently whitelist localhost. Add localhost via
    # DEFEND_DASHBOARD_CORS_ORIGINS when developing locally instead.
    dashboard_cors_origins: str = "https://dashboard.24defend.com"

    # Bedrock LLM. Native model IDs, no "bedrock/" prefix (that's LiteLLM notation).
    # Available: "zai.glm-4.7" (chosen), "zai.glm-4.7-flash",
    # "zai.glm-5", "us.anthropic.claude-sonnet-4-6".
    bedrock_model_id: str = "zai.glm-4.7"
    bedrock_region: str = "us-east-1"

    # Serper (Google search API)
    serper_api_key: str | None = None

    # Google Safe Browsing API v4
    safe_browsing_api_key: str | None = None

    # Environment
    env: str = "dev"  # "dev" | "prod"

    model_config = {"env_prefix": "DEFEND_"}


settings = Settings()
