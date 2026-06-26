from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    QDRANT_URL: str = Field(default="http://localhost:6333", description="Qdrant vector DB URL")
    OPENCTI_URL: str = Field(default="http://localhost:8080", description="OpenCTI platform URL")
    CORTEX_URL: str = Field(default="http://localhost:9001", description="TheHive Cortex URL")
    OPENAI_API_KEY: str = Field(default="", description="OpenAI API key")
    SLACK_WEBHOOK_URL: str = Field(default="", description="Slack webhook for notifications")
    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="LLM API requests per minute")
    MAX_TOKENS_PER_AGENT: int = Field(default=4096, description="Max tokens per agent call")
    HUMAN_APPROVAL_TIMEOUT_SECONDS: int = Field(default=300, description="Approval timeout")
    LOG_LEVEL: str = Field(default="INFO", description="Logging level")
    HMAC_SECRET: str = Field(default="change-me-in-production", description="HMAC signing secret")

    model_config = {"env_prefix": "", "case_sensitive": True}


settings = Settings()
