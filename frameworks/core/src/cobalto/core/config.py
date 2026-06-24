"""
Configuration management using Pydantic Settings.
Supports environment variables, .env files, and AWS Parameter Store.
"""

import os
from functools import lru_cache
from typing import Optional, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "cobalto"
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    debug: bool = False
    log_level: str = "INFO"
    log_format: str = "json"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_workers: int = 4
    api_timeout: int = 30

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/cobalto",
        validation_alias="DATABASE_URL"
    )
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        validation_alias="REDIS_URL"
    )
    redis_max_connections: int = 50

    # RabbitMQ
    rabbitmq_url: str = Field(
        default="amqp://guest:guest@localhost:5672/",
        validation_alias="RABBITMQ_URL"
    )

    # Elasticsearch/OpenSearch
    opensearch_url: str = Field(
        default="http://localhost:9200",
        validation_alias="OPENSEARCH_URL"
    )
    opensearch_username: Optional[str] = None
    opensearch_password: Optional[str] = None
    opensearch_verify_certs: bool = False

    # Qdrant Vector DB
    qdrant_url: str = Field(
        default="http://localhost:6333",
        validation_alias="QDRANT_URL"
    )
    qdrant_api_key: Optional[str] = None
    qdrant_collection_prefix: str = "cobalto"

    # Wazuh
    wazuh_url: str = Field(
        default="https://localhost:55000",
        validation_alias="WAZUH_URL"
    )
    wazuh_username: str = "wazuh"
    wazuh_password: str = Field(validation_alias="WAZUH_PASSWORD")
    wazuh_verify_ssl: bool = False

    # OpenCTI
    opencti_url: str = Field(
        default="http://localhost:4000/graphql",
        validation_alias="OPENCTI_URL"
    )
    opencti_token: str = Field(validation_alias="OPENCTI_TOKEN")

    # TheHive
    thehive_url: str = Field(
        default="http://localhost:9000/api",
        validation_alias="THEHIVE_URL"
    )
    thehive_token: str = Field(validation_alias="THEHIVE_TOKEN")

    # Cortex
    cortex_url: str = Field(
        default="http://localhost:9001/api",
        validation_alias="CORTEX_URL"
    )
    cortex_token: str = Field(validation_alias="CORTEX_TOKEN")

    # n8n
    n8n_url: str = Field(
        default="http://localhost:5678",
        validation_alias="N8N_URL"
    )
    n8n_api_key: str = Field(validation_alias="N8N_API_KEY")
    n8n_webhook_secret: str = Field(validation_alias="N8N_WEBHOOK_SECRET")

    # LangGraph Agent Service
    langgraph_url: str = Field(
        default="http://localhost:8001",
        validation_alias="LANGGRAPH_URL"
    )
    langgraph_api_key: str = Field(validation_alias="LANGGRAPH_API_KEY")

    # Vault
    vault_url: str = Field(
        default="http://localhost:8200",
        validation_alias="VAULT_URL"
    )
    vault_token: Optional[str] = Field(default=None, validation_alias="VAULT_TOKEN")
    vault_role_id: Optional[str] = Field(default=None, validation_alias="VAULT_ROLE_ID")
    vault_secret_id: Optional[str] = Field(default=None, validation_alias="VAULT_SECRET_ID")
    vault_mount_point: str = "secret"

    # Slack
    slack_bot_token: Optional[str] = Field(default=None, validation_alias="SLACK_BOT_TOKEN")
    slack_signing_secret: Optional[str] = Field(default=None, validation_alias="SLACK_SIGNING_SECRET")
    slack_channel_alerts: str = "#soc-alerts"
    slack_channel_approvals: str = "#soc-approvals"

    # VirusTotal
    virustotal_api_key: Optional[str] = Field(default=None, validation_alias="VIRUSTOTAL_API_KEY")

    # AbuseIPDB
    abuseipdb_api_key: Optional[str] = Field(default=None, validation_alias="ABUSEIPDB_API_KEY")

    # Shodan
    shodan_api_key: Optional[str] = Field(default=None, validation_alias="SHODAN_API_KEY")

    # MaxMind
    maxmind_account_id: Optional[str] = Field(default=None, validation_alias="MAXMIND_ACCOUNT_ID")
    maxmind_license_key: Optional[str] = Field(default=None, validation_alias="MAXMIND_LICENSE_KEY")

    # MITRE ATT&CK
    mitre_attack_url: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    mitre_cache_ttl: int = 86400

    # AWS
    aws_region: str = "us-east-1"
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None

    # EKS
    eks_cluster_name: str = "cobalto-cluster"
    eks_cluster_endpoint: Optional[str] = None
    eks_cluster_ca_data: Optional[str] = None

    # S3
    s3_bucket_logs: str = "cobalto-logs"
    s3_bucket_artifacts: str = "cobalto-artifacts"
    s3_bucket_models: str = "cobalto-models"

    # Monitoring
    prometheus_port: int = 9090
    grafana_url: str = "http://localhost:3000"
    grafana_api_key: Optional[str] = None

    # OpenTelemetry
    otel_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "cobalto"
    otel_sample_rate: float = 0.1

    # Security
    jwt_secret_key: str = Field(validation_alias="JWT_SECRET_KEY")
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # MCP Server
    mcp_server_enabled: bool = True
    mcp_server_host: str = "0.0.0.0"
    mcp_server_port: int = 8002
    mcp_server_transport: str = "sse"  # stdio, sse, websocket
    mcp_auth_enabled: bool = True
    mcp_rate_limit_requests: int = 100
    mcp_rate_limit_window_seconds: int = 60

    # MCP External Servers (JSON format: {"name": {"url": "...", "auth": {...}}})
    mcp_external_servers: str = "{}"

    # Data Mesh Memory
    memory_data_mesh_enabled: bool = True
    memory_consolidation_enabled: bool = True
    memory_consolidation_schedule: str = "0 2 * * *"  # 2 AM daily
    memory_ttl_days: int = 90
    memory_importance_threshold: float = 0.3
    memory_max_entries_per_agent: int = 10000
    memory_cross_tenant_sharing: bool = False
    memory_embedding_model: str = "text-embedding-3-small"
    memory_embedding_dimensions: int = 1536

    # Feature Flags
    enable_mitre_mapping: bool = True
    enable_threat_hunt: bool = False
    enable_documentation_agent: bool = False
    enable_auto_response: bool = False
    enable_multi_tenant: bool = False

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()

    @field_validator("app_env")
    @classmethod
    def validate_app_env(cls, v: str) -> str:
        valid = ["development", "staging", "production"]
        if v.lower() not in valid:
            raise ValueError(f"app_env must be one of {valid}")
        return v.lower()

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_staging(self) -> bool:
        return self.app_env == "staging"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


class TenantSettings(BaseSettings):
    """Per-tenant settings for multi-tenancy support."""

    model_config = SettingsConfigDict(
        env_prefix="TENANT_",
        extra="ignore",
    )

    tenant_id: str
    tenant_name: str
    wazuh_index_prefix: str = "wazuh"
    opencti_organization: str = "default"
    thehive_organisation: str = "default"
    allowed_ips: List[str] = []
    blocked_ips: List[str] = []
    custom_mitre_tags: List[str] = []
    notification_channels: List[str] = ["slack"]
    max_cases_per_day: int = 1000
    retention_days: int = 365

    @classmethod
    def from_tenant_id(cls, tenant_id: str) -> "TenantSettings":
        """Load tenant settings from environment with prefix."""
        import os
        prefix = f"TENANT_{tenant_id.upper()}_"
        env_vars = {k.replace(prefix, "").lower(): v for k, v in os.environ.items() if k.startswith(prefix)}
        return cls(tenant_id=tenant_id, **env_vars)