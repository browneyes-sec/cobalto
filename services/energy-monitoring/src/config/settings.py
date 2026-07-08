"""
Energy Monitoring Service Configuration
"""
import os
from typing import List, Optional
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "Energy Monitoring Service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str = "postgresql://energy_user:energy_password@localhost:5432/energy_db"
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    REDIS_TTL: int = 3600  # 1 hour default TTL
    
    # External Energy APIs
    ERCOT_API_URL: str = "https://api.ercot.com/api"
    ERCOT_API_KEY: Optional[str] = None
    
    PJM_API_URL: str = "https://api.pjm.com/api/v1"
    PJM_API_KEY: Optional[str] = None
    
    CAISO_API_URL: str = "https://api.caiso.com/api"
    CAISO_API_KEY: Optional[str] = None
    
    NREL_API_URL: str = "https://api.nrel.gov"
    NREL_API_KEY: Optional[str] = None
    
    # ESG Configuration
    MIN_RENEWABLE_PERCENTAGE: float = 35.0
    CARBON_INTENSITY_THRESHOLD: float = 0.02
    CO2_PRICE_PER_TON: float = 112.0
    
    # Alert Thresholds
    ALERT_CO2_SPIKE_THRESHOLD: float = 0.5  # 50% increase
    ALERT_RENEWABLE_DROP_THRESHOLD: float = 15.0  # 15 percentage points
    ALERT_EFFICIENCY_DROP_THRESHOLD: float = 20.0  # 20 percentage points
    
    # Rate Limiting
    MAX_API_CALLS_PER_MINUTE: int = 100
    EXTERNAL_API_TIMEOUT: int = 30  # seconds
    
    # Cache
    CACHED_DATA_HOURS: int = 24
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Cached settings instance"""
    return Settings()


settings = get_settings()