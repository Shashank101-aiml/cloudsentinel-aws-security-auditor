from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    APP_NAME: str = "CloudSentinel — AWS Security & Compliance Auditor"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"  # nosec B104
    PORT: int = 8000
    SECRET_KEY: str = "cloudsentinel-insecure-dev-key-change-in-production-123456"

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

    # Database
    DATABASE_URL: str = "sqlite:///./cloudsentinel.db"

    # AWS Defaults
    AWS_PROFILE: Optional[str] = None
    AWS_DEFAULT_REGION: str = "us-east-1"
    AWS_ASSUME_ROLE_ARN: Optional[str] = None

    # Risk Scoring Policy Weights
    WEIGHT_CRITICAL: float = 10.0
    WEIGHT_HIGH: float = 7.0
    WEIGHT_MEDIUM: float = 4.0
    WEIGHT_LOW: float = 2.0
    WEIGHT_INFO: float = 0.0

    # Demo Mode Default
    DEMO_MODE_DEFAULT: bool = True

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()
