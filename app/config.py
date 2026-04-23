from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # Application settings
    APP_NAME: str = "AI Cloud Security Monitor"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # AWS Configuration
    AWS_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    
    # Database Configuration
    DATABASE_URL: str = "sqlite:///./security_monitor.db"
    
    # AI Service Configuration
    OPENAI_API_KEY: str = ""
    AI_MODEL: str = "gpt-4"
    
    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: list = ["*"]
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings()
