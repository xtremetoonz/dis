# Domain Analysis API Configuration
# backend/config.py

import os
from datetime import timedelta

class Config:
    """Base configuration for the application"""
    # Application settings
    APP_NAME = "Domain Analysis API"
    VERSION = "1.0.0"
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Logging settings
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # API settings
    API_PREFIX = "/api/v1"
    API_TITLE = "Domain Analysis API"
    API_VERSION = "1.0"
    API_DESCRIPTION = "API for analyzing domain security and configuration"
    
    # Security settings
    API_SIGNING_REQUIRED = False  # Whether to require request signing
    API_SIGNATURE_TTL = 300  # Time window for signature validation (seconds)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # CORS settings
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*")
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "memory://")
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Caching
    CACHE_TYPE = "SimpleCache"
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # External API keys
    CERTSPOTTER_API_KEY = os.environ.get("CERTSPOTTER_API_KEY", "")
    
    # Operational settings
    QUERY_TIMEOUT = 10  # Default timeout for external queries (seconds)
    
    # DNS resolver settings
    DNS_TIMEOUT = 3.0  # Timeout for DNS queries (seconds)
    DNS_LIFETIME = 6.0  # Total lifetime for DNS queries (seconds)
    DNS_DEFAULT_SERVERS = ["1.1.1.1", "8.8.8.8"]  # Fallback DNS servers

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    
    # Development-specific settings
    CACHE_TYPE = "NullCache"  # Disable caching in development
    
    # More verbose error messages
    PROPAGATE_EXCEPTIONS = True
    
    # Development rate limits
    RATELIMIT_DEFAULT = "1000 per day, 200 per hour"
    
    # Development DNS settings
    DNS_TIMEOUT = 5.0  # Longer timeout for development
    
    # Add sample API key for development
    API_KEYS = {
        "dev-api-key": {
            "id": "dev-client",
            "name": "Development Client",
            "secret_key": "dev-secret-key"
        }
    }

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Test-specific settings
    RATELIMIT_ENABLED = False  # Disable rate limiting in tests
    CACHE_TYPE = "NullCache"  # Disable caching in tests
    
    # Use in-memory database for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    
    # Mock API keys
    API_KEYS = {
        "test-api-key": {
            "id": "test-client", 
            "name": "Test Client",
            "secret_key": "test-secret-key"
        }
    }

class ProductionConfig(Config):
    """Production configuration"""
    # Ensure all production settings are from environment variables
    SECRET_KEY = os.environ.get("SECRET_KEY")
    
    # Stricter security settings
    API_SIGNING_REQUIRED = os.environ.get("API_SIGNING_REQUIRED", "True").lower() in ("true", "1", "t")
    
    # Use Redis for rate limiting if available
    RATELIMIT_STORAGE_URL = os.environ.get("REDIS_URL", "memory://")
    
    # More restrictive CORS
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "")
    
    # Production caching
    CACHE_TYPE = os.environ.get("CACHE_TYPE", "SimpleCache")
    CACHE_DEFAULT_TIMEOUT = int(os.environ.get("CACHE_TIMEOUT", "300"))
    
    # Override in production with DATABASE_URL environment variable
    # SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")

# Select configuration based on environment
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}

# Helper function to get config
def get_config():
    env = os.environ.get("FLASK_ENV", "default")
    return config.get(env, config["default"])
