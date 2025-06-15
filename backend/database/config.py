# backend/database/config.py
import os
from urllib.parse import quote_plus
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)

class DatabaseConfig:
    # MySQL connection configuration for DIS project
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_NAME = os.getenv('DB_NAME', 'domain_scanner')
    DB_USER = os.getenv('DB_USER', 'dis_user')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    
    @classmethod
    def get_database_uri(cls):
        if not cls.DB_PASSWORD:
            raise ValueError("DB_PASSWORD must be set in environment or .env file")
        
        password = quote_plus(cls.DB_PASSWORD)
        return f"mysql+pymysql://{cls.DB_USER}:{password}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}?charset=utf8mb4"
    
    @classmethod
    def validate_config(cls):
        """Validate database configuration"""
        required_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']
        missing = [var for var in required_vars if not getattr(cls, var)]
        
        if missing:
            raise ValueError(f"Missing required database configuration: {', '.join(missing)}")
        
        return True
