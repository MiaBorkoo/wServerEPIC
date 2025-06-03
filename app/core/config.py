import os
import ssl
from datetime import timedelta
from dotenv import load_dotenv
from typing import List, Optional
from pydantic import BaseSettings, validator

# Load environment variables from .env file
load_dotenv()

# Supabase settings
SUPABASE_URL: str = os.getenv("SUPABASE_URL")
SUPABASE_KEY: str = os.getenv("SUPABASE_KEY")

# Server settings
PROJECT_NAME: str = "EPIC Server"
PORT: int = int(os.getenv("PORT", 8000))
SSL_KEYFILE: str = os.getenv("SSL_KEYFILE", "key.pem") # TODO: Consider if these defaults are secure for all environments
SSL_CERTFILE: str = os.getenv("SSL_CERTFILE", "cert.pem") # TODO: Consider if these defaults are secure for all environments

# Session settings
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_EXPIRY: timedelta = timedelta(minutes=10)
MAX_SESSIONS_PER_USER: int = 2

# CORS settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

if ENVIRONMENT == "production":
    ALLOW_ORIGINS = [
        "https://yourdomain.com",
        "https://app.yourdomain.com"
    ]

else:
    # Development only
    ALLOW_ORIGINS = [
        "http://localhost:3000",
        "http://localhost:8080"
        "*"
    ]

class Settings(BaseSettings):
    environment: str = "development"
    cors_origins: List[str] = []
    database_url: str
    ssl_keyfile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    
    @validator('cors_origins', pre=True)
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator('environment')
    def validate_environment(cls, v):
        if v not in ['development', 'production']:
            raise ValueError('Environment must be development, staging, or production')
        return v
    
    class Config:
        env_file = ".env"

settings = Settings()

# Validate required production settings
if settings.environment == "production":
    required_vars = ['DATABASE_URL', 'SECRET_KEY', 'TOTP_DATABASE_ENCRYPTION_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables for production: {missing_vars}")

# SSL/TLS Configuration
class SSLConfig:
    def __init__(self):
        self.ssl_keyfile = os.getenv("SSL_KEYFILE")
        self.ssl_certfile = os.getenv("SSL_CERTFILE")
        self.ssl_ca_certs = os.getenv("SSL_CA_CERTS")
        
    def validate_ssl_files(self):
        """Validate SSL certificate files exist and are readable"""
        if ENVIRONMENT == "production":
            if not self.ssl_keyfile or not self.ssl_certfile:
                raise ValueError("SSL_KEYFILE and SSL_CERTFILE must be set in production")
            
            if not os.path.exists(self.ssl_keyfile):
                raise FileNotFoundError(f"SSL key file not found: {self.ssl_keyfile}")
            
            if not os.path.exists(self.ssl_certfile):
                raise FileNotFoundError(f"SSL cert file not found: {self.ssl_certfile}")
            
            # Check file permissions (should be readable only by owner)
            key_stat = os.stat(self.ssl_keyfile)
            if key_stat.st_mode & 0o077:
                raise PermissionError(f"SSL key file has insecure permissions: {self.ssl_keyfile}")
    
    def get_ssl_context(self):
        """Create secure SSL context with strong ciphers"""
        if not self.ssl_keyfile or not self.ssl_certfile:
            return None
            
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.ssl_certfile, self.ssl_keyfile)
        
        # Disable weak protocols
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        # Set minimum TLS version to 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Use strong cipher suites only
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context

ssl_config = SSLConfig()

# Validate SSL configuration on startup
if ENVIRONMENT in ["production", "staging"]:
    ssl_config.validate_ssl_files()

# Database URL with SSL enforcement
if ENVIRONMENT == "production":
    # Force SSL for production database connections
    DATABASE_URL = os.getenv("DATABASE_URL")
    if DATABASE_URL and "sslmode=" not in DATABASE_URL:
        separator = "&" if "?" in DATABASE_URL else "?"
        DATABASE_URL += f"{separator}sslmode=require&sslcert=/path/to/client-cert.pem&sslkey=/path/to/client-key.pem&sslrootcert=/path/to/ca-cert.pem"
else:
    DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/epic_db")

# Redis URL with TLS
if ENVIRONMENT == "production":
    REDIS_URL = os.getenv("REDIS_URL", "rediss://localhost:6380/0")  # rediss:// for TLS
else:
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0") 