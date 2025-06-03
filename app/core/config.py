import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv
from typing import List

# Load environment variables from .env file
load_dotenv()

# Server settings
PROJECT_NAME: str = "EPIC Server"
PORT: int = int(os.getenv("PORT", 3010))

# Session settings
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_EXPIRY: timedelta = timedelta(minutes=10)
MAX_SESSIONS_PER_USER: int = 2

# CORS settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

if ENVIRONMENT == "production":
    ALLOW_ORIGINS = [
        "https://chrisplusplus.gobbler.info",
    ]
else:
    ALLOW_ORIGINS = [
        "http://localhost:3000",              # Local development
        "https://chrisplusplus.gobbler.info", # Production subdomain  
        "*"  
    ]

# Validate required production settings
if ENVIRONMENT == "production":
    required_vars = ['DATABASE_URL', 'SECRET_KEY', 'TOTP_ENCRYPTION_KEY', 'AUDIT_LOG_HMAC_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing required environment variables for production: {missing_vars}")

# Database URL
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./epic.db")

# Audit Log HMAC Key for integrity protection
AUDIT_LOG_HMAC_KEY = os.getenv("AUDIT_LOG_HMAC_KEY", secrets.token_urlsafe(32))

# Sanitize database URL for logging
# def sanitize_db_url(url: str) -> str:
#     """Remove credentials from database URL for safe logging"""
#     import re
#     return re.sub(r'://[^:]+:[^@]+@', '://***:***@', url)

# DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./epic.db")
# SAFE_DATABASE_URL = sanitize_db_url(DATABASE_URL)  # For logging only

# Redis URL
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0") 