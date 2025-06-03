from datetime import datetime, timedelta, timezone
from typing import Any, Union, Optional
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import os
import secrets
import hashlib
import hmac
from uuid import UUID
from cryptography.fernet import Fernet
import ntplib
import time
import logging
#import requests
import json

from app.db.database import get_db
from app.db import crud

# Environment variables
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# TOTP-SEED ENCRYPTION KEY
# • We store the *TOTP seed* (the long-lived base-32 secret) encrypted
#   in the database, never in plaintext.
# • Encryption uses Fernet (AES-128-GCM + HMAC-SHA-256).

APP_ENV = os.getenv("APP_ENV", "dev").lower() #choose environment

# Change the check to only apply in production
if os.getenv("ENVIRONMENT") == "production":
    if not os.getenv("TOTP_ENCRYPTION_KEY"):
        raise RuntimeError("TOTP_ENCRYPTION_KEY must be set in production!")
        
# For development, use a default key
TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY", "j10sWLvYgV7vHcnJ88aaCVqIFN8W063kQKy3_WqGKK4=")

fernet = Fernet(TOTP_ENCRYPTION_KEY)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT Bearer token
security = HTTPBearer()

class SecuritySettings:
    secret_key: str = SECRET_KEY
    algorithm: str = ALGORITHM
    access_token_expire_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    refresh_token_expire_days: int = REFRESH_TOKEN_EXPIRE_DAYS

settings = SecuritySettings()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def verify_token(token: str, expected_type: str = "access") -> dict:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("type") != expected_type:
            raise JWTError("Invalid token type")
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def hash_ip_address(ip: str, salt: str = "") -> str:
    """Hash IP address for privacy in audit logs"""
    return hashlib.sha256(f"{ip}{salt}".encode()).hexdigest()

def compute_hmac(data: str, key: str) -> str:
    """Compute HMAC for data integrity"""
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data: str, key: str, expected_hmac: str) -> bool:
    """Verify HMAC for data integrity"""
    computed_hmac = compute_hmac(data, key)
    return hmac.compare_digest(computed_hmac, expected_hmac)

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """Get current authenticated user from JWT token"""
    payload = verify_token(credentials.credentials)
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID format",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = crud.get_user_by_id(db, user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

async def get_current_active_user(
    current_user = Depends(get_current_user)
):
    """Get current active user (extend for user status checks)"""
    return current_user

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown" 

#Fernet helpers for encrypting the TOTP seed that lives in the DB. 
def encrypt_totp_seed(seed: str) -> bytes:
    """Encrypt TOTP seed for database storage"""
    return fernet.encrypt(seed.encode())

def decrypt_totp_seed(encrypted_seed: bytes) -> str:
    """Decrypt TOTP seed from database"""
    return fernet.decrypt(encrypted_seed).decode()

# Replace NTP with HTTPS time sources for better security
SECURE_TIME_SOURCES = [
    "https://worldtimeapi.org/api/timezone/Etc/UTC",
    "https://timeapi.io/api/Time/current/zone?timeZone=UTC",
    "https://worldclockapi.com/api/json/utc/now"
]

def get_synchronized_time() -> float:
    """
    Get synchronized time from HTTPS time services.
    Falls back to system time if all services are unavailable.
    
    Returns:
        float: Unix timestamp synchronized with external time servers
    """
    for time_service in SECURE_TIME_SOURCES:
        try:
            response = requests.get(time_service, timeout=5, verify=True)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse time based on service format
            if "worldtimeapi.org" in time_service:
                time_str = data.get("datetime")
                if time_str:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    return dt.timestamp()
            elif "timeapi.io" in time_service:
                time_str = data.get("dateTime")
                if time_str:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    return dt.timestamp()
            elif "worldclockapi.com" in time_service:
                time_str = data.get("currentDateTime")
                if time_str:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    return dt.timestamp()
                    
        except Exception as e:
            logging.debug(f"Failed to sync with time service {time_service}: {e}")
            continue
    
    # Fall back to system time if all services fail
    logging.warning("All secure time services failed, using system time for TOTP validation")
    return time.time()

def check_time_sync():
    """Stub function for time synchronization check"""
    return {"status": "ok", "time_sync": True}