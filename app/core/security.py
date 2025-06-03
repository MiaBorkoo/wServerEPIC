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
        
# For development, use a default key or generate one
TOTP_ENCRYPTION_KEY = os.getenv("TOTP_ENCRYPTION_KEY")
if not TOTP_ENCRYPTION_KEY:
    # Generate a secure key for development
    TOTP_ENCRYPTION_KEY = Fernet.generate_key()
    print("WARNING: Using generated TOTP_ENCRYPTION_KEY for development. Set TOTP_ENCRYPTION_KEY in production!")

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
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    username = verify_token(credentials.credentials, credentials_exception)
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user = Depends(get_current_user)):
    return current_user

def compute_hmac(data: str, key: str) -> str:
    """Compute HMAC-SHA256 for integrity protection"""
    return hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()

def verify_hmac(data: str, key: str, provided_hmac: str) -> bool:
    """Verify HMAC-SHA256 for integrity protection"""
    computed_hmac = compute_hmac(data, key)
    return hmac.compare_digest(computed_hmac, provided_hmac)

def hash_ip_address(ip: str) -> str:
    """Hash IP address for privacy while maintaining audit capability"""
    return hashlib.sha256(ip.encode()).hexdigest()

def get_client_ip(request: Request) -> str:
    """Get client IP address from request"""
    # Check for forwarded headers (when behind proxy like Apache)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host

def encrypt_totp_secret(secret: str) -> bytes:
    """Encrypt TOTP secret using Fernet (AES-GCM + HMAC)"""
    return fernet.encrypt(secret.encode())

def decrypt_totp_secret(encrypted_secret: bytes) -> str:
    """Decrypt TOTP secret"""
    if isinstance(encrypted_secret, str):
        encrypted_secret = encrypted_secret.encode()
    return fernet.decrypt(encrypted_secret).decode()

# Alias for backwards compatibility
def encrypt_totp_seed(secret: str) -> bytes:
    """Encrypt TOTP seed using Fernet (AES-GCM + HMAC) - alias for encrypt_totp_secret"""
    return encrypt_totp_secret(secret)

def decrypt_totp_seed(encrypted_secret: bytes) -> str:
    """Decrypt TOTP seed - alias for decrypt_totp_secret"""
    return decrypt_totp_secret(encrypted_secret)

def check_time_sync():
    """Check if server time is synchronized with NTP servers"""
    try:
        client = ntplib.NTPClient()
        response = client.request('pool.ntp.org', version=3, timeout=10)
        server_time = time.time()
        ntp_time = response.tx_time
        drift = abs(server_time - ntp_time)
        
        return {
            "status": "ok" if drift < 30 else "warning",
            "time_drift_seconds": drift,
            "server_time": server_time,
            "ntp_time": ntp_time,
            "synchronized": drift < 30
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "synchronized": False
        }