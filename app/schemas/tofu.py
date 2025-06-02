from pydantic import BaseModel, validator
from datetime import datetime
from uuid import UUID
from typing import Optional
import base64

class DeviceCertRequest(BaseModel):
    user_id: UUID
    device_id: str
    public_key: str  # Base64-encoded public key
    signature: str   # Base64-encoded signature
    expires_at: datetime

    @validator('expires_at')
    def validate_expiration(cls, v):
        min_expiry = datetime.now() + timedelta(days=1)
        max_expiry = datetime.now() + timedelta(days=365)
        if v < min_expiry:
            raise ValueError("Certificate must be valid for at least 1 day")
        if v > max_expiry:
            raise ValueError("Certificate cannot be valid for more than 1 year")
        return v

    @validator('device_id')
    def validate_device_id(cls, v):
        if not v or len(v) < 8 or len(v) > 64:
            raise ValueError("Device ID must be between 8 and 64 characters")
        return v

    @validator('public_key', 'signature')
    def validate_base64(cls, v):
        try:
            base64.b64decode(v)
            return v
        except Exception:
            raise ValueError("Invalid base64 encoding")

class VerificationRequest(BaseModel):
    user_id: UUID
    device_id: str
    verification_code: str
    timestamp: datetime
    signature: str  # Base64-encoded signature

    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v < datetime.now() - timedelta(minutes=5):
            raise ValueError("Verification code has expired")
        if v > datetime.now() + timedelta(minutes=5):
            raise ValueError("Invalid future timestamp")
        return v

    @validator('signature')
    def validate_base64(cls, v):
        try:
            base64.b64decode(v)
            return v
        except Exception:
            raise ValueError("Invalid base64 encoding")