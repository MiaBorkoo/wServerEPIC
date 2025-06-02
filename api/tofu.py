from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, validator
from datetime import datetime, timedelta
from typing import List, Optional
from base64 import b64encode, b64decode
from database import (
    store_device_certificate,
    get_device_certificate,
    get_user_certificates,
    store_trust_relationship,
    update_trust_level,
    store_verification_event,
    get_trust_status,
    get_verification_history
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import json
import secrets

router = APIRouter()

class DeviceCertRequest(BaseModel):
    username: str
    device_id: str
    public_key: str  # Base64 encoded
    signature: str   # Base64 encoded
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

class VerificationRequest(BaseModel):
    username: str
    device_id: str
    verification_code: str
    timestamp: datetime
    signature: str 

    @validator('timestamp')
    def validate_timestamp(cls, v):
        # Verify timestamp is within last 5 minutes
        if v < datetime.now() - timedelta(minutes=5):
            raise ValueError("Verification code has expired")
        if v > datetime.now() + timedelta(minutes=5):
            raise ValueError("Invalid future timestamp")
        return v

def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_bytes)
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except (InvalidSignature, ValueError):
        return False

@router.post("/api/tofu/register")
async def register_device(request: DeviceCertRequest):
    try:
        public_key_bytes = b64decode(request.public_key)
        signature_bytes = b64decode(request.signature)

        # Verify the signature (device must sign its own registration data)
        message = f"{request.username}:{request.device_id}:{request.public_key}:{request.expires_at.isoformat()}".encode()
        if not verify_signature(public_key_bytes, message, signature_bytes):
            raise HTTPException(status_code=400, detail="Invalid signature")

        cert_data = store_device_certificate(
            request.username,
            request.device_id,
            public_key_bytes,
            request.expires_at,
            signature_bytes
        )

        # Initially set trust level to 'untrusted'
        trust_data = store_trust_relationship(
            request.username,
            str(cert_data["cert_id"]),
            "untrusted"
        )

        return {
            "status": "success",
            "cert_id": cert_data["cert_id"],
            "trust_status": trust_data
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/api/tofu/devices/{username}")
async def get_user_devices(username: str):
    try:
        devices = get_user_certificates(username)
        
        # Bulk load trust statuses
        cert_ids = [device["cert_id"] for device in devices]
        trust_statuses = [get_trust_status(username, cert_id) for cert_id in cert_ids]
        trust_status_map = {ts["trusted_cert_id"]: ts for ts in trust_statuses if ts}

        # Process each device
        for device in devices:
            # Convert binary data to base64
            device["public_key"] = b64encode(device["public_key"]).decode()
            device["signature"] = b64encode(device["signature"]).decode()
            
            # Add trust status from map
            device["trust_status"] = trust_status_map.get(str(device["cert_id"]))

        return {"devices": devices}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/api/tofu/verify")
async def verify_device(request: VerificationRequest):
    try:
        # Get device certificate
        device = get_device_certificate(request.username, request.device_id)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Verify the signature using device's public key
        message = f"{request.username}:{request.device_id}:{request.verification_code}:{request.timestamp.isoformat()}".encode()
        signature = b64decode(request.signature)
        
        if not verify_signature(device["public_key"], message, signature):
            raise HTTPException(status_code=400, detail="Invalid signature")

        # Get current trust status
        trust_status = get_trust_status(request.username, str(device["cert_id"]))
        if not trust_status:
            raise HTTPException(status_code=404, detail="Trust relationship not found")

        # Update trust level to 'verified'
        updated_trust = update_trust_level(
            trust_status["trust_id"],
            "verified",
            "cryptographic"
        )

        # Record verification event
        store_verification_event(
            trust_status["trust_id"],
            "verify",
            "cryptographic",
            True,
            f"Verified with timestamp {request.timestamp.isoformat()}"
        )

        return {"status": "success", "trust_status": updated_trust}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/api/tofu/verification-history/{trust_id}")
async def get_device_verification_history(trust_id: str):
    try:
        events = get_verification_history(trust_id)
        return {"events": events}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))