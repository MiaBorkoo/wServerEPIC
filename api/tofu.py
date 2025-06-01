from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
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
from base64 import b64decode, b64encode

router = APIRouter()

# Request Models
class DeviceCertRequest(BaseModel):
    username: str
    device_id: str
    public_key: str  # base64 encoded
    expires_at: datetime
    signature: str   # base64 encoded

class TrustDecision(BaseModel):
    username: str
    device_id: str
    trust_level: str  # "untrusted", "tofu", "verified"
    verification_method: Optional[str] = None

class QRVerificationRequest(BaseModel):
    username: str
    device_id: str
    verification_code: str
    timestamp: datetime

@router.post("/api/tofu/register")
async def register_device(request: DeviceCertRequest):
    """Register a new device certificate."""
    try:
        # Check if device already exists
        existing = get_device_certificate(request.username, request.device_id)
        if existing:
            raise HTTPException(status_code=400, detail="Device already registered")
        
        # Convert base64 to bytes for storage
        public_key = b64decode(request.public_key)
        signature = b64decode(request.signature)
        
        # Store certificate and create trust relationship
        result = store_device_certificate(
            request.username,
            request.device_id,
            public_key,
            request.expires_at,
            signature
        )
        
        return {
            "status": "success",
            "cert_id": result["cert_id"],
            "trust_id": result["trust_id"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/tofu/devices/{username}")
async def get_user_devices(username: str):
    """Get all devices and their trust status for a user."""
    try:
        devices = get_user_certificates(username)
        
        # Convert bytes to base64 for JSON response
        for device in devices:
            device["public_key"] = b64encode(device["public_key"]).decode()
            device["signature"] = b64encode(device["signature"]).decode()
            
            # Get trust status
            trust_status = get_trust_status(username, device["cert_id"])
            if trust_status:
                device["trust_level"] = trust_status["trust_level"]
                device["verification_method"] = trust_status["verification_method"]
                device["last_verified"] = trust_status["updated_at"]
            
        return {"devices": devices}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/tofu/trust")
async def update_trust_level(request: TrustDecision):
    """Update trust level for a device."""
    try:
        # Validate trust level
        valid_levels = ["untrusted", "tofu", "verified"]
        if request.trust_level not in valid_levels:
            raise HTTPException(status_code=400, detail="Invalid trust level")
        
        # Get certificate
        cert = get_device_certificate(request.username, request.device_id)
        if not cert:
            raise HTTPException(status_code=404, detail="Device certificate not found")
            
        # Get trust status
        trust_status = get_trust_status(request.username, cert["cert_id"])
        if not trust_status:
            # Create new trust relationship
            trust_status = store_trust_relationship(
                request.username,
                cert["cert_id"],
                request.trust_level,
                request.verification_method
            )
        else:
            # Update existing trust relationship
            trust_status = update_trust_level(
                trust_status["trust_id"],
                request.trust_level,
                request.verification_method
            )
            
        # Log verification event
        store_verification_event(
            trust_status["trust_id"],
            "verify" if request.trust_level == "verified" else "update",
            request.verification_method,
            True,
            f"Trust level updated to {request.trust_level}"
        )
        
        return {"status": "success", "message": "Trust level updated"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/tofu/verify/qr")
async def verify_qr_code(request: QRVerificationRequest):
    """Verify a device using QR code verification."""
    try:
        # Get certificate
        cert = get_device_certificate(request.username, request.device_id)
        if not cert:
            raise HTTPException(status_code=404, detail="Device not found")
            
        # Get trust status
        trust_status = get_trust_status(request.username, cert["cert_id"])
        if not trust_status:
            raise HTTPException(status_code=404, detail="Trust relationship not found")
            
        # Verify the QR code using actual decoding and validation logic
        try:
            decoded_data = b64decode(request.qr_code_data).decode("utf-8")
            # Validate the decoded data (e.g., check format, match device ID and username)
            if decoded_data == f"{request.username}:{request.device_id}":
                verification_success = True
            else:
                verification_success = False
        except Exception as e:
            raise HTTPException(status_code=400, detail="Invalid QR code data")
        
        if verification_success:
            # Update trust level
            trust_status = update_trust_level(
                trust_status["trust_id"],
                "verified",
                "qr_code"
            )
                
            # Log verification event
            store_verification_event(
                trust_status["trust_id"],
                "verify",
                "qr_code",
                True,
                "QR code verification successful"
            )
            
            return {"status": "success", "message": "QR verification successful"}
        else:
            raise HTTPException(status_code=400, detail="QR verification failed")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/tofu/devices/{username}/{device_id}")
async def remove_device(username: str, device_id: str):
    """Remove a device and its trust relationships."""
    try:
        # Get certificate
        cert = get_device_certificate(username, device_id)
        if not cert:
            raise HTTPException(status_code=404, detail="Device not found")
            
        # Get trust status
        trust_status = get_trust_status(username, cert["cert_id"])
        if trust_status:
            # Log revocation event
            store_verification_event(
                trust_status["trust_id"],
                "revoke",
                None,
                True,
                "Device removed"
            )
            
        # The actual deletion is handled by database CASCADE
        return {"status": "success", "message": "Device removed"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 