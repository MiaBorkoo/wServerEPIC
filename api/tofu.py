from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from database import supabase
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
        existing = supabase.table("device_certificates").select("*")\
            .eq("username", request.username)\
            .eq("device_id", request.device_id)\
            .execute()
        
        if existing.data:
            raise HTTPException(status_code=400, detail="Device already registered")
        
        # Convert base64 to bytes for storage
        public_key = b64decode(request.public_key)
        signature = b64decode(request.signature)
        
        # Store certificate
        cert_response = supabase.table("device_certificates").insert({
            "username": request.username,
            "device_id": request.device_id,
            "public_key": public_key.hex(),
            "expires_at": request.expires_at.isoformat(),
            "signature": signature.hex()
        }).execute()
        
        if not cert_response.data:
            raise HTTPException(status_code=500, detail="Failed to store certificate")
        
        cert_id = cert_response.data[0]["cert_id"]
        
        # Create initial TOFU trust relationship
        trust_response = supabase.table("trust_relationships").insert({
            "username": request.username,
            "trusted_cert_id": cert_id,
            "trust_level": "tofu",
            "verification_method": "tofu"
        }).execute()
        
        if not trust_response.data:
            raise HTTPException(status_code=500, detail="Failed to create trust relationship")
        
        # Log the TOFU event
        supabase.table("verification_events").insert({
            "trust_id": trust_response.data[0]["trust_id"],
            "event_type": "tofu",
            "success": True,
            "details": "Initial device registration"
        }).execute()
        
        return {
            "status": "success",
            "cert_id": cert_id,
            "trust_id": trust_response.data[0]["trust_id"]
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/tofu/devices/{username}")
async def get_user_devices(username: str):
    """Get all devices and their trust status for a user."""
    try:
        response = supabase.table("device_certificates")\
            .select("*, trust_relationships(trust_level, verification_method, last_verified)")\
            .eq("username", username)\
            .execute()
        
        devices = []
        for device in response.data:
            # Convert hex strings to base64 for client
            device["public_key"] = b64encode(bytes.fromhex(device["public_key"])).decode()
            device["signature"] = b64encode(bytes.fromhex(device["signature"])).decode()
            devices.append(device)
            
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
        
        # Get certificate ID
        cert_response = supabase.table("device_certificates")\
            .select("cert_id")\
            .eq("username", request.username)\
            .eq("device_id", request.device_id)\
            .single()\
            .execute()
            
        if not cert_response.data:
            raise HTTPException(status_code=404, detail="Device certificate not found")
            
        cert_id = cert_response.data["cert_id"]
        
        # Update trust relationship
        trust_response = supabase.table("trust_relationships")\
            .update({
                "trust_level": request.trust_level,
                "verification_method": request.verification_method,
                "last_verified": datetime.now().isoformat()
            })\
            .eq("username", request.username)\
            .eq("trusted_cert_id", cert_id)\
            .execute()
            
        if not trust_response.data:
            raise HTTPException(status_code=404, detail="Trust relationship not found")
            
        # Log verification event
        supabase.table("verification_events").insert({
            "trust_id": trust_response.data[0]["trust_id"],
            "event_type": "verify" if request.trust_level == "verified" else "update",
            "method": request.verification_method,
            "success": True,
            "details": f"Trust level updated to {request.trust_level}"
        }).execute()
        
        return {"status": "success", "message": "Trust level updated"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/tofu/verify/qr")
async def verify_qr_code(request: QRVerificationRequest):
    """Verify a device using QR code verification."""
    try:
        # Get certificate and trust info
        cert_response = supabase.table("device_certificates")\
            .select("cert_id, trust_relationships(trust_id)")\
            .eq("username", request.username)\
            .eq("device_id", request.device_id)\
            .single()\
            .execute()
            
        if not cert_response.data:
            raise HTTPException(status_code=404, detail="Device not found")
            
        # Verify the QR code (you'll need to implement the actual verification logic)
        # This is just a placeholder that accepts any code
        verification_success = True
        
        if verification_success:
            # Update trust level
            trust_response = supabase.table("trust_relationships")\
                .update({
                    "trust_level": "verified",
                    "verification_method": "qr_code",
                    "last_verified": datetime.now().isoformat()
                })\
                .eq("trust_id", cert_response.data["trust_relationships"]["trust_id"])\
                .execute()
                
            # Log verification event
            supabase.table("verification_events").insert({
                "trust_id": cert_response.data["trust_relationships"]["trust_id"],
                "event_type": "verify",
                "method": "qr_code",
                "success": True,
                "details": "QR code verification successful"
            }).execute()
            
            return {"status": "success", "message": "QR verification successful"}
        else:
            raise HTTPException(status_code=400, detail="QR verification failed")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/api/tofu/devices/{username}/{device_id}")
async def remove_device(username: str, device_id: str):
    """Remove a device and its trust relationships."""
    try:
        # Get certificate ID first
        cert_response = supabase.table("device_certificates")\
            .select("cert_id")\
            .eq("username", username)\
            .eq("device_id", device_id)\
            .single()\
            .execute()
            
        if not cert_response.data:
            raise HTTPException(status_code=404, detail="Device not found")
            
        cert_id = cert_response.data["cert_id"]
        
        # Delete trust relationships (cascades to verification_events)
        supabase.table("trust_relationships")\
            .delete()\
            .eq("trusted_cert_id", cert_id)\
            .execute()
            
        # Delete the certificate
        supabase.table("device_certificates")\
            .delete()\
            .eq("cert_id", cert_id)\
            .execute()
            
        return {"status": "success", "message": "Device removed"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 