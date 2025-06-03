from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List, Dict, Any
from uuid import UUID
import base64

from app.schemas.tofu import DeviceCertRequest, VerificationRequest
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.core.security import verify_signature  # Assumed to exist or use cryptography
from app.core.exceptions import handle_database_error, handle_validation_error, SecureHTTPException
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

router = APIRouter(prefix="/tofu", tags=["tofu"])

def _verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature using RSA-PSS with SHA256"""
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
    except InvalidSignature:
        return False
    except Exception as e:
        raise SecureHTTPException(
            status_code=400, 
            detail="Signature verification failed",
            internal_detail=f"Signature verification error: {str(e)}"
        )

@router.post("/register-device")
def register_device(request: DeviceCertRequest, db: Session = Depends(get_db)):
    """Register a new device certificate for TOFU"""
    try:
        # Verify user exists
        user = crud.get_user_by_id(db, request.user_id)
        if not user:
            raise SecureHTTPException(
                status_code=404, 
                detail="User not found",
                internal_detail=f"User {request.user_id} not found"
            )

        # Decode base64 inputs
        public_key_bytes = base64.b64decode(request.public_key)
        signature_bytes = base64.b64decode(request.signature)

        # Verify signature
        message = f"{request.user_id}:{request.device_id}:{request.public_key}:{request.expires_at.isoformat()}".encode()
        if not _verify_signature(public_key_bytes, message, signature_bytes):
            raise SecureHTTPException(
                status_code=400, 
                detail="Invalid signature",
                internal_detail=f"Device registration signature verification failed for user {request.user_id}"
            )

        # Store device certificate
        cert_data = crud.create_device_certificate(
            db=db,
            user_id=request.user_id,
            device_id=request.device_id,
            public_key=public_key_bytes,
            expires_at=request.expires_at,
            signature=signature_bytes
        )

        # Create initial trust relationship
        trust_data = crud.create_trust_relationship(
            db=db,
            user_id=request.user_id,
            cert_id=cert_data["cert_id"],
            trust_level="untrusted"
        )

        return {
            "status": "success",
            "cert_id": str(cert_data["cert_id"]),
            "trust_status": {
                "trust_id": str(trust_data["trust_id"]),
                "trust_level": trust_data["trust_level"],
                "created_at": trust_data["created_at"].isoformat()
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise handle_database_error(e)

@router.get("/devices/{user_id}")
def get_user_devices(user_id: UUID, db: Session = Depends(get_db)):
    """Get all device certificates for a user"""
    try:
        # Verify user exists
        user = crud.get_user_by_id(db, user_id)
        if not user:
            raise SecureHTTPException(
                status_code=404, 
                detail="User not found",
                internal_detail=f"User {user_id} not found"
            )

        # Get certificates
        devices = crud.get_user_certificates(db, user_id)

        # Prepare response with base64-encoded fields
        response_devices = []
        for device in devices:
            response_devices.append({
                "cert_id": str(device["cert_id"]),
                "device_id": device["device_id"],
                "public_key": base64.b64encode(device["public_key"]).decode(),
                "signature": base64.b64encode(device["signature"]).decode(),
                "expires_at": device["expires_at"].isoformat(),
                "created_at": device["created_at"].isoformat(),
                "trust_status": device["trust_relationships"][0] if device["trust_relationships"] else None
            })

        return {"status": "success", "devices": response_devices}
    except HTTPException:
        raise
    except Exception as e:
        raise handle_database_error(e)

@router.post("/verify")
def verify_device(request: VerificationRequest, db: Session = Depends(get_db)):
    """Verify a device certificate with a signed verification code"""
    try:
        # Verify user exists
        user = crud.get_user_by_id(db, request.user_id)
        if not user:
            raise SecureHTTPException(
                status_code=404, 
                detail="User not found",
                internal_detail=f"User {request.user_id} not found"
            )

        # Get device certificate
        device = crud.get_device_certificate(db, request.user_id, request.device_id)
        if not device:
            raise SecureHTTPException(
                status_code=404, 
                detail="Device not found",
                internal_detail=f"Device {request.device_id} not found for user {request.user_id}"
            )

        # Verify signature
        message = f"{request.user_id}:{request.device_id}:{request.verification_code}:{request.timestamp.isoformat()}".encode()
        signature = base64.b64decode(request.signature)
        if not _verify_signature(device["public_key"], message, signature):
            raise SecureHTTPException(
                status_code=400, 
                detail="Invalid signature",
                internal_detail=f"Device verification signature failed for device {request.device_id}"
            )

        # Get trust relationship
        trust_status = crud.get_trust_status(db, request.user_id, device["cert_id"])
        if not trust_status:
            raise SecureHTTPException(
                status_code=404, 
                detail="Trust relationship not found",
                internal_detail=f"Trust relationship not found for cert {device['cert_id']}"
            )

        # Update trust level
        updated_trust = crud.update_trust_level(
            db=db,
            trust_id=trust_status["trust_id"],
            trust_level="verified",
            verification_method="cryptographic"
        )

        # Log verification event
        crud.create_verification_event(
            db=db,
            trust_id=trust_status["trust_id"],
            event_type="verify",
            method="cryptographic",
            success=True,
            details=f"Verified with timestamp {request.timestamp.isoformat()}"
        )

        return {
            "status": "success",
            "trust_status": {
                "trust_id": str(updated_trust["trust_id"]),
                "trust_level": updated_trust["trust_level"],
                "verification_method": updated_trust["verification_method"],
                "updated_at": updated_trust["updated_at"].isoformat()
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise handle_database_error(e)

@router.get("/verification-history/{trust_id}")
def get_verification_history(trust_id: UUID, db: Session = Depends(get_db)):
    """Get verification history for a trust relationship"""
    try:
        # Get verification events
        events = crud.get_verification_history(db, trust_id)

        # Prepare response
        response_events = [
            {
                "event_id": str(event["event_id"]),
                "trust_id": str(event["trust_id"]),
                "event_type": event["event_type"],
                "method": event["method"],
                "success": event["success"],
                "details": event["details"],
                "created_at": event["created_at"].isoformat()
            }
            for event in events
        ]

        return {"status": "success", "events": response_events}
    except Exception as e:
        raise handle_database_error(e)