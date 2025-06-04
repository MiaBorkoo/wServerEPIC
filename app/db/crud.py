from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from uuid import UUID, uuid4
from datetime import datetime, timezone
import time
from typing import List, Tuple, Optional, Dict, Any
import hashlib
import hmac
import os

from app.db.models import User, File, Share, FileAuditLog, DeviceCertificate, TrustRelationship, VerificationEvent
from app.core.security import compute_hmac, verify_hmac, hash_ip_address

# User CRUD operations

def create_user(
    db: Session, 
    username: str, 
    auth_salt: str,
    auth_salt_2: str,
    enc_salt: str,
    auth_hash: str,
    encrypted_mek: bytes,
    totp_secret: str,
    public_key: str,
    user_data_hmac: str
) -> User:
    """Create a new user with integrity protection - UPDATED to match REQ-AUTH-001"""
    # Convert public_key dict to JSON string for storage
    if isinstance(public_key, dict):
        import json
        public_key = json.dumps(public_key)
    
    # Convert encrypted_mek to bytes if it's a string (base64 encoded)
    if isinstance(encrypted_mek, str):
        import base64
        encrypted_mek = base64.b64decode(encrypted_mek)
    
    user = User(
        username=username,
        auth_salt=auth_salt,          # Authentication salt
        auth_salt_2=auth_salt_2,      # Second authentication salt
        enc_salt=enc_salt,            # Encryption salt  
        auth_hash=auth_hash,          # Authentication hash (Argon2id output)
        encrypted_mek=encrypted_mek,  # Client-encrypted MEK
        totp_secret=totp_secret,      # TOTP secret
        public_key=public_key,
        user_data_hmac=user_data_hmac,
        created_at=func.now()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def get_user_by_id(db: Session, user_id: UUID) -> Optional[User]:
    """Get user by ID"""
    return db.query(User).filter(User.user_id == user_id).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get user by username"""
    return db.query(User).filter(User.username == username).first()

def update_user_last_login(db: Session, user_id: UUID) -> bool:
    """Update user's last login timestamp"""
    result = db.query(User).filter(User.user_id == user_id).update({
        "last_login": func.now()
    })
    db.commit()
    return result > 0

def get_user_salts(db: Session, username: str) -> Optional[Dict[str, str]]:
    """Get user's authentication and encryption salts - ADDED for REQ-AUTH-005"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    return {
        "auth_salt": user.auth_salt,
        "auth_salt_2": user.auth_salt_2, 
        "enc_salt": user.enc_salt
    }

def verify_user_auth(db: Session, username: str, auth_hash: str) -> bool:
    """Verify user's authentication hash - ADDED for login flow"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    return user.auth_hash == auth_hash

def get_encrypted_mek(db: Session, username: str) -> Optional[bytes]:
    """Get user's encrypted MEK - ADDED for TOTP flow"""
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    return user.encrypted_mek

def update_user_password(db: Session, username: str, new_auth_hash: str, new_encrypted_mek: bytes) -> bool:
    """Update user's password and encrypted MEK - ADDED for password change"""
    # Convert encrypted_mek to bytes if it's a string (base64 encoded)
    if isinstance(new_encrypted_mek, str):
        import base64
        new_encrypted_mek = base64.b64decode(new_encrypted_mek)
    
    result = db.query(User).filter(User.username == username).update({
        "auth_hash": new_auth_hash,  # CHANGED: Using auth_hash instead of auth_key
        "encrypted_mek": new_encrypted_mek
    })
    db.commit()
    return result > 0

# File CRUD operations

def create_file(
    db: Session,
    owner_id: UUID,
    filename_encrypted: bytes,
    file_size_encrypted: bytes,
    file_data_hmac: str,
    server_storage_path: str
) -> File:
    """Create a new file with integrity protection"""
    upload_timestamp = int(time.time())
    
    file = File(
        owner_id=owner_id,
        filename_encrypted=filename_encrypted,
        file_size_encrypted=file_size_encrypted,
        upload_timestamp=upload_timestamp,
        file_data_hmac=file_data_hmac,
        server_storage_path=server_storage_path,
        is_deleted=False
    )
    db.add(file)
    db.commit()
    db.refresh(file)
    return file

def get_file_by_id(db: Session, file_id: UUID) -> Optional[File]:
    """Get file by ID if not deleted"""
    return db.query(File).filter(
        and_(File.file_id == file_id, File.is_deleted == False)
    ).first()

def get_user_owned_files(db: Session, user_id: UUID, limit: int = 100, offset: int = 0) -> List[File]:
    """Get files owned by user with pagination"""
    return db.query(File).filter(
        and_(File.owner_id == user_id, File.is_deleted == False)
    ).order_by(File.upload_timestamp.desc()).limit(limit).offset(offset).all()

def get_user_shared_files(db: Session, user_id: UUID, limit: int = 100, offset: int = 0) -> List[Tuple[File, Share]]:
    """Get files shared with user with pagination"""
    return db.query(File, Share).join(Share, File.file_id == Share.file_id).filter(
        and_(
            Share.recipient_id == user_id,
            Share.revoked_at.is_(None),
            or_(Share.expires_at.is_(None), Share.expires_at > func.now()),
            File.is_deleted == False
        )
    ).order_by(Share.granted_at.desc()).limit(limit).offset(offset).all()

def soft_delete_file(db: Session, file_id: UUID, user_id: UUID) -> bool:
    """Soft delete a file (only owner can delete)"""
    result = db.query(File).filter(
        and_(File.file_id == file_id, File.owner_id == user_id, File.is_deleted == False)
    ).update({
        "is_deleted": True,
        "deleted_at": func.now()
    })
    db.commit()
    return result > 0

def hard_delete_file(db: Session, file_id: UUID, user_id: UUID) -> bool:
    """Hard delete a file - removes both database record and physical file"""
    # Get file record first to access storage path
    file_record = db.query(File).filter(
        and_(File.file_id == file_id, File.owner_id == user_id, File.is_deleted == False)
    ).first()
    
    if not file_record:
        return False
    
    # Delete physical file
    try:
        if os.path.exists(file_record.server_storage_path):
            os.remove(file_record.server_storage_path)
    except OSError:
        pass  # Continue even if file deletion fails
    
    # Delete database record
    result = db.query(File).filter(
        and_(File.file_id == file_id, File.owner_id == user_id)
    ).delete()
    db.commit()
    return result > 0

def verify_file_ownership(db: Session, file_id: UUID, user_id: UUID) -> bool:
    """Verify that user owns the file"""
    return db.query(File).filter(
        and_(File.file_id == file_id, File.owner_id == user_id, File.is_deleted == False)
    ).first() is not None

# Share CRUD operations

def create_share(
    db: Session,
    file_id: UUID,
    owner_id: UUID,
    recipient_id: UUID,
    encrypted_data_key: bytes,
    share_grant_hmac: str,
    share_chain_hmac: str,
    expires_at: Optional[datetime] = None
) -> Share:
    """Create a new file share with integrity protection"""
    share = Share(
        file_id=file_id,
        owner_id=owner_id,
        recipient_id=recipient_id,
        encrypted_data_key=encrypted_data_key,
        share_grant_hmac=share_grant_hmac,
        share_chain_hmac=share_chain_hmac,
        expires_at=expires_at
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    return share

def get_share_by_id(db: Session, share_id: UUID) -> Optional[Share]:
    """Get share by ID"""
    return db.query(Share).filter(Share.share_id == share_id).first()

def get_active_share(db: Session, file_id: UUID, recipient_id: UUID) -> Optional[Share]:
    """Get active share for file and recipient"""
    return db.query(Share).filter(
        and_(
            Share.file_id == file_id,
            Share.recipient_id == recipient_id,
            Share.revoked_at.is_(None),
            or_(Share.expires_at.is_(None), Share.expires_at > func.now())
        )
    ).first()

def revoke_share(db: Session, share_id: UUID, owner_id: UUID) -> bool:
    """Revoke a share (only owner can revoke)"""
    result = db.query(Share).filter(
        and_(Share.share_id == share_id, Share.owner_id == owner_id, Share.revoked_at.is_(None))
    ).update({
        "revoked_at": func.now()
    })
    db.commit()
    return result > 0

def get_file_shares(db: Session, file_id: UUID, owner_id: UUID) -> List[Share]:
    """Get all shares for a file (only owner can view)"""
    return db.query(Share).filter(
        and_(Share.file_id == file_id, Share.owner_id == owner_id)
    ).order_by(Share.granted_at.desc()).all()

# Audit log operations

def create_audit_log(
    db: Session,
    file_id: UUID,
    user_id: UUID,
    action: str,
    client_ip: str,
    log_entry_hmac: str,
    previous_log_hmac: Optional[str] = None
) -> FileAuditLog:
    """Create audit log entry with chain of custody"""
    timestamp = int(time.time())
    client_ip_hash = hash_ip_address(client_ip)
    
    # Get previous log entry for chain
    if previous_log_hmac is None:
        last_log = db.query(FileAuditLog).filter(
            FileAuditLog.file_id == file_id
        ).order_by(FileAuditLog.timestamp.desc()).first()
        
        if last_log:
            previous_log_hmac = last_log.log_entry_hmac
    
    audit_log = FileAuditLog(
        file_id=file_id,
        user_id=user_id,
        action=action,
        timestamp=timestamp,
        client_ip_hash=client_ip_hash,
        log_entry_hmac=log_entry_hmac,
        previous_log_hmac=previous_log_hmac
    )
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    return audit_log

def get_file_audit_logs(
    db: Session, 
    file_id: UUID, 
    user_id: UUID, 
    limit: int = 100, 
    offset: int = 0
) -> List[FileAuditLog]:
    """Get audit logs for a file (only owner can view full logs)"""
    # Verify file ownership first
    if not verify_file_ownership(db, file_id, user_id):
        return []
    
    return db.query(FileAuditLog).filter(
        FileAuditLog.file_id == file_id
    ).order_by(FileAuditLog.timestamp.desc()).limit(limit).offset(offset).all()

# Helper functions for integrity verification

def verify_file_integrity(file: File, expected_hmac: str, hmac_key: str) -> bool:
    """Verify file metadata integrity using HMAC"""
    file_data = f"{file.file_id}{file.owner_id}{file.upload_timestamp}"
    return verify_hmac(file_data, hmac_key, expected_hmac)

def verify_share_integrity(share: Share, expected_hmac: str, hmac_key: str) -> bool:
    """Verify share integrity using HMAC"""
    share_data = f"{share.share_id}{share.file_id}{share.owner_id}{share.recipient_id}"
    return verify_hmac(share_data, hmac_key, expected_hmac)

def verify_audit_chain_integrity(db: Session, file_id: UUID) -> bool:
    """Verify the integrity of the audit log chain for a file"""
    logs = db.query(FileAuditLog).filter(
        FileAuditLog.file_id == file_id
    ).order_by(FileAuditLog.timestamp.asc()).all()
    
    if not logs:
        return True
    
    previous_hmac = None
    for log in logs:
        if log.previous_log_hmac != previous_hmac:
            return False
        previous_hmac = log.log_entry_hmac
    
    return True

# TOFU CRUD operations

def create_device_certificate(
    db: Session,
    user_id: UUID,
    device_id: str,
    public_key: bytes,
    expires_at: datetime,
    signature: bytes
) -> Dict[str, Any]:
    """Create a new device certificate for TOFU"""
    cert = DeviceCertificate(
        user_id=user_id,
        device_id=device_id,
        public_key=public_key,
        expires_at=expires_at,
        signature=signature,
        created_at=func.now()
    )
    db.add(cert)
    db.commit()
    db.refresh(cert)
    return {
        "cert_id": cert.cert_id,
        "user_id": cert.user_id,
        "device_id": cert.device_id,
        "public_key": cert.public_key,
        "expires_at": cert.expires_at,
        "signature": cert.signature,
        "created_at": cert.created_at
    }

def get_device_certificate(
    db: Session,
    user_id: UUID,
    device_id: str
) -> Optional[Dict[str, Any]]:
    """Get a device certificate by user_id and device ID"""
    cert = db.query(DeviceCertificate).filter(
        and_(
            DeviceCertificate.user_id == user_id,
            DeviceCertificate.device_id == device_id
        )
    ).first()
    if not cert:
        return None
    return {
        "cert_id": cert.cert_id,
        "user_id": cert.user_id,
        "device_id": cert.device_id,
        "public_key": cert.public_key,
        "expires_at": cert.expires_at,
        "signature": cert.signature,
        "created_at": cert.created_at
    }

def get_user_certificates(
    db: Session,
    user_id: UUID
) -> List[Dict[str, Any]]:
    """Get all device certificates for a user"""
    certs = db.query(DeviceCertificate).filter(
        DeviceCertificate.user_id == user_id
    ).all()
    return [{
        "cert_id": cert.cert_id,
        "user_id": cert.user_id,
        "device_id": cert.device_id,
        "public_key": cert.public_key,
        "expires_at": cert.expires_at,
        "signature": cert.signature,
        "created_at": cert.created_at,
        "trust_relationships": [{
            "trust_level": tr.trust_level,
            "verification_method": tr.verification_method,
            "last_verified": tr.updated_at
        } for tr in cert.trust_relationships]
    } for cert in certs]

def create_trust_relationship(
    db: Session,
    user_id: UUID,
    cert_id: UUID,
    trust_level: str,
    verification_method: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new trust relationship for TOFU"""
    trust = TrustRelationship(
        user_id=user_id,
        trusted_cert_id=cert_id,
        trust_level=trust_level,
        verification_method=verification_method,
        created_at=func.now(),
        updated_at=func.now()
    )
    db.add(trust)
    db.commit()
    db.refresh(trust)
    return {
        "trust_id": trust.trust_id,
        "user_id": trust.user_id,
        "trusted_cert_id": trust.trusted_cert_id,
        "trust_level": trust.trust_level,
        "verification_method": trust.verification_method,
        "created_at": trust.created_at,
        "updated_at": trust.updated_at
    }

def update_trust_level(
    db: Session,
    trust_id: UUID,
    trust_level: str,
    verification_method: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Update the trust level of an existing trust relationship"""
    trust = db.query(TrustRelationship).filter(
        TrustRelationship.trust_id == trust_id
    ).first()
    if not trust:
        return None
    trust.trust_level = trust_level
    if verification_method:
        trust.verification_method = verification_method
    trust.updated_at = func.now()
    db.commit()
    db.refresh(trust)
    return {
        "trust_id": trust.trust_id,
        "user_id": trust.user_id,
        "trusted_cert_id": trust.trusted_cert_id,
        "trust_level": trust.trust_level,
        "verification_method": trust.verification_method,
        "created_at": trust.created_at,
        "updated_at": trust.updated_at
    }

def create_verification_event(
    db: Session,
    trust_id: UUID,
    event_type: str,
    method: Optional[str],
    success: bool,
    details: Optional[str] = None
) -> Dict[str, Any]:
    """Create a new verification event for a trust relationship"""
    event = VerificationEvent(
        trust_id=trust_id,
        event_type=event_type,
        method=method,
        success=success,
        details=details,
        created_at=func.now()
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return {
        "event_id": event.event_id,
        "trust_id": event.trust_id,
        "event_type": event.event_type,
        "method": event.method,
        "success": event.success,
        "details": event.details,
        "created_at": event.created_at
    }

def get_trust_status(
    db: Session,
    user_id: UUID,
    cert_id: UUID
) -> Optional[Dict[str, Any]]:
    """Get the trust status for a specific certificate"""
    trust = db.query(TrustRelationship).filter(
        and_(
            TrustRelationship.user_id == user_id,
            TrustRelationship.trusted_cert_id == cert_id
        )
    ).first()
    if not trust:
        return None
    return {
        "trust_id": trust.trust_id,
        "user_id": trust.user_id,
        "trusted_cert_id": trust.trusted_cert_id,
        "trust_level": trust.trust_level,
        "verification_method": trust.verification_method,
        "created_at": trust.created_at,
        "updated_at": trust.updated_at
    }

def get_verification_history(
    db: Session,
    trust_id: UUID
) -> List[Dict[str, Any]]:
    """Get the verification history for a trust relationship"""
    events = db.query(VerificationEvent).filter(
        VerificationEvent.trust_id == trust_id
    ).order_by(VerificationEvent.created_at.desc()).all()
    return [{
        "event_id": event.event_id,
        "trust_id": event.trust_id,
        "event_type": event.event_type,
        "method": event.method,
        "success": event.success,
        "details": event.details,
        "created_at": event.created_at
    } for event in events]