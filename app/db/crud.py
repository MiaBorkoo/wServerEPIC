from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func
from uuid import UUID, uuid4
from datetime import datetime, timezone
import time
from typing import List, Tuple, Optional, Dict, Any
import hashlib
import hmac

from app.db.models import User, File, Share, FileAuditLog
from app.core.security import compute_hmac, verify_hmac, hash_ip_address

# User CRUD operations

def create_user(
    db: Session, 
    username: str, 
    public_key: str, 
    user_data_hmac: str
) -> User:
    """Create a new user with integrity protection"""
    user = User(
        username=username,
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
    permission_level: str,
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
        permission_level=permission_level,
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
    share_data = f"{share.share_id}{share.file_id}{share.owner_id}{share.recipient_id}{share.permission_level}"
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