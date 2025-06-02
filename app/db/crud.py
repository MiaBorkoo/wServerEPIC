from sqlalchemy.orm import Session
from .models import User, DeviceCertificate, TrustRelationship, VerificationEvent, File, SharedFile
from typing import Optional, List, Tuple
from datetime import datetime
import logging
from sqlalchemy import or_, and_

logger = logging.getLogger(__name__)

def store_user(db: Session, username: str, auth_salt: str, enc_salt: str, auth_key: str, encrypted_mek: str) -> None:
    try:
        user = User(username=username, auth_salt=auth_salt, enc_salt=enc_salt, auth_key=auth_key, encrypted_mek=encrypted_mek)
        db.add(user)
        db.commit()
        logger.info(f"User registered: {username}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store user {username}: {str(e)}")
        raise

def get_user_salts(db: Session, username: str) -> Optional[dict]:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.warning(f"User not found for salts: {username}")
        return None
    return {"auth_salt": user.auth_salt, "enc_salt": user.enc_salt}

def verify_user_auth(db: Session, username: str, auth_key: str) -> bool:
    user = db.query(User).filter(User.username == username).first()
    result = bool(user and user.auth_key == auth_key)
    logger.info(f"Authentication attempt for {username}: {'success' if result else 'failed'}")
    return result

def get_encrypted_mek(db: Session, username: str) -> str:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.error(f"User not found for MEK: {username}")
        raise ValueError("User not found")
    return user.encrypted_mek

def update_user_password(db: Session, username: str, new_auth_key: str, new_encrypted_mek: str) -> None:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        logger.error(f"User not found for password update: {username}")
        raise ValueError("User not found")
    user.auth_key = new_auth_key
    user.encrypted_mek = new_encrypted_mek
    db.commit()
    logger.info(f"Password updated for user: {username}")

def store_device_certificate(db: Session, username: str, device_id: str, public_key: bytes, expires_at: datetime, signature: bytes) -> dict:
    try:
        cert = DeviceCertificate(
            username=username, device_id=device_id, public_key=public_key, expires_at=expires_at, signature=signature
        )
        db.add(cert)
        db.commit()
        db.refresh(cert)
        logger.info(f"Device certificate stored for user {username}, device {device_id}")
        return {
            "cert_id": cert.cert_id, "username": cert.username, "device_id": cert.device_id,
            "public_key": cert.public_key, "expires_at": cert.expires_at, "signature": cert.signature,
            "created_at": cert.created_at
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store device certificate for {username}: {str(e)}")
        raise

def get_device_certificate(db: Session, username: str, device_id: str) -> Optional[dict]:
    cert = db.query(DeviceCertificate).filter(DeviceCertificate.username == username, DeviceCertificate.device_id == device_id).first()
    if not cert:
        logger.warning(f"Device certificate not found for {username}, device {device_id}")
        return None
    return {
        "cert_id": cert.cert_id, "username": cert.username, "device_id": cert.device_id,
        "public_key": cert.public_key, "expires_at": cert.expires_at, "signature": cert.signature,
        "created_at": cert.created_at
    }

def get_user_certificates(db: Session, username: str) -> List[dict]:
    certs = db.query(DeviceCertificate).filter(DeviceCertificate.username == username).all()
    return [{
        "cert_id": cert.cert_id, "username": cert.username, "device_id": cert.device_id,
        "public_key": cert.public_key, "expires_at": cert.expires_at, "signature": cert.signature,
        "created_at": cert.created_at,
        "trust_relationships": [{
            "trust_level": tr.trust_level, "verification_method": tr.verification_method, "last_verified": tr.updated_at
        } for tr in cert.trust_relationships]
    } for cert in certs]

def store_trust_relationship(db: Session, username: str, cert_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    try:
        trust = TrustRelationship(
            username=username, trusted_cert_id=cert_id, trust_level=trust_level, verification_method=verification_method
        )
        db.add(trust)
        db.commit()
        db.refresh(trust)
        logger.info(f"Trust relationship stored for {username}, cert_id {cert_id}, level {trust_level}")
        return {
            "trust_id": trust.trust_id, "username": trust.username, "trusted_cert_id": trust.trusted_cert_id,
            "trust_level": trust.trust_level, "verification_method": trust.verification_method,
            "created_at": trust.created_at, "updated_at": trust.updated_at
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store trust relationship: {str(e)}")
        raise

def update_trust_level(db: Session, trust_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    trust = db.query(TrustRelationship).filter(TrustRelationship.trust_id == trust_id).first()
    if not trust:
        logger.error(f"Trust relationship not found: {trust_id}")
        raise ValueError("Trust relationship not found")
    trust.trust_level = trust_level
    if verification_method:
        trust.verification_method = verification_method
    db.commit()
    db.refresh(trust)
    logger.info(f"Trust level updated for trust_id {trust_id} to {trust_level}")
    return {
        "trust_id": trust.trust_id, "username": trust.username, "trusted_cert_id": trust.trusted_cert_id,
        "trust_level": trust.trust_level, "verification_method": trust.verification_method,
        "created_at": trust.created_at, "updated_at": trust.updated_at
    }

def store_verification_event(db: Session, trust_id: str, event_type: str, method: Optional[str], success: bool, details: Optional[str] = None) -> dict:
    try:
        event = VerificationEvent(trust_id=trust_id, event_type=event_type, method=method, success=success, details=details)
        db.add(event)
        db.commit()
        db.refresh(event)
        logger.info(f"Verification event stored for trust_id {trust_id}, type {event_type}")
        return {
            "event_id": event.event_id, "trust_id": event.trust_id, "event_type": event.event_type,
            "method": event.method, "success": event.success, "details": event.details, "created_at": event.created_at
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to store verification event: {str(e)}")
        raise

def get_trust_status(db: Session, username: str, cert_id: str) -> Optional[dict]:
    trust = db.query(TrustRelationship).filter(TrustRelationship.username == username, TrustRelationship.trusted_cert_id == cert_id).first()
    if not trust:
        logger.warning(f"Trust status not found for {username}, cert_id {cert_id}")
        return None
    return {
        "trust_id": trust.trust_id, "username": trust.username, "trusted_cert_id": trust.trusted_cert_id,
        "trust_level": trust.trust_level, "verification_method": trust.verification_method,
        "created_at": trust.created_at, "updated_at": trust.updated_at
    }

def get_verification_history(db: Session, trust_id: str) -> List[dict]:
    events = db.query(VerificationEvent).filter(VerificationEvent.trust_id == trust_id).order_by(VerificationEvent.created_at.desc()).all()
    return [{
        "event_id": event.event_id, "trust_id": event.trust_id, "event_type": event.event_type,
        "method": event.method, "success": event.success, "details": event.details, "created_at": event.created_at
    } for event in events]

def create_file(db: Session, owner_id: str, name: str, size: float, encrypted_file: str, integrity_hash: str) -> dict:
    try:
        file = File(owner_id=owner_id, name=name, size=size, encrypted_file=encrypted_file, integrity_hash=integrity_hash)
        db.add(file)
        db.commit()
        db.refresh(file)
        logger.info(f"File created for user {owner_id}: {name}")
        return {
            "file_uuid": file.file_uuid, "owner_id": file.owner_id, "name": file.name,
            "size": file.size, "integrity_hash": file.integrity_hash, "created_at": file.created_at
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create file for {owner_id}: {str(e)}")
        raise

def create_shared_file(db: Session, owner_id: str, recipient_id: str, file_id: str, encrypted_file_key: str, expires_at: Optional[datetime] = None) -> dict:
    file = db.query(File).filter(File.file_uuid == file_id, File.owner_id == owner_id).first()
    if not file:
        logger.error(f"File not found or no permission for {owner_id}, file_id {file_id}")
        raise ValueError("File not found or you don't have permission to share it")
    try:
        shared = SharedFile(
            file_id=file_id, owner_id=owner_id, recipient_id=recipient_id, encrypted_file_key=encrypted_file_key, expires_at=expires_at
        )
        db.add(shared)
        db.commit()
        db.refresh(shared)
        logger.info(f"File shared from {owner_id} to {recipient_id}, file_id {file_id}")
        return {
            "share_id": shared.share_id, "file_id": shared.file_id, "owner_id": shared.owner_id,
            "recipient_id": shared.recipient_id, "shared_at": shared.shared_at, "expires_at": shared.expires_at
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to share file: {str(e)}")
        raise

def get_user_files(db: Session, username: str) -> Tuple[List[dict], List[dict]]:
    owned_files = db.query(File).filter(File.owner_id == username).all()
    owned_files_data = [{
        "file_uuid": file.file_uuid, "name": file.name, "size": file.size,
        "created_at": file.created_at, "integrity_hash": file.integrity_hash
    } for file in owned_files]
    
    current_time = datetime.now()
    shared_files = db.query(SharedFile, File).join(File).filter(
        SharedFile.recipient_id == username,
        or_(SharedFile.expires_at.is_(None), SharedFile.expires_at > current_time)
    ).all()
    shared_files_data = [{
        "file_uuid": file.file_uuid, "name": file.name, "size": file.size,
        "created_at": file.created_at, "integrity_hash": file.integrity_hash,
        "shared_at": shared.shared_at, "expires_at": shared.expires_at,
        "encrypted_file_key": shared.encrypted_file_key
    } for shared, file in shared_files]
    
    logger.info(f"Retrieved files for user {username}")
    return owned_files_data, shared_files_data

def delete_file(db: Session, file_id: str, owner_id: str) -> bool:
    file = db.query(File).filter(File.file_uuid == file_id, File.owner_id == owner_id).first()
    if not file:
        logger.warning(f"File not found for deletion: {file_id}, owner {owner_id}")
        return False
    try:
        db.delete(file)
        db.commit()
        logger.info(f"File deleted: {file_id} by {owner_id}")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete file {file_id}: {str(e)}")
        raise

def revoke_file_share(db: Session, share_id: str, owner_id: str) -> bool:
    share = db.query(SharedFile).filter(SharedFile.share_id == share_id, SharedFile.owner_id == owner_id).first()
    if not share:
        logger.warning(f"Share not found for revocation: {share_id}, owner {owner_id}")
        return False
    try:
        db.delete(share)
        db.commit()
        logger.info(f"Share revoked: {share_id} by {owner_id}")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to revoke share {share_id}: {str(e)}")
        raise

def get_file_metadata(db: Session, file_id: str, user_id: str) -> Optional[dict]:
    file = db.query(File).outerjoin(SharedFile).filter(
        File.file_uuid == file_id,
        or_(
            File.owner_id == user_id,
            and_(
                SharedFile.recipient_id == user_id,
                or_(SharedFile.expires_at.is_(None), SharedFile.expires_at > datetime.now())
            )
        )
    ).first()
    if not file:
        logger.warning(f"File metadata not found for {file_id}, user {user_id}")
        return None
    logger.info(f"Retrieved metadata for file {file_id} for user {user_id}")
    return {
        "file_uuid": file.file_uuid, "owner_id": file.owner_id, "name": file.name,
        "size": file.size, "integrity_hash": file.integrity_hash, "created_at": file.created_at
    }