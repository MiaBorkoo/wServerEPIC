import os
from datetime import datetime
from typing import Optional, List
from sqlalchemy import create_engine, Column, String, DateTime, LargeBinary, Boolean, Text, ForeignKey, text, Float, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from dotenv import load_dotenv
import secrets
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from sqlalchemy import or_, and_

# Load environment variables
load_dotenv()
database_url = os.getenv("DATABASE_URL")
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")

# Create SQLAlchemy engine and session
engine = create_engine(database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing configuration
ph = PasswordHasher(
    time_cost=1, memory_cost=4097152, parallelism=8, salt_len=16, hash_len=32
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# SQLAlchemy Models
class User(Base):
    __tablename__ = "users"
    
    username = Column(String(50), primary_key=True)
    auth_salt = Column(String(64), nullable=False)
    enc_salt = Column(String(64), nullable=False)
    auth_key = Column(String(128), nullable=False)
    encrypted_mek = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    device_certificates = relationship("DeviceCertificate", back_populates="user")
    trust_relationships = relationship("TrustRelationship", back_populates="user")
    owned_files = relationship("File", back_populates="owner")
    shared_files = relationship("SharedFile", back_populates="recipient")

class DeviceCertificate(Base):
    __tablename__ = "device_certificates"
    
    cert_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username = Column(String(50), ForeignKey("users.username"), nullable=False)
    device_id = Column(String(64), nullable=False)
    public_key = Column(LargeBinary, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    signature = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="device_certificates")
    trust_relationships = relationship("TrustRelationship", back_populates="device_certificate")

class TrustRelationship(Base):
    __tablename__ = "trust_relationships"
    
    trust_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username = Column(String(50), ForeignKey("users.username"), nullable=False)
    trusted_cert_id = Column(UUID(as_uuid=True), ForeignKey("device_certificates.cert_id", ondelete="CASCADE"), nullable=False)
    trust_level = Column(String(20), nullable=False)  # 'untrusted', 'tofu', 'verified'
    verification_method = Column(String(20))  # 'qr', 'voice', etc.
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    user = relationship("User", back_populates="trust_relationships")
    device_certificate = relationship("DeviceCertificate", back_populates="trust_relationships")
    verification_events = relationship("VerificationEvent", back_populates="trust_relationship")

class VerificationEvent(Base):
    __tablename__ = "verification_events"
    
    event_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    trust_id = Column(UUID(as_uuid=True), ForeignKey("trust_relationships.trust_id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(20), nullable=False)  # 'verify', 'revoke', etc.
    method = Column(String(20))  # 'qr', 'voice', etc.
    success = Column(Boolean, nullable=False)
    details = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    trust_relationship = relationship("TrustRelationship", back_populates="verification_events")

# File-related models
class File(Base):
    __tablename__ = "files"
    
    file_uuid = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    owner_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    name = Column(String(255), nullable=False)
    size = Column(Float, nullable=False)
    encrypted_file = Column(Text, nullable=False)  # Base64 encoded encrypted file data
    integrity_hash = Column(String(128), nullable=False)  # SHA-512 hash of the original file
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="owned_files")
    shared_with = relationship("SharedFile", back_populates="file", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index('idx_files_owner', 'owner_id'),
    )

class SharedFile(Base):
    __tablename__ = "shared_files"
    
    share_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    file_id = Column(UUID(as_uuid=True), ForeignKey("files.file_uuid", ondelete="CASCADE"), nullable=False)
    owner_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    recipient_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    encrypted_file_key = Column(String(256), nullable=False)  # Encrypted with recipient's key
    shared_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True))  # Optional expiration
    
    # Relationships
    file = relationship("File", back_populates="shared_with")
    recipient = relationship("User", back_populates="shared_files")
    
    # Indexes
    __table_args__ = (
        Index('idx_shared_files_owner', 'owner_id'),
        Index('idx_shared_files_recipient', 'recipient_id'),
        Index('idx_shared_files_expires', 'expires_at'),
    )

# Helper Functions
def derive_mek_wrapper(client_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"MEK Wrapper"
    )
    return hkdf.derive(client_key)

# User-related functions
def store_user(username: str, auth_salt: str, enc_salt: str, auth_key: str, encrypted_mek: str) -> None:
    db = SessionLocal()
    try:
        user = User(
            username=username,
            auth_salt=auth_salt,
            enc_salt=enc_salt,
            auth_key=auth_key,
            encrypted_mek=encrypted_mek
        )
        db.add(user)
        db.commit()
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to store user: {str(e)}")
    finally:
        db.close()

def get_user_salts(username: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        return {"auth_salt": user.auth_salt, "enc_salt": user.enc_salt}
    finally:
        db.close()

def verify_user_auth(username: str, auth_key: str) -> bool:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        return bool(user and user.auth_key == auth_key)
    finally:
        db.close()

def get_encrypted_mek(username: str) -> str:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise Exception("User not found")
        return user.encrypted_mek
    finally:
        db.close()

def update_user_password(username: str, new_auth_key: str, new_encrypted_mek: str) -> None:
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise Exception("User not found")
        user.auth_key = new_auth_key
        user.encrypted_mek = new_encrypted_mek
        db.commit()
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to update password: {str(e)}")
    finally:
        db.close()

# TOFU-related functions
def store_device_certificate(username: str, device_id: str, public_key: bytes, expires_at: datetime, signature: bytes) -> dict:
    db = SessionLocal()
    try:
        cert = DeviceCertificate(
            username=username,
            device_id=device_id,
            public_key=public_key,
            expires_at=expires_at,
            signature=signature
        )
        db.add(cert)
        db.commit()
        db.refresh(cert)
        return {
            "cert_id": cert.cert_id,
            "username": cert.username,
            "device_id": cert.device_id,
            "public_key": cert.public_key,
            "expires_at": cert.expires_at,
            "signature": cert.signature,
            "created_at": cert.created_at
        }
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to store device certificate: {str(e)}")
    finally:
        db.close()

def get_device_certificate(username: str, device_id: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        cert = db.query(DeviceCertificate).filter(
            DeviceCertificate.username == username,
            DeviceCertificate.device_id == device_id
        ).first()
        if not cert:
            return None
        return {
            "cert_id": cert.cert_id,
            "username": cert.username,
            "device_id": cert.device_id,
            "public_key": cert.public_key,
            "expires_at": cert.expires_at,
            "signature": cert.signature,
            "created_at": cert.created_at
        }
    finally:
        db.close()

def get_user_certificates(username: str) -> List[dict]:
    db = SessionLocal()
    try:
        certs = db.query(DeviceCertificate).filter(
            DeviceCertificate.username == username
        ).all()
        return [{
            "cert_id": cert.cert_id,
            "username": cert.username,
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
    finally:
        db.close()

def store_trust_relationship(username: str, cert_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    db = SessionLocal()
    try:
        trust = TrustRelationship(
            username=username,
            trusted_cert_id=cert_id,
            trust_level=trust_level,
            verification_method=verification_method
        )
        db.add(trust)
        db.commit()
        db.refresh(trust)
        return {
            "trust_id": trust.trust_id,
            "username": trust.username,
            "trusted_cert_id": trust.trusted_cert_id,
            "trust_level": trust.trust_level,
            "verification_method": trust.verification_method,
            "created_at": trust.created_at,
            "updated_at": trust.updated_at
        }
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to store trust relationship: {str(e)}")
    finally:
        db.close()

def update_trust_level(trust_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    db = SessionLocal()
    try:
        trust = db.query(TrustRelationship).filter(TrustRelationship.trust_id == trust_id).first()
        if not trust:
            raise Exception("Trust relationship not found")
        trust.trust_level = trust_level
        if verification_method:
            trust.verification_method = verification_method
        db.commit()
        db.refresh(trust)
        return {
            "trust_id": trust.trust_id,
            "username": trust.username,
            "trusted_cert_id": trust.trusted_cert_id,
            "trust_level": trust.trust_level,
            "verification_method": trust.verification_method,
            "created_at": trust.created_at,
            "updated_at": trust.updated_at
        }
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to update trust level: {str(e)}")
    finally:
        db.close()

def store_verification_event(trust_id: str, event_type: str, method: Optional[str], success: bool, details: Optional[str] = None) -> dict:
    db = SessionLocal()
    try:
        event = VerificationEvent(
            trust_id=trust_id,
            event_type=event_type,
            method=method,
            success=success,
            details=details
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
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to store verification event: {str(e)}")
    finally:
        db.close()

def get_trust_status(username: str, cert_id: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        trust = db.query(TrustRelationship).filter(
            TrustRelationship.username == username,
            TrustRelationship.trusted_cert_id == cert_id
        ).first()
        if not trust:
            return None
        return {
            "trust_id": trust.trust_id,
            "username": trust.username,
            "trusted_cert_id": trust.trusted_cert_id,
            "trust_level": trust.trust_level,
            "verification_method": trust.verification_method,
            "created_at": trust.created_at,
            "updated_at": trust.updated_at
        }
    finally:
        db.close()

def get_verification_history(trust_id: str) -> List[dict]:
    db = SessionLocal()
    try:
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
    finally:
        db.close()

# File-related functions
def create_file(owner_id: str, name: str, size: float, encrypted_file: str, integrity_hash: str) -> dict:
    """Create a new file record."""
    db = SessionLocal()
    try:
        file = File(
            owner_id=owner_id,
            name=name,
            size=size,
            encrypted_file=encrypted_file,
            integrity_hash=integrity_hash
        )
        db.add(file)
        db.commit()
        db.refresh(file)
        return {
            "file_uuid": file.file_uuid,
            "owner_id": file.owner_id,
            "name": file.name,
            "size": file.size,
            "integrity_hash": file.integrity_hash,
            "created_at": file.created_at
        }
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to create file: {str(e)}")
    finally:
        db.close()

def create_shared_file(owner_id: str, recipient_id: str, file_id: str, encrypted_file_key: str, expires_at: Optional[datetime] = None) -> dict:
    """Share a file with another user."""
    db = SessionLocal()
    try:
        # Verify file exists and belongs to owner
        file = db.query(File).filter(
            File.file_uuid == file_id,
            File.owner_id == owner_id
        ).first()
        if not file:
            raise Exception("File not found or you don't have permission to share it")
        
        shared = SharedFile(
            file_id=file_id,
            owner_id=owner_id,
            recipient_id=recipient_id,
            encrypted_file_key=encrypted_file_key,
            expires_at=expires_at
        )
        db.add(shared)
        db.commit()
        db.refresh(shared)
        return {
            "share_id": shared.share_id,
            "file_id": shared.file_id,
            "owner_id": shared.owner_id,
            "recipient_id": shared.recipient_id,
            "shared_at": shared.shared_at,
            "expires_at": shared.expires_at
        }
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to share file: {str(e)}")
    finally:
        db.close()

def get_user_files(username: str) -> tuple[List[dict], List[dict]]:
    """Get both owned and shared files for a user."""
    db = SessionLocal()
    try:
        # Get owned files
        owned_files = db.query(File).filter(File.owner_id == username).all()
        owned_files_data = [{
            "file_uuid": file.file_uuid,
            "name": file.name,
            "size": file.size,
            "created_at": file.created_at,
            "integrity_hash": file.integrity_hash
        } for file in owned_files]
        
        # Get shared files
        current_time = datetime.now()
        shared_files = db.query(SharedFile, File).join(File).filter(
            SharedFile.recipient_id == username,
            or_(
                SharedFile.expires_at.is_(None),
                SharedFile.expires_at > current_time
            )
        ).all()
        shared_files_data = [{
            "file_uuid": file.file_uuid,
            "name": file.name,
            "size": file.size,
            "created_at": file.created_at,
            "integrity_hash": file.integrity_hash,
            "shared_at": shared.shared_at,
            "expires_at": shared.expires_at,
            "encrypted_file_key": shared.encrypted_file_key
        } for shared, file in shared_files]
        
        return owned_files_data, shared_files_data
    finally:
        db.close()

def delete_file(file_id: str, owner_id: str) -> bool:
    """Delete a file and all its shares."""
    db = SessionLocal()
    try:
        file = db.query(File).filter(
            File.file_uuid == file_id,
            File.owner_id == owner_id
        ).first()
        if not file:
            return False
        
        db.delete(file)  # This will cascade delete all shares
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to delete file: {str(e)}")
    finally:
        db.close()

def revoke_file_share(share_id: str, owner_id: str) -> bool:
    """Revoke a specific file share."""
    db = SessionLocal()
    try:
        share = db.query(SharedFile).filter(
            SharedFile.share_id == share_id,
            SharedFile.owner_id == owner_id
        ).first()
        if not share:
            return False
        
        db.delete(share)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        raise Exception(f"Failed to revoke share: {str(e)}")
    finally:
        db.close()

def get_file_metadata(file_id: str, user_id: str) -> Optional[dict]:
    """Get file metadata if user has access."""
    db = SessionLocal()
    try:
        # Check if user owns or has access to the file
        file = db.query(File).outerjoin(SharedFile).filter(
            File.file_uuid == file_id,
            or_(
                File.owner_id == user_id,
                and_(
                    SharedFile.recipient_id == user_id,
                    or_(
                        SharedFile.expires_at.is_(None),
                        SharedFile.expires_at > datetime.now()
                    )
                )
            )
        ).first()
        
        if not file:
            return None
            
        return {
            "file_uuid": file.file_uuid,
            "owner_id": file.owner_id,
            "name": file.name,
            "size": file.size,
            "integrity_hash": file.integrity_hash,
            "created_at": file.created_at
        }
    finally:
        db.close()