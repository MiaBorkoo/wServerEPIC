from sqlalchemy import Column, String, Boolean, Text, LargeBinary, BigInteger, ForeignKey, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy import DateTime
import uuid

Base = declarative_base()

class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type when available, otherwise uses CHAR(36).
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(UUID())
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return str(uuid.UUID(value))
            else:
                return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid.UUID):
                return uuid.UUID(value)
            else:
                return value

def get_timestamp_type():
    """Returns appropriate timestamp type based on dialect"""
    return DateTime

class User(Base):
    __tablename__ = "users"
    
    user_id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    username = Column(String(255), unique=True, nullable=False)
    auth_salt = Column(String(64), nullable=False)  # 32-byte salt, hex encoded
    enc_salt = Column(String(64), nullable=False)   # 32-byte salt, hex encoded
    auth_key = Column(String(128), nullable=False)  # Argon2id hash of server key
    encrypted_mek = Column(LargeBinary, nullable=False)  # Client-encrypted MEK
    totp_secret = Column(String(64), nullable=False)  # TOTP secret
    public_key = Column(Text, nullable=False)
    created_at = Column(get_timestamp_type(), default=func.now())
    last_login = Column(get_timestamp_type(), nullable=True)
    user_data_hmac = Column(String(64), nullable=False)
    
    # Relationships
    owned_files = relationship("File", back_populates="owner", foreign_keys="File.owner_id")
    granted_shares = relationship("Share", back_populates="owner", foreign_keys="Share.owner_id")
    received_shares = relationship("Share", back_populates="recipient", foreign_keys="Share.recipient_id")
    audit_logs = relationship("FileAuditLog", back_populates="user")

class File(Base):
    __tablename__ = "files"
    
    file_id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    owner_id = Column(GUID(), ForeignKey("users.user_id"), nullable=False)
    filename_encrypted = Column(LargeBinary, nullable=False)
    file_size_encrypted = Column(LargeBinary, nullable=False)
    upload_timestamp = Column(BigInteger, nullable=False)
    file_data_hmac = Column(String(64), nullable=False)
    server_storage_path = Column(String(255), nullable=False)
    is_deleted = Column(Boolean, default=False)
    deleted_at = Column(get_timestamp_type(), nullable=True)
    
    # Relationships
    owner = relationship("User", back_populates="owned_files", foreign_keys=[owner_id])
    shares = relationship("Share", back_populates="file")
    audit_logs = relationship("FileAuditLog", back_populates="file")

class Share(Base):
    __tablename__ = "shares"
    
    share_id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    file_id = Column(GUID(), ForeignKey("files.file_id"), nullable=False)
    owner_id = Column(GUID(), ForeignKey("users.user_id"), nullable=False)
    recipient_id = Column(GUID(), ForeignKey("users.user_id"), nullable=False)
    encrypted_data_key = Column(LargeBinary, nullable=False)
    permission_level = Column(String(20), nullable=False)
    granted_at = Column(get_timestamp_type(), default=func.now())
    expires_at = Column(get_timestamp_type(), nullable=True)
    revoked_at = Column(get_timestamp_type(), nullable=True)
    share_grant_hmac = Column(String(64), nullable=False)
    share_chain_hmac = Column(String(64), nullable=False)
    
    # Relationships
    file = relationship("File", back_populates="shares")
    owner = relationship("User", back_populates="granted_shares", foreign_keys=[owner_id])
    recipient = relationship("User", back_populates="received_shares", foreign_keys=[recipient_id])
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('file_id', 'recipient_id', name='unique_file_recipient'),
    )

class FileAuditLog(Base):
    __tablename__ = "file_audit_log"
    
    log_id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    file_id = Column(GUID(), ForeignKey("files.file_id"), nullable=False)
    user_id = Column(GUID(), ForeignKey("users.user_id"), nullable=False)
    action = Column(String(50), nullable=False)
    timestamp = Column(BigInteger, nullable=False)
    client_ip_hash = Column(String(64), nullable=True)
    log_entry_hmac = Column(String(64), nullable=False)
    previous_log_hmac = Column(String(64), nullable=True)
    
    # Relationships
    file = relationship("File", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_file_timestamp', 'file_id', 'timestamp'),
    ) 