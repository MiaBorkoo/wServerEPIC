from sqlalchemy import Column, String, DateTime, LargeBinary, Boolean, Text, ForeignKey, Float, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    username = Column(String(50), primary_key=True)
    auth_salt = Column(String(64), nullable=False)
    enc_salt = Column(String(64), nullable=False)
    auth_key = Column(String(128), nullable=False)
    encrypted_mek = Column(String(256), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
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
    user = relationship("User", back_populates="device_certificates")
    trust_relationships = relationship("TrustRelationship", back_populates="device_certificate")

class TrustRelationship(Base):
    __tablename__ = "trust_relationships"
    trust_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    username = Column(String(50), ForeignKey("users.username"), nullable=False)
    trusted_cert_id = Column(UUID(as_uuid=True), ForeignKey("device_certificates.cert_id", ondelete="CASCADE"), nullable=False)
    trust_level = Column(String(20), nullable=False)
    verification_method = Column(String(20))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    user = relationship("User", back_populates="trust_relationships")
    device_certificate = relationship("DeviceCertificate", back_populates="trust_relationships")
    verification_events = relationship("VerificationEvent", back_populates="trust_relationship")

class VerificationEvent(Base):
    __tablename__ = "verification_events"
    event_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    trust_id = Column(UUID(as_uuid=True), ForeignKey("trust_relationships.trust_id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(20), nullable=False)
    method = Column(String(20))
    success = Column(Boolean, nullable=False)
    details = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    trust_relationship = relationship("TrustRelationship", back_populates="verification_events")

class File(Base):
    __tablename__ = "files"
    file_uuid = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    owner_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    name = Column(String(255), nullable=False)
    size = Column(Float, nullable=False)
    encrypted_file = Column(Text, nullable=False)
    integrity_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    owner = relationship("User", back_populates="owned_files")
    shared_with = relationship("SharedFile", back_populates="file", cascade="all, delete-orphan")
    __table_args__ = (Index('idx_files_owner', 'owner_id'),)

class SharedFile(Base):
    __tablename__ = "shared_files"
    share_id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    file_id = Column(UUID(as_uuid=True), ForeignKey("files.file_uuid", ondelete="CASCADE"), nullable=False)
    owner_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    recipient_id = Column(String(50), ForeignKey("users.username"), nullable=False)
    encrypted_file_key = Column(String(256), nullable=False)
    shared_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True))
    file = relationship("File", back_populates="shared_with")
    recipient = relationship("User", back_populates="shared_files")
    __table_args__ = (
        Index('idx_shared_files_owner', 'owner_id'),
        Index('idx_shared_files_recipient', 'recipient_id'),
        Index('idx_shared_files_expires', 'expires_at'),
    )