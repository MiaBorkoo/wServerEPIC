from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List
from uuid import UUID

class DeviceCertificateResponse(BaseModel):
    cert_id: UUID
    username: str
    device_id: str
    public_key: bytes
    expires_at: datetime
    signature: bytes
    created_at: datetime
    trust_relationships: List[dict]

class TrustRelationshipResponse(BaseModel):
    trust_id: UUID
    username: str
    trusted_cert_id: UUID
    trust_level: str
    verification_method: Optional[str]
    created_at: datetime
    updated_at: datetime

class VerificationEventResponse(BaseModel):
    event_id: UUID
    trust_id: UUID
    event_type: str
    method: Optional[str]
    success: bool
    details: Optional[str]
    created_at: datetime