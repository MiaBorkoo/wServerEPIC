from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from datetime import datetime

# Request schemas
class FileUploadRequest(BaseModel):
    filename_encrypted: bytes
    file_size_encrypted: bytes 
    file_data_hmac: str = Field(..., max_length=64)
    server_storage_path: str = Field(..., max_length=255)

class FileShareRequest(BaseModel):
    file_id: UUID
    recipient_username: str = Field(..., max_length=255)
    encrypted_data_key: bytes
    expires_at: Optional[datetime] = None
    share_grant_hmac: str = Field(..., max_length=64)
    share_chain_hmac: str = Field(..., max_length=64)

class ShareRevokeRequest(BaseModel):
    share_id: UUID

class FileDeleteRequest(BaseModel):
    file_id: UUID

# Response schemas
class FileResponse(BaseModel):
    file_id: UUID
    filename_encrypted: bytes
    file_size_encrypted: bytes
    upload_timestamp: int
    file_data_hmac: str
    server_storage_path: str
    
    class Config:
        from_attributes = True

class ShareResponse(BaseModel):
    share_id: UUID
    file_id: UUID
    recipient_id: UUID
    granted_at: datetime
    expires_at: Optional[datetime]
    revoked_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class UserFilesResponse(BaseModel):
    owned_files: List[FileResponse]
    shared_files: List[FileResponse]

class AuditLogResponse(BaseModel):
    log_id: UUID
    action: str
    timestamp: int
    client_ip_hash: str
    
    class Config:
        from_attributes = True

# Pagination schemas
class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0) 