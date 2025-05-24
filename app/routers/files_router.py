from fastapi import APIRouter, HTTPException, Depends, Request, status, UploadFile, File as FastAPIFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from uuid import UUID
from typing import List
import time
import os
import io

from app.schemas.files import (
    FileUploadRequest, FileShareRequest, ShareRevokeRequest,
    FileResponse, ShareResponse, UserFilesResponse, 
    AuditLogResponse, PaginationParams
)
from app.db.database import get_db
from app.db import crud
from app.db.models import User
from app.core.security import get_current_active_user, get_client_ip, compute_hmac

router = APIRouter()

@router.post("/upload", response_model=dict)
async def upload_file(
    request: Request,
    file_request: FileUploadRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Upload a file with integrity protection and audit logging"""
    try:
        # Create file record
        file_record = crud.create_file(
            db=db,
            owner_id=current_user.user_id,
            filename_encrypted=file_request.filename_encrypted,
            file_size_encrypted=file_request.file_size_encrypted,
            file_data_hmac=file_request.file_data_hmac,
            server_storage_path=file_request.server_storage_path
        )
        
        # Create audit log entry
        client_ip = get_client_ip(request)
        log_data = f"{file_record.file_id}{current_user.user_id}upload{int(time.time())}"
        log_hmac = compute_hmac(log_data, "audit_log_key")
        
        crud.create_audit_log(
            db=db,
            file_id=file_record.file_id,
            user_id=current_user.user_id,
            action="upload",
            client_ip=client_ip,
            log_entry_hmac=log_hmac
        )
        
        return {
            "status": "success", 
            "file_id": file_record.file_id,
            "upload_timestamp": file_record.upload_timestamp
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Upload failed: {str(e)}"}
        )

@router.get("/{file_id}/download")
async def download_file(
    request: Request,
    file_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Download file with authorization check and audit logging"""
    try:
        # Check if user owns file or has share access
        file_record = crud.get_file_by_id(db, file_id)
        if not file_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        
        has_access = (file_record.owner_id == current_user.user_id or 
                     crud.get_active_share(db, file_id, current_user.user_id) is not None)
        
        if not has_access:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
        # Create audit log
        client_ip = get_client_ip(request)
        log_data = f"{file_id}{current_user.user_id}download{int(time.time())}"
        log_hmac = compute_hmac(log_data, "audit_log_key")
        
        crud.create_audit_log(
            db=db,
            file_id=file_id,
            user_id=current_user.user_id,
            action="download",
            client_ip=client_ip,
            log_entry_hmac=log_hmac
        )
        
        # Stream file content
        def file_generator():
            with open(file_record.server_storage_path, "rb") as f:
                while chunk := f.read(8192):
                    yield chunk
        
        return StreamingResponse(
            file_generator(),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f"attachment; filename={file_id}"}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Download failed: {str(e)}"}
        )

@router.get("/{file_id}/metadata", response_model=FileResponse)
async def get_file_metadata(
    file_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get file metadata"""
    try:
        file_record = crud.get_file_by_id(db, file_id)
        if not file_record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")
        
        # Check access
        has_access = (file_record.owner_id == current_user.user_id or 
                     crud.get_active_share(db, file_id, current_user.user_id) is not None)
        
        if not has_access:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
        return FileResponse.model_validate(file_record)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Failed to get metadata: {str(e)}"}
        )

@router.post("/share", response_model=dict)
async def share_file(
    request: Request,
    share_request: FileShareRequest,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Share a file with another user with integrity protection"""
    try:
        # Verify file ownership
        if not crud.verify_file_ownership(db, share_request.file_id, current_user.user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't own this file"
            )
        
        # Get recipient user
        recipient = crud.get_user_by_username(db, share_request.recipient_username)
        if not recipient:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Recipient user not found"
            )
        
        # Check if share already exists
        existing_share = crud.get_active_share(db, share_request.file_id, recipient.user_id)
        if existing_share:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="File already shared with this user"
            )
        
        # Create share
        share = crud.create_share(
            db=db,
            file_id=share_request.file_id,
            owner_id=current_user.user_id,
            recipient_id=recipient.user_id,
            encrypted_data_key=share_request.encrypted_data_key,
            permission_level=share_request.permission_level,
            share_grant_hmac=share_request.share_grant_hmac,
            share_chain_hmac=share_request.share_chain_hmac,
            expires_at=share_request.expires_at
        )
        
        # Create audit log
        client_ip = get_client_ip(request)
        log_data = f"{share_request.file_id}{current_user.user_id}share{int(time.time())}"
        log_hmac = compute_hmac(log_data, "audit_log_key")
        
        crud.create_audit_log(
            db=db,
            file_id=share_request.file_id,
            user_id=current_user.user_id,
            action="share",
            client_ip=client_ip,
            log_entry_hmac=log_hmac
        )
        
        return {
            "status": "success",
            "share_id": share.share_id,
            "granted_at": share.granted_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Share failed: {str(e)}"}
        )

@router.delete("/share/{share_id}", response_model=dict)
async def revoke_share(
    request: Request,
    share_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Revoke a file share"""
    try:
        success = crud.revoke_share(db, share_id, current_user.user_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Share not found or you don't have permission to revoke it"
            )
        
        # Get share details for audit log
        share = crud.get_share_by_id(db, share_id)
        if share:
            client_ip = get_client_ip(request)
            log_data = f"{share.file_id}{current_user.user_id}revoke{int(time.time())}"
            log_hmac = compute_hmac(log_data, "audit_log_key")
            
            crud.create_audit_log(
                db=db,
                file_id=share.file_id,
                user_id=current_user.user_id,
                action="revoke",
                client_ip=client_ip,
                log_entry_hmac=log_hmac
            )
        
        return {"status": "success", "message": "Share revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Revoke failed: {str(e)}"}
        )

@router.get("/", response_model=UserFilesResponse)
async def list_files(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List user's owned and shared files with pagination"""
    try:
        # Get owned files
        owned_files = crud.get_user_owned_files(
            db, current_user.user_id, pagination.limit, pagination.offset
        )
        
        # Get shared files
        shared_files_data = crud.get_user_shared_files(
            db, current_user.user_id, pagination.limit, pagination.offset
        )
        shared_files = [file for file, share in shared_files_data]
        
        return UserFilesResponse(
            owned_files=[FileResponse.model_validate(file) for file in owned_files],
            shared_files=[FileResponse.model_validate(file) for file in shared_files]
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Failed to list files: {str(e)}"}
        )

@router.get("/{file_id}/shares", response_model=List[ShareResponse])
async def list_file_shares(
    file_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List all shares for a file (only owner can view)"""
    try:
        # Verify file ownership
        if not crud.verify_file_ownership(db, file_id, current_user.user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't own this file"
            )
        
        shares = crud.get_file_shares(db, file_id, current_user.user_id)
        return [ShareResponse.model_validate(share) for share in shares]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Failed to list shares: {str(e)}"}
        )

@router.get("/shares/received", response_model=List[FileResponse])
async def list_received_shares(
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """List files shared with current user"""
    try:
        shared_files_data = crud.get_user_shared_files(
            db, current_user.user_id, pagination.limit, pagination.offset
        )
        shared_files = [file for file, share in shared_files_data]
        return [FileResponse.model_validate(file) for file in shared_files]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Failed to list received shares: {str(e)}"}
        )

@router.get("/{file_id}/audit", response_model=List[AuditLogResponse])
async def get_file_audit_logs(
    file_id: UUID,
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Get audit logs for a file (only owner can view)"""
    try:
        logs = crud.get_file_audit_logs(
            db, file_id, current_user.user_id, pagination.limit, pagination.offset
        )
        return [AuditLogResponse.model_validate(log) for log in logs]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Failed to get audit logs: {str(e)}"}
        )

@router.delete("/{file_id}", response_model=dict)
async def delete_file(
    request: Request,
    file_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    """Soft delete a file (only owner can delete)"""
    try:
        success = crud.soft_delete_file(db, file_id, current_user.user_id)
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found or you don't have permission to delete it"
            )
        
        # Create audit log
        client_ip = get_client_ip(request)
        log_data = f"{file_id}{current_user.user_id}delete{int(time.time())}"
        log_hmac = compute_hmac(log_data, "audit_log_key")
        
        crud.create_audit_log(
            db=db,
            file_id=file_id,
            user_id=current_user.user_id,
            action="delete",
            client_ip=client_ip,
            log_entry_hmac=log_hmac
        )
        
        return {"status": "success", "message": "File deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "error", "message": f"Delete failed: {str(e)}"}
        ) 