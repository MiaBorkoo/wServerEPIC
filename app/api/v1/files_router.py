from fastapi import APIRouter, HTTPException

from app.schemas.files import FileUploadRequest, FileShareRequest
from app.db import crud # Assuming crud.py contains all db operations

router = APIRouter()

@router.post("/upload")
async def upload_file(request: FileUploadRequest):
    # TODO: Get owner_id from authenticated user session/token, not from request body.
    # TODO: Implement file storage (e.g., to a cloud bucket or local filesystem).
    #       The `encrypted_file` field suggests the file content itself is being sent as a string.
    #       This is not scalable for large files. Consider using FastAPI's UploadFile for multipart uploads.
    try:
        file_data = crud.create_file(
            owner_id=request.owner_id, 
            name=request.name,
            size=request.size,
            encrypted_file=request.encrypted_file, # This should ideally be a path or reference to the stored file
            integrity_hash=request.integrity_hash
        )
        return {"status": "success", "file_uuid": file_data.get("file_uuid")}
    except Exception as e:
        # TODO: More specific error handling
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

@router.post("/share")
async def share_file(request: FileShareRequest):
    # TODO: Get owner_id from authenticated user session/token.
    # TODO: Validate that owner_id actually owns file_id.
    # TODO: Validate recipient_id exists.
    try:
        share_data = crud.create_shared_file(
            owner_id=request.owner_id,
            recipient_id=request.recipient_id,
            file_id=request.file_id,
            encrypted_file_key=request.encrypted_file_key,
            time_limit=request.time_limit
        )
        return {"status": "success", "shared_id": share_data.get("shared_id")}
    except Exception as e:
        # TODO: More specific error handling
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

@router.get("/") # Path is /api/files/
async def list_files(user_id: int):
    # TODO: Get user_id from authenticated user session/token.
    # TODO: Add pagination, filtering, sorting.
    try:
        owned_files, shared_files = crud.get_user_files(user_id)
        return {"owned": owned_files, "shared": shared_files}
    except Exception as e:
        # TODO: More specific error handling
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)}) 