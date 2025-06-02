from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from api.auth import router as auth_router
from api.tofu import router as tofu_router
from app.db.crud import create_file, create_shared_file, get_user_files, verify_user_auth, update_user_password
from app.db.database import get_db
from app.totp import verify_totp
from sqlalchemy.orm import Session
from secrets import token_urlsafe
import os
import logging

logger = logging.getLogger(__name__)

app = FastAPI(title="EPIC Server", description="Server for CS4455 Epic Project")
app.include_router(auth_router)
app.include_router(tofu_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "EPIC Server is running with Supabase."}

class FileUploadRequest(BaseModel):
    owner_id: str
    name: str
    size: float
    encrypted_file: str
    integrity_hash: str

@app.post("/api/files/upload")
async def upload_file(request: FileUploadRequest, db: Session = Depends(get_db)):
    try:
        file_data = create_file(
            db=db, owner_id=request.owner_id, name=request.name, size=request.size,
            encrypted_file=request.encrypted_file, integrity_hash=request.integrity_hash
        )
        return {"status": "success", "file_uuid": file_data["file_uuid"]}
    except Exception as e:
        logger.error(f"File upload failed: {str(e)}")
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

class FileShareRequest(BaseModel):
    owner_id: str
    recipient_id: str
    file_id: str
    encrypted_file_key: str
    time_limit: int

@app.post("/api/files/share")
async def share_file(request: FileShareRequest, db: Session = Depends(get_db)):
    from datetime import datetime, timedelta
    expires_at = datetime.now() + timedelta(seconds=request.time_limit) if request.time_limit else None
    try:
        share_data = create_shared_file(
            db=db, owner_id=request.owner_id, recipient_id=request.recipient_id,
            file_id=request.file_id, encrypted_file_key=request.encrypted_file_key, expires_at=expires_at
        )
        return {"status": "success", "shared_id": share_data["share_id"]}
    except Exception as e:
        logger.error(f"File share failed: {str(e)}")
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

@app.get("/api/files")
async def list_files(user_id: str, db: Session = Depends(get_db)):
    try:
        owned_files, shared_files = get_user_files(db, user_id)
        return {"owned": owned_files, "shared": shared_files}
    except Exception as e:
        logger.error(f"File listing failed for user {user_id}: {str(e)}")
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str

@app.post("/api/auth/change_password")
async def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):
    if not verify_user_auth(db, request.username, request.old_auth_key):
        logger.warning(f"Invalid old credentials for password change: {request.username}")
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid old credentials"})
    if not verify_totp(request.username, request.totp_code):
        logger.warning(f"Invalid TOTP for password change: {request.username}")
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})
    try:
        update_user_password(db, request.username, request.new_auth_key, request.new_encrypted_mek)
        session_token = token_urlsafe(64)
        logger.info(f"Password changed for user: {request.username}")
        return {"status": "ok", "session": session_token}
    except Exception as e:
        logger.error(f"Password change failed for {request.username}: {str(e)}")
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)})

if __name__ == "__main__":
    uvicorn.run(
        app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)),
        ssl_keyfile="key.pem", ssl_certfile="cert.pem"
    )