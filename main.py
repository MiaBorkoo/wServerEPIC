from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from api.auth import router as auth_router
from database import create_file, create_shared_file, get_user_files, verify_user_auth, update_user_password, store_user, get_user_salts, get_encrypted_mek
from totp import verify_totp
import os
from secrets import token_urlsafe
from datetime import datetime

# FastAPI app
app = FastAPI(title="EPIC Server", description="Server for CS4455 Epic Project")

# Mount authentication routes
app.include_router(auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Endpoints

# Root endpoint (placeholder)
@app.get("/")
async def root():
    return {"message": "EPIC Server is running with Supabase."}

  # Registration
class RegisterRequest(BaseModel):
    username: str
    auth_salt: str
    enc_salt: str
    auth_key: str
    encrypted_mek: str

@app.post("/api/auth/register")
def register_user(data: RegisterRequest):
    try:
        store_user(data.username, data.auth_salt, data.enc_salt, data.auth_key, data.encrypted_mek)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Get Salts
@app.get("/api/user/{username}/salts")
def get_salts(username: str):
    salts = get_user_salts(username)
    if not salts:
        raise HTTPException(status_code=404, detail="User not found")
    return salts

class LoginRequest(BaseModel):
    username: str
    auth_key: str

@app.post("/api/auth/login")
def login(data: LoginRequest):
    if not verify_user_auth(data.username, data.auth_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_token = token_urlsafe(32)
    # Store temporary 
    return {"session": session_token, "totp_required": True}

# TOTP (Second Factor)
class TOTPRequest(BaseModel):
    username: str
    totp_code: str

@app.post("/api/auth/totp")
def verify_totp_and_return_mek(data: TOTPRequest):
    if not verify_totp(data.username, data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    mek = get_encrypted_mek(data.username)
    session_token = token_urlsafe(64)
    return {"session": session_token, "encrypted_mek": mek}

# File Upload
class FileUploadRequest(BaseModel):
    owner_id: int
    name: str
    size: float
    encrypted_file: str
    integrity_hash: str

@app.post("/api/files/upload")
async def upload_file(request: FileUploadRequest):
    try:
        file_data = create_file(
            owner_id=request.owner_id,
            name=request.name,
            size=request.size,
            encrypted_file=request.encrypted_file,
            integrity_hash=request.integrity_hash
        )
        return {"status": "success", "file_uuid": file_data["file_uuid"]}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

# Share File
class FileShareRequest(BaseModel):
    owner_id: int
    recipient_id: int
    file_id: str
    encrypted_file_key: str
    time_limit: int

@app.post("/api/files/share")
async def share_file(request: FileShareRequest):
    try:
        share_data = create_shared_file(
            owner_id=request.owner_id,
            recipient_id=request.recipient_id,
            file_id=request.file_id,
            encrypted_file_key=request.encrypted_file_key,
            time_limit=request.time_limit
        )
        return {"status": "success", "shared_id": share_data["shared_id"]}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

# List Files
@app.get("/api/files")
async def list_files(user_id: int):
    try:
        owned_files, shared_files = get_user_files(user_id)
        return {"owned": owned_files, "shared": shared_files}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

# Change Password
class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str

@app.post("/api/auth/change_password")
async def change_password(request: ChangePasswordRequest):
    if not verify_user_auth(request.username, request.old_auth_key):
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid old credentials"})

    if not verify_totp(request.username, request.totp_code):
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})

    # Update password and encrypted_mek
    try:
        update_user_password(request.username, request.new_auth_key, request.new_encrypted_mek)
        return {"status": "ok", "session": token_urlsafe(64)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)})

# Start server with SSL/TLS
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )