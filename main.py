import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from supabase import create_client, Client
import uvicorn
import ssl
from datetime import datetime
import secrets

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# FastAPI app
app = FastAPI(title="EPIC Server", description="Server for CS4455 Epic Project")

# Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(supabase_url, supabase_key)

# API Endpoints

# Root endpoint (placeholder)
@app.get("/")
async def root():
    return {"message": "EPIC Server is running with Supabase."}

# User Registration: POST /api/auth/register
class RegisterRequest(BaseModel):
    username: str
    hashed_password: str
    salt: str
    public_key: str

@app.post("/api/auth/register")
async def register(request: RegisterRequest):
    response = supabase.table("Users").insert({
        "username": request.username,
        "hashed_password": request.hashed_password,
        "salt": request.salt,
        "totp_secret": None,
        "public_key": request.public_key
    }).execute()

    if not response.data:
        raise HTTPException(status_code=400, detail={"status": "error", "message": response.error.message if response.error else "Unknown error"})
    
    user_id = response.data[0]["id"]
    return {"status": "success", "user_id": user_id}

# Get Salts: GET /api/user/{username}/salts
@app.get("/api/user/{username}/salts")
async def get_salts(username: str):
    response = supabase.table("Users").select("salt").eq("username", username).maybe_single().execute()

    if not response.data:
        raise HTTPException(status_code=404, detail={"status": "error", "message": "User not found"})
    
    return {"salt": response.data["salt"]}

# First-Factor Login: POST /api/auth/login/first-factor
class LoginFirstFactorRequest(BaseModel):
    username: str
    hashed_password: str

@app.post("/api/auth/login/first-factor")
async def login_first_factor(request: LoginFirstFactorRequest):
    response = supabase.table("Users").select("id, hashed_password, totp_secret").eq("username", request.username).maybe_single().execute()

    if not response.data or response.data["hashed_password"] != request.hashed_password:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid credentials"})

    temp_session = secrets.token_hex(16)
    totp_required = bool(response.data["totp_secret"])
    return {"temp_session": temp_session, "totp_required": totp_required}

# Second-Factor Login: POST /api/auth/totp/second-factor
class LoginSecondFactorRequest(BaseModel):
    temp_session: str
    totp: str

@app.post("/api/auth/totp/second-factor")
async def login_second_factor(request: LoginSecondFactorRequest):
    if request.totp == "123456":  # Placeholder for TOTP validation
        session_id = secrets.token_hex(16)
        return {"session": session_id}
    raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})

# File Upload: POST /api/files/upload
class FileUploadRequest(BaseModel):
    owner_id: int
    name: str
    size: float
    encrypted_file: str
    integrity_hash: str

@app.post("/api/files/upload")
async def upload_file(request: FileUploadRequest):
    response = supabase.table("Files").insert({
        "owner_id": request.owner_id,
        "name": request.name,
        "size": request.size,
        "encrypted_file": request.encrypted_file,
        "integrity_hash": request.integrity_hash,
        "created_at": datetime.utcnow().isoformat()
    }).execute()

    if not response.data:
        raise HTTPException(status_code=400, detail={"status": "error", "message": response.error.message if response.error else "Unknown error"})

    file_uuid = response.data[0]["file_uuid"]
    return {"status": "success", "file_uuid": file_uuid}

# Share File: POST /api/files/share
class FileShareRequest(BaseModel):
    owner_id: int
    recipient_id: int
    file_id: str
    encrypted_file_key: str
    time_limit: int

@app.post("/api/files/share")
async def share_file(request: FileShareRequest):
    response = supabase.table("Shared").insert({
        "owner_id": request.owner_id,
        "recipient_id": request.recipient_id,
        "file_id": request.file_id,
        "encrypted_file_key": request.encrypted_file_key,
        "shared_at": datetime.utcnow().isoformat(),
        "time_limit": request.time_limit
    }).execute()

    if not response.data:
        raise HTTPException(status_code=400, detail={"status": "error", "message": response.error.message if response.error else "Unknown error"})

    shared_id = response.data[0]["shared_id"]
    return {"status": "success", "shared_id": shared_id}

# List Files: GET /api/files
@app.get("/api/files")
async def list_files(user_id: int):
    # Owned files
    owned_response = supabase.table("Files").select("file_uuid, name, size, created_at, integrity_hash").eq("owner_id", user_id).execute()

    # Shared files
    shared_response = supabase.table("Shared").select("Files(file_uuid, name, size, created_at, integrity_hash), encrypted_file_key").eq("recipient_id", user_id).execute()

    if not owned_response.data or not shared_response.data:
        if owned_response.error or shared_response.error:
            raise HTTPException(status_code=400, detail={"status": "error", "message": owned_response.error.message or shared_response.error.message})

    return {"owned": owned_response.data, "shared": shared_response.data}

# Start server with SSL/TLS
if __name__ == "__main__":
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    uvicorn.run(app, host="0.0.0.0", port=443, ssl=ssl_context)