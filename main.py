from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from api.auth import router as auth_router
from database import create_file, create_shared_file, get_user_files

# FastAPI app
app = FastAPI(title="EPIC Server", description="Server for CS4455 Epic Project")

# Mount authentication routes
app.include_router(auth_router)

# API Endpoints

# Root endpoint (placeholder)
@app.get("/")
async def root():
    return {"message": "EPIC Server is running with Supabase."}

# File Upload: POST /api/files/upload
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

# Share File: POST /api/files/share
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

# List Files: GET /api/files
@app.get("/api/files")
async def list_files(user_id: int):
    try:
        owned_files, shared_files = get_user_files(user_id)
        return {"owned": owned_files, "shared": shared_files}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"status": "error", "message": str(e)})

# Start server with SSL/TLS
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=443,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem"
    )