from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from database import store_user, get_user_salts, verify_user_auth, get_encrypted_mek, update_user_password
from totp import verify_totp
from secrets import token_urlsafe

router = APIRouter()

# Registration
class RegisterRequest(BaseModel):
    username: str
    auth_salt: str
    enc_salt: str
    auth_key: str
    encrypted_mek: str

@router.post("/api/auth/register")
def register_user(data: RegisterRequest):
    try:
        store_user(data.username, data.auth_salt, data.enc_salt, data.auth_key, data.encrypted_mek)
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Get Salts
@router.get("/api/user/{username}/salts")
def get_salts(username: str):
    salts = get_user_salts(username)
    if not salts:
        raise HTTPException(status_code=404, detail="User not found")
    return salts

# Login (First Factor)
class LoginRequest(BaseModel):
    username: str
    auth_key: str

@router.post("/api/auth/login")
def login(data: LoginRequest):
    if not verify_user_auth(data.username, data.auth_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_token = token_urlsafe(32)
    # Store temporary session (in-memory for demo; use Redis in production)
    return {"session": session_token, "totp_required": True}

# TOTP (Second Factor)
class TOTPRequest(BaseModel):
    username: str
    totp_code: str

@router.post("/api/auth/totp")
def verify_totp_and_return_mek(data: TOTPRequest):
    if not verify_totp(data.username, data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    mek = get_encrypted_mek(data.username)
    session_token = token_urlsafe(64)
    return {"session": session_token, "encrypted_mek": mek}

# Password Change
class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str

@router.post("/api/auth/change_password")
def change_password(data: ChangePasswordRequest):
    if not verify_user_auth(data.username, data.old_auth_key):
        raise HTTPException(status_code=401, detail="Invalid old credentials")
    if not verify_totp(data.username, data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    # Update user data (client should derive new keys and re-encrypt MEK)
    try:
        update_user_password(data.username, data.new_auth_key, data.new_encrypted_mek)
        return {"status": "ok", "session": token_urlsafe(64)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))