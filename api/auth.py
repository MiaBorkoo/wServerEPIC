from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from database import store_user, get_user_salts, verify_user_auth, get_encrypted_mek, update_user_password
from totp import verify_totp
from session import SessionManager
from rate_limiter import RateLimiter
from typing import Optional
import os

router = APIRouter()

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
session_manager = SessionManager(redis_url)
rate_limiter = RateLimiter(redis_url)

# Registration
class RegisterRequest(BaseModel):
    username: str
    auth_salt: str
    enc_salt: str
    auth_key: str
    encrypted_mek: str

@router.post("/api/auth/register")
def register_user(data: RegisterRequest, request: Request):
    # Rate limit by IP address
    client_ip = request.client.host
    if rate_limiter.is_rate_limited(client_ip, "register"):
        remaining = rate_limiter.get_remaining_attempts(client_ip, "register")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too many registration attempts",
                "reset_in": remaining["reset_in"],
                "retry_after": remaining["reset_in"]
            }
        )
    
    try:
        store_user(data.username, data.auth_salt, data.enc_salt, data.auth_key, data.encrypted_mek)
        return {"status": "success"}
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
def login(data: LoginRequest, request: Request):
    # Rate limit by both IP and username
    client_ip = request.client.host
    if rate_limiter.is_rate_limited(client_ip, "login") or rate_limiter.is_rate_limited(data.username, "login"):
        remaining = rate_limiter.get_remaining_attempts(client_ip, "login")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too many login attempts",
                "reset_in": remaining["reset_in"],
                "retry_after": remaining["reset_in"]
            }
        )
    
    if not verify_user_auth(data.username, data.auth_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create initial session with 2FA pending status
    session_token = session_manager.create_session(
        data.username,
        {"status": "2fa_pending", "totp_required": True}
    )
    
    return {"session": session_token, "totp_required": True}

# TOTP (Second Factor)
class TOTPRequest(BaseModel):
    username: str
    totp_code: str
    session_token: str

@router.post("/api/auth/totp")
def verify_totp_and_return_mek(data: TOTPRequest, request: Request):
    # Rate limit by username for TOTP attempts
    if rate_limiter.is_rate_limited(data.username, "totp"):
        remaining = rate_limiter.get_remaining_attempts(data.username, "totp")
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too many TOTP attempts",
                "reset_in": remaining["reset_in"],
                "retry_after": remaining["reset_in"]
            }
        )
    
    # Verify session exists and is in 2FA pending state
    session = session_manager.get_session(data.session_token)
    if not session or session["username"] != data.username or session["data"].get("status") != "2fa_pending":
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    if not verify_totp(data.username, data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")

    mek = get_encrypted_mek(data.username)
    
    # Create new fully authenticated session
    new_session_token = session_manager.create_session(
        data.username,
        {"status": "authenticated", "totp_verified": True}
    )
    
    # Delete the old 2FA pending session
    session_manager.delete_session(data.session_token)
    
    return {"session": new_session_token, "encrypted_mek": mek}

# Password Change
class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str
    session_token: str

@router.post("/api/auth/change_password")
def change_password(data: ChangePasswordRequest):
    # Verify session is authenticated
    session = session_manager.get_session(data.session_token)
    if not session or session["username"] != data.username or session["data"].get("status") != "authenticated":
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    if not verify_user_auth(data.username, data.old_auth_key):
        raise HTTPException(status_code=401, detail="Invalid old credentials")
    
    if not verify_totp(data.username, data.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    
    try:
        update_user_password(data.username, data.new_auth_key, data.new_encrypted_mek)
        # Invalidate all existing sessions for the user
        session_manager.invalidate_user_sessions(data.username)
        # Create new session
        new_session_token = session_manager.create_session(
            data.username,
            {"status": "authenticated", "totp_verified": True}
        )
        return {"status": "ok", "session": new_session_token}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/auth/logout")
def logout(session_token: str):
    if session_manager.delete_session(session_token):
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid or expired session")