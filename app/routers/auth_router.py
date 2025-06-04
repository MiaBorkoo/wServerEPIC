from fastapi import APIRouter, HTTPException, Depends, Request
from secrets import token_urlsafe
from sqlalchemy.orm import Session
import json  # ADDED: For JSON serialization
import base64  # ADDED: For bytes to base64 conversion
import os

from app.schemas.users import RegisterRequest, LoginRequest, ChangePasswordRequest, LogoutRequest
from app.db import crud # Assuming crud.py contains all db operations
from app.db.database import get_db  
from app.services.totp_service import new_secret, provisioning_uri, verify_totp 
from app.core.security import create_access_token, encrypt_totp_seed, decrypt_totp_seed  # ADDED: For proper JWT token generation
from app.core.jwt_session_manager import JWTSessionManager  # NEW: JWT-based session management
from app.core.memory_rate_limiter import MemoryRateLimiter  # NEW: Memory-only rate limiting
from app.core.exceptions import handle_database_error, handle_authentication_error, handle_validation_error, SecureHTTPException

router = APIRouter()

session_manager = JWTSessionManager()
rate_limiter = MemoryRateLimiter()

@router.post("/register")
def register_user(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    # Rate limit by IP address
    client_ip = request.client.host
    if rate_limiter.is_rate_limited(client_ip, "register"):
        raise SecureHTTPException(
            status_code=429,
            detail="Too many registration attempts. Please try again later.",
            internal_detail=f"Rate limit exceeded for IP {client_ip}"
        )

    try:
        # Check if user already exists - ADDED validation per REQ-AUTH-003
        existing_user = crud.get_user_by_username(db, data.username)
        if existing_user:
            raise SecureHTTPException(
                status_code=400, 
                detail="Registration failed",
                internal_detail=f"Username {data.username} already exists"
            )
        
        # FIXED: Use correct CRUD function with all required parameters per REQ-AUTH-001
        seed  = new_secret()
        user = crud.create_user(
            db=db,
            username=data.username, 
            auth_salt=data.auth_salt,
            enc_salt=data.enc_salt, 
            auth_key=data.auth_key,
            encrypted_mek=data.encrypted_mek,
            totp_secret=encrypt_totp_seed(seed),
            public_key=data.public_key,  # Will be converted to JSON string in CRUD
            user_data_hmac=data.user_data_hmac  # FIXED: Use client-provided HMAC
        )
        
        return {
            "status": "success",
            "user_id": str(user.user_id),                    # client stores this
            "otpauth_uri": provisioning_uri(seed, data.username),
            "message": "Please scan the QR code or manually enter the secret from your authenticator app"
        } # Return user ID
    except Exception as e:
        raise handle_database_error(e)

@router.post("/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    # Rate limit by both IP and username
    client_ip = request.client.host
    if rate_limiter.is_rate_limited(client_ip, "login") or rate_limiter.is_rate_limited(data.username, "login"):
        raise SecureHTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later.",
            internal_detail=f"Rate limit exceeded for {client_ip} or {data.username}"
        )

    user = crud.get_user_by_username(db, data.username)
    if not user or not crud.verify_user_auth(db, data.username, data.auth_key):
        raise handle_authentication_error(Exception("Invalid credentials"))
    
    if rate_limiter.is_rate_limited(data.username, "totp"):
        raise SecureHTTPException(
            status_code=429,
            detail="Too many TOTP attempts. Please try again later.",
            internal_detail=f"TOTP rate limit exceeded for {data.username}"
        )
    
    # TOTP verification
    if not verify_totp(db, data.username, data.otp):
        raise handle_authentication_error(Exception("Invalid or replayed TOTP"))
    
    # Create JWT session tokens
    tokens = session_manager.create_session(
        data.username,
        {"status": "authenticated", "user_id": str(user.user_id)}
    )
    
    # Get encrypted MEK
    mek_bytes = crud.get_encrypted_mek(db, data.username)
    if not mek_bytes:
        raise handle_database_error(Exception("Encrypted MEK not found"))
    encrypted_mek = base64.b64encode(mek_bytes).decode()
    
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": tokens["token_type"],
        "expires_in": tokens["expires_in"],
        "encrypted_mek": encrypted_mek
    }

@router.post("/refresh")
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    new_tokens = session_manager.refresh_session(refresh_token)
    if not new_tokens:
        raise handle_authentication_error(Exception("Invalid or expired refresh token"))
    
    return new_tokens

@router.post("/logout")
async def logout(data: LogoutRequest):
    """Logout user by revoking access token"""
    # For JWT logout, we add the token to a revoked list
    if session_manager.delete_session(data.session_token):
        return {"status": "success", "message": "Logged out successfully"}
    raise handle_authentication_error(Exception("Invalid or expired session"))

@router.post("/change_password")
async def change_password(data: ChangePasswordRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # Verify JWT session is authenticated
    session = session_manager.get_session(data.session_token)
    if not session or session["username"] != data.username or session["data"].get("status") != "authenticated":
        raise handle_authentication_error(Exception("Invalid or expired session"))

    if not crud.verify_user_auth(db, data.username, data.old_auth_key):  # FIXED: Pass db session
        raise handle_authentication_error(Exception("Invalid old credentials"))

    if not verify_totp(db, data.username, data.totp_code):
        raise handle_authentication_error(Exception("Invalid TOTP"))

    try:
        # TODO: for @ruan
        # Change salts with password change for additional security
        # This requires schema changes to add new_auth_salt and new_enc_salt to ChangePasswordRequest
        # and updating the database schema accordingly??? i think??
        
        # Update password and encrypted MEK
        crud.update_user_password(db, data.username, data.new_auth_key, data.new_encrypted_mek)
        
        # Revoke current session (user needs to login again with new password)
        session_manager.delete_session(data.session_token)
        
        return {"status": "success", "message": "Password changed successfully. Please login again."}
    except Exception as e:
        raise handle_database_error(e)

