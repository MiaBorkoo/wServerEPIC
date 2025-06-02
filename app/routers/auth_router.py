from fastapi import APIRouter, HTTPException, Depends, Request
from secrets import token_urlsafe
from sqlalchemy.orm import Session
import json  # ADDED: For JSON serialization
import base64  # ADDED: For bytes to base64 conversion
import os

from app.schemas.users import RegisterRequest, LoginRequest, ChangePasswordRequest, LogoutRequest
from app.db import crud # Assuming crud.py contains all db operations
from app.db.database import get_db  # ADDED: Missing database dependency
from app.services.totp_service import new_secret, provisioning_uri, verify_totp 
from app.core.security import create_access_token, encrypt_totp_seed, decrypt_totp_seed  # ADDED: For proper JWT token generation
from app.core.rate_limiter import RateLimiter
from app.core.session_manager import SessionManager

router = APIRouter()

# Initialize Redis-based services
redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
session_manager = SessionManager(redis_url)
rate_limiter = RateLimiter(redis_url)

@router.post("/register")
def register_user(data: RegisterRequest, request: Request, db: Session = Depends(get_db)):
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
        # Check if user already exists - ADDED validation per REQ-AUTH-003
        existing_user = crud.get_user_by_username(db, data.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
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
            "user_id": str(user.user_id),
            "totp_secret": seed,                       # client stores this
            "otpauth_uri": provisioning_uri(seed, data.username)
        } # Return user IDeturn user ID
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


#I'm gonna write the totp into the login route and comment out /totp route - seems like a better approach?
@router.post("/login")
def login(data: LoginRequest, request: Request, db: Session = Depends(get_db)):
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

    user = crud.get_user_by_username(db, data.username)
    if not user or not crud.verify_user_auth(db, data.username, data.auth_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
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
    
    # TOTP verification
    if not verify_totp(db, data.username, data.otp):
        raise HTTPException(401, "Invalid or replayed TOTP")
    
    # Create authenticated session
    session_token = session_manager.create_session(
        data.username,
        {"status": "authenticated", "user_id": str(user.user_id)}
    )
    
    # Get encrypted MEK
    mek_bytes = crud.get_encrypted_mek(db, data.username)
    if not mek_bytes:
        raise HTTPException(500, "Encrypted MEK not found")
    encrypted_mek = base64.b64encode(mek_bytes).decode()
    
    return {"session_token": session_token, "encrypted_mek": encrypted_mek}

# @router.post("/totp")
# def verify_totp_and_return_mek(data: TOTPRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
#     # TODO: Validate session from login before allowing TOTP verification.
#     if not verify_totp(db,data.username, data.totp_code): # Placeholder
#         raise HTTPException(status_code=401, detail="Invalid TOTP")
    
#     # TODO: Ensure that a valid session/state exists from the initial login step.
#     user = crud.get_user_by_username(db, data.username)
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")
        
#     mek_bytes = crud.get_encrypted_mek(db, data.username)  # FIXED: Pass db session
    
#     # Convert bytes to base64 string for JSON serialization - FIXED encoding issue
#     if mek_bytes:
#         encrypted_mek = base64.b64encode(mek_bytes).decode('utf-8')
#     else:
#         # Placeholder for when user doesn't exist or no MEK found
#         encrypted_mek = "placeholder_encrypted_mek_not_implemented"
    
#     # Generate proper JWT session token - FIXED: Use JWT instead of random token
#     session_token = create_access_token(data={"sub": str(user.user_id)})
    
#     # TODO: Store this new session_token, perhaps replacing the previous one.
#     return {"session_token": session_token, "encrypted_mek": encrypted_mek}

@router.post("/logout")
async def logout(data: LogoutRequest):
    """Logout user by invalidating session"""
    if session_manager.delete_session(data.session_token):
        return {"status": "success"}
    raise HTTPException(status_code=401, detail="Invalid or expired session")

@router.post("/change_password")
async def change_password(data: ChangePasswordRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # Verify session is authenticated
    session = session_manager.get_session(data.session_token)
    if not session or session["username"] != data.username or session["data"].get("status") != "authenticated":
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    if not crud.verify_user_auth(db, data.username, data.old_auth_key):  # FIXED: Pass db session
        raise HTTPException(status_code=401, detail="Invalid old credentials")

    if not verify_totp(db, data.username, data.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail="Invalid TOTP")

    try:
        # TODO: Invalidate old sessions/tokens after password change.
        crud.update_user_password(db, data.username, data.new_auth_key, data.new_encrypted_mek)  # FIXED: Pass db session
        
        # Invalidate all existing sessions for the user
        session_manager.invalidate_user_sessions(data.username)
        
        # Create new session
        new_session_token = session_manager.create_session(
            data.username,
            {"status": "authenticated", "totp_verified": True}
        )
        
        return {"status": "success", "session": new_session_token} # Placeholder: new session token
    except Exception as e:
        # TODO: More specific error handling.
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)}) 