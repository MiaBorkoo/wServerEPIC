from fastapi import APIRouter, HTTPException, Depends, Request
from secrets import token_urlsafe
from sqlalchemy.orm import Session
import json  # ADDED: For JSON serialization
import base64  # ADDED: For bytes to base64 conversion

from app.schemas.users import RegisterRequest, LoginRequest, ChangePasswordRequest
from app.db import crud # Assuming crud.py contains all db operations
from app.db.database import get_db  # ADDED: Missing database dependency
from app.services.totp_service import verify_totp # Placeholder for actual TOTP verification
from app.core.security import create_access_token, encrypt_totp_secret  # ADDED: For proper JWT token generation

router = APIRouter()

@router.post("/register")
def register_user(data: RegisterRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    try:
        # Check if user already exists - ADDED validation per REQ-AUTH-003
        existing_user = crud.get_user_by_username(db, data.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        
        # FIXED: Use correct CRUD function with all required parameters per REQ-AUTH-001
        user = crud.create_user(
            db=db,
            username=data.username, 
            auth_salt=data.auth_salt,
            enc_salt=data.enc_salt, 
            auth_key=data.auth_key,
            encrypted_mek=data.encrypted_mek,
            totp_secret=encrypt_totp_secret(data.totp_secret),
            public_key=data.public_key,  # Will be converted to JSON string in CRUD
            user_data_hmac=data.user_data_hmac  # FIXED: Use client-provided HMAC
        )
        return {"status": "ok", "user_id": str(user.user_id)} # Return user ID
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


#I'm gonna write the totp into the login route and comment out /totp route - seems like a better approach?
@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # TODO: Implement proper session management. This is a placeholder.
    user = crud.get_user_by_username(db, data.username)
    if not user or not crud.verify_user_auth(db, data.username, data.auth_key):  # FIXED: Pass db session
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    #TOTP verification
    if not verify_totp(db, data.username, data.otp):
        raise HTTPException(401, "Invalid or replayed TOTP")
    
    # 3) return encrypted MEK (same payload /totp used to send)
    mek_bytes = crud.get_encrypted_mek(db, data.username)
    if not mek_bytes:
        raise HTTPException(500, "Encrypted MEK not found")
    encrypted_mek = base64.b64encode(mek_bytes).decode()

    
    token = create_access_token(data={"sub": str(user.user_id)})

    
    # TODO: Store session_token associated with the user and manage its lifecycle.
    # TODO: Determine if TOTP is actually required for the user.
    return {"session_token": token, "encrypted_mek": encrypted_mek} # Placeholder

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
async def logout():
    """Logout user by invalidating session token"""
    # Note: For JWT tokens, logout is primarily handled client-side by discarding the token
    # TODO: In production, consider implementing a token blacklist for enhanced security
    return {"status": "success", "message": "Logged out successfully"}

@router.post("/change_password")
async def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # TODO: Validate session before allowing password change.
    if not crud.verify_user_auth(db, request.username, request.old_auth_key):  # FIXED: Pass db session
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid old credentials"})

    # TODO: Ensure this TOTP verification is tied to an active, pre-verified session state.
    if not verify_totp(db,request.username, request.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})

    try:
        # TODO: Invalidate old sessions/tokens after password change.
        crud.update_user_password(db, request.username, request.new_auth_key, request.new_encrypted_mek)  # FIXED: Pass db session
        
        # Generate new JWT session token after password change - FIXED: Use JWT
        user = crud.get_user_by_username(db, request.username)
        new_session_token = create_access_token(data={"sub": str(user.user_id)})
        
        # TODO: Return a new session token.
        return {"status": "ok", "session_token": new_session_token} # Placeholder: new session token
    except Exception as e:
        # TODO: More specific error handling.
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)}) 