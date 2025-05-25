from fastapi import APIRouter, HTTPException, Depends
from secrets import token_urlsafe
from sqlalchemy.orm import Session

from app.schemas.users import RegisterRequest, LoginRequest, TOTPRequest, ChangePasswordRequest, UserSaltsResponse
from app.db import crud # Assuming crud.py contains all db operations
from app.db.database import get_db  # ADDED: Missing database dependency
from app.services.totp_service import verify_totp # Placeholder for actual TOTP verification
import json  # ADDED: For JSON serialization

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
            totp_secret=data.totp_secret,
            public_key=data.public_key,  # Will be converted to JSON string in CRUD
            user_data_hmac=data.user_data_hmac  # FIXED: Use client-provided HMAC
        )
        return {"status": "ok", "user_id": str(user.user_id)} # Return user ID
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{username}/salts", response_model=UserSaltsResponse)
def get_salts(username: str, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    salts = crud.get_user_salts(db, username)  # FIXED: Pass db session
    if not salts:
        raise HTTPException(status_code=404, detail="User not found")
    return salts

@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # TODO: Implement proper session management. This is a placeholder.
    if not crud.verify_user_auth(db, data.username, data.auth_key):  # FIXED: Pass db session
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_token = token_urlsafe(32) 
    # TODO: Store session_token associated with the user and manage its lifecycle.
    # TODO: Determine if TOTP is actually required for the user.
    return {"session_token": session_token, "totp_required": True} # Placeholder

@router.post("/totp")
def verify_totp_and_return_mek(data: TOTPRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # TODO: Validate session from login before allowing TOTP verification.
    if not verify_totp(data.username, data.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    
    # TODO: Ensure that a valid session/state exists from the initial login step.
    mek = crud.get_encrypted_mek(db, data.username)  # FIXED: Pass db session
    session_token = token_urlsafe(64) # This should be a new, authenticated session token
    # TODO: Store this new session_token, perhaps replacing the previous one.
    return {"session_token": session_token, "encrypted_mek": mek}

@router.post("/change_password")
async def change_password(request: ChangePasswordRequest, db: Session = Depends(get_db)):  # ADDED: Database session dependency
    # TODO: Validate session before allowing password change.
    if not crud.verify_user_auth(db, request.username, request.old_auth_key):  # FIXED: Pass db session
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid old credentials"})

    # TODO: Ensure this TOTP verification is tied to an active, pre-verified session state.
    if not verify_totp(request.username, request.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})

    try:
        # TODO: Invalidate old sessions/tokens after password change.
        crud.update_user_password(db, request.username, request.new_auth_key, request.new_encrypted_mek)  # FIXED: Pass db session
        # TODO: Return a new session token.
        return {"status": "ok", "session_token": token_urlsafe(64)} # Placeholder: new session token
    except Exception as e:
        # TODO: More specific error handling.
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)}) 