from fastapi import APIRouter, HTTPException
from secrets import token_urlsafe

from app.schemas.users import RegisterRequest, LoginRequest, TOTPRequest, ChangePasswordRequest, UserSaltsResponse
from app.db import crud # Assuming crud.py contains all db operations
from app.services.totp_service import verify_totp # Placeholder for actual TOTP verification

router = APIRouter()

@router.post("/register")
def register_user(data: RegisterRequest):
    try:
        # TODO: Add more robust error handling and user existence checks
        user = crud.store_user(data.username, data.auth_salt, data.enc_salt, data.auth_key, data.encrypted_mek)
        return {"status": "ok", "user_id": user.get("id")} # Example: return user ID or other relevant data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{username}/salts", response_model=UserSaltsResponse)
def get_salts(username: str):
    salts = crud.get_user_salts(username)
    if not salts:
        raise HTTPException(status_code=404, detail="User not found")
    return salts

@router.post("/login")
def login(data: LoginRequest):
    # TODO: Implement proper session management. This is a placeholder.
    if not crud.verify_user_auth(data.username, data.auth_key):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_token = token_urlsafe(32) 
    # TODO: Store session_token associated with the user and manage its lifecycle.
    # TODO: Determine if TOTP is actually required for the user.
    return {"session_token": session_token, "totp_required": True} # Placeholder

@router.post("/totp")
def verify_totp_and_return_mek(data: TOTPRequest):
    # TODO: Validate session from login before allowing TOTP verification.
    if not verify_totp(data.username, data.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail="Invalid TOTP")
    
    # TODO: Ensure that a valid session/state exists from the initial login step.
    mek = crud.get_encrypted_mek(data.username)
    session_token = token_urlsafe(64) # This should be a new, authenticated session token
    # TODO: Store this new session_token, perhaps replacing the previous one.
    return {"session_token": session_token, "encrypted_mek": mek}

@router.post("/change_password")
async def change_password(request: ChangePasswordRequest):
    # TODO: Validate session before allowing password change.
    if not crud.verify_user_auth(request.username, request.old_auth_key):
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid old credentials"})

    # TODO: Ensure this TOTP verification is tied to an active, pre-verified session state.
    if not verify_totp(request.username, request.totp_code): # Placeholder
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Invalid TOTP"})

    try:
        # TODO: Invalidate old sessions/tokens after password change.
        crud.update_user_password(request.username, request.new_auth_key, request.new_encrypted_mek)
        # TODO: Return a new session token.
        return {"status": "ok", "session_token": token_urlsafe(64)} # Placeholder: new session token
    except Exception as e:
        # TODO: More specific error handling.
        raise HTTPException(status_code=500, detail={"status": "error", "message": str(e)}) 