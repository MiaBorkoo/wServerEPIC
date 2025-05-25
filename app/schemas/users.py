from pydantic import BaseModel
from typing import Dict, Any, Optional

class RegisterRequest(BaseModel):
    username: str
    auth_salt: str
    enc_salt: str
    auth_key: str
    encrypted_mek: str
    totp_secret: str
    public_key: Dict[str, Any]
    user_data_hmac: str

class LoginRequest(BaseModel):
    username: str
    auth_key: str

class TOTPRequest(BaseModel):
    username: str
    totp_code: str

class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str

class UserSaltsResponse(BaseModel):
    auth_salt: str
    enc_salt: str 