from pydantic import BaseModel, Field
from typing import Dict, Any

class RegisterRequest(BaseModel):
    username: str
    auth_salt: str
    auth_salt_2: str
    enc_salt: str
    auth_key: str
    encrypted_mek: str
    # totp_secret: str
    public_key: Dict[str, Any]
    user_data_hmac: str

class LoginRequest(BaseModel):
    username: str
    auth_key: str
    otp: str = Field(pattern=r"^[0-9]{6}$")

class ChangePasswordRequest(BaseModel):
    username: str
    old_auth_key: str
    new_auth_key: str
    new_encrypted_mek: str
    totp_code: str
    session_token: str

class LogoutRequest(BaseModel):
    session_token: str

class UserSaltsResponse(BaseModel):
    auth_salt: str
    auth_salt_2: str
    enc_salt: str 