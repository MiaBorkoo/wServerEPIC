import pyotp
from database import get_user_totp_secret

def generate_totp_secret() -> str:
    """Generate a new TOTP secret key"""
    return pyotp.random_base32()

def verify_totp(username: str, totp_code: str) -> bool:
    """Verify a TOTP code for a user"""
    secret = get_user_totp_secret(username)
    if not secret:
        return False
    
    totp = pyotp.TOTP(secret)
    return totp.verify(totp_code)

def get_totp_uri(username: str, secret: str) -> str:
    """Get the TOTP URI for QR code generation"""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="EPIC Secure File Share"
    )