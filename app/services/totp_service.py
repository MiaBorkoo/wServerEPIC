import time, pyotp
from typing import Final
from sqlalchemy.orm import Session
from app.db import models
from app.core.security import decrypt_totp_seed

_STEP: Final[int] = 30      # RFC default
_DIGITS: Final[int] = 6
_WINDOW: Final[int] = 1     # ±30 s drift

def verify_totp(db: Session, username: str, code: str) -> bool:
    """Return True if OTP is valid and not replayed."""
    if not (code.isdigit() and len(code) == _DIGITS):
        return False

    user = db.query(models.User).filter_by(username=username).first()
    if not user:
        return False

    # Decrypt the stored TOTP secret
    secret = decrypt_totp_seed(user.totp_secret) \
             if isinstance(user.totp_secret, (bytes, bytearray)) \
             else user.totp_secret

    totp = pyotp.TOTP(secret, interval=_STEP, digits=_DIGITS)

    # verify against current / previous / next step
    if not totp.verify(code, valid_window=_WINDOW):
        return False

    # Check for replay attacks using the counter
    current_counter = int(time.time())
    if user.totp_last_counter and current_counter <= user.totp_last_counter:
        return False          # replay within window

    # Update the last used counter
    user.totp_last_counter = current_counter
    db.commit()
    return True

def new_secret() -> str:
    """Generate a new TOTP secret key"""
    return pyotp.random_base32()          # 160-bit seed

def provisioning_uri(secret: str, user: str, issuer="EPIC-App") -> str:
    """Get the TOTP URI for QR code generation"""
    return pyotp.TOTP(secret, interval=_STEP, digits=_DIGITS) \
               .provisioning_uri(name=user, issuer_name=issuer)