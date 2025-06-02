import pyotp
import logging

logger = logging.getLogger(__name__)

def verify_totp(username: str, totp_code: str) -> bool:
    try:
        # Placeholder: In production, retrieve totp_secret from database
        totp_secret = "JBSWY3DPEHPK3PXP"  # Example base32 secret
        totp = pyotp.TOTP(totp_secret)
        result = totp.verify(totp_code)
        logger.info(f"TOTP verification for {username}: {'success' if result else 'failed'}")
        return result
    except Exception as e:
        logger.error(f"TOTP verification error for {username}: {str(e)}")
        return False