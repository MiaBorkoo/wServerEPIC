def verify_totp(username: str, totp_code: str) -> bool:
    # Placeholder: Replace with actual TOTP verification (e.g., using pyotp with totp_secret from database)
    return totp_code == "123456"