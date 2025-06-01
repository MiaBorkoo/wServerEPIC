import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from supabase import create_client, Client
from dotenv import load_dotenv
from datetime import datetime
import secrets
from base64 import b64encode, b64decode
from typing import Optional, List

# Load environment variables
load_dotenv()
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(supabase_url, supabase_key)

# *** Password hashing section start, keep

#RIFC 9106 reccomends 1 iteration, 8 lanes, 4 GiB memory, 128-bit salt
ph = PasswordHasher(
    time_cost=1, memory_cost=4097152, parallelism=8, salt_len=16, hash_len=32
)

# Derive MEK Wrapper using HKDF
def derive_mek_wrapper(client_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"MEK Wrapper"
    )
    return hkdf.derive(client_key)


# *** Section end

# User-related functions

def store_user(username: str, auth_salt: str, enc_salt: str, auth_key: str, encrypted_mek: str) -> None:
    response = supabase.table("Users").insert({
        "username": username,
        "auth_salt": auth_salt,
        "enc_salt": enc_salt,
        "auth_key": auth_key,
        "encrypted_mek": encrypted_mek,
        "totp_secret": secrets.token_urlsafe(32),  # Placeholder TOTP secret
        "created_at": datetime.now().isoformat()
    }).execute()
    if not response.data:
        raise Exception(f"Failed to store user: {response.error.message if response.error else 'Unknown error'}")

def get_user_salts(username: str) -> dict:
    response = supabase.table("Users").select("auth_salt, enc_salt").eq("username", username).maybe_single().execute()
    if not response.data:
        return None
    return {"auth_salt": response.data["auth_salt"], "enc_salt": response.data["enc_salt"]}

def verify_user_auth(username: str, auth_key: str) -> bool:
    response = supabase.table("Users").select("auth_key").eq("username", username).maybe_single().execute()
    return bool(response.data and response.data["auth_key"] == auth_key)

def get_encrypted_mek(username: str) -> str:
    response = supabase.table("Users").select("encrypted_mek").eq("username", username).maybe_single().execute()
    if not response.data:
        raise Exception("User not found")
    return response.data["encrypted_mek"]

def update_user_password(username: str, new_auth_key: str, new_encrypted_mek: str) -> None:
    response = supabase.table("Users").update({
        "auth_key": new_auth_key,
        "encrypted_mek": new_encrypted_mek,
    }).eq("username", username).execute()
    if not response.data:
        raise Exception("Failed to update password")

# File-related functions

def create_file(owner_id: int, name: str, size: float, encrypted_file: str, integrity_hash: str) -> dict:
    response = supabase.table("Files").insert({
        "owner_id": owner_id,
        "name": name,
        "size": size,
        "encrypted_file": encrypted_file,
        "integrity_hash": integrity_hash,
        "created_at": datetime.now().isoformat()
    }).execute()
    if not response.data:
        raise Exception(f"Failed to create file: {response.error.message if response.error else 'Unknown error'}")
    return response.data[0]

def create_shared_file(owner_id: int, recipient_id: int, file_id: str, encrypted_file_key: str, time_limit: int) -> dict:
    response = supabase.table("Shared").insert({
        "owner_id": owner_id,
        "recipient_id": recipient_id,
        "file_id": file_id,
        "encrypted_file_key": encrypted_file_key,
        "shared_at": datetime.now().isoformat(),
        "time_limit": time_limit
    }).execute()
    if not response.data:
        raise Exception(f"Failed to share file: {response.error.message if response.error else 'Unknown error'}")
    return response.data[0]

def get_user_files(user_id: int) -> tuple:
    owned_response = supabase.table("Files").select("file_uuid, name, size, created_at, integrity_hash").eq("owner_id", user_id).execute()
    shared_response = supabase.table("Shared").select("Files(file_uuid, name, size, created_at, integrity_hash), encrypted_file_key").eq("recipient_id", user_id).execute()
    return owned_response.data, shared_response.data

# TOFU-related database functions


def store_device_certificate(username: str, device_id: str, public_key: bytes, expires_at: datetime, signature: bytes) -> dict:
    """Store a new device certificate."""
    response = supabase.table("device_certificates").insert({
        "username": username,
        "device_id": device_id,
        "public_key": public_key.hex(),
        "expires_at": expires_at.isoformat(),
        "signature": signature.hex()
    }).execute()
    
    if not response.data:
        raise Exception("Failed to store device certificate")
    return response.data[0]

def get_device_certificate(username: str, device_id: str) -> Optional[dict]:
    """Get a device certificate."""
    response = supabase.table("device_certificates").select("*")\
        .eq("username", username)\
        .eq("device_id", device_id)\
        .maybe_single()\
        .execute()
    
    if not response.data:
        return None
    
    cert = response.data
    cert["public_key"] = bytes.fromhex(cert["public_key"])
    cert["signature"] = bytes.fromhex(cert["signature"])
    return cert

def get_user_certificates(username: str) -> List[dict]:
    """Get all certificates for a user."""
    response = supabase.table("device_certificates")\
        .select("*, trust_relationships(trust_level, verification_method, last_verified)")\
        .eq("username", username)\
        .execute()
    
    certs = []
    for cert in response.data:
        cert["public_key"] = bytes.fromhex(cert["public_key"])
        cert["signature"] = bytes.fromhex(cert["signature"])
        certs.append(cert)
    return certs

def store_trust_relationship(username: str, cert_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    """Store a new trust relationship."""
    response = supabase.table("trust_relationships").insert({
        "username": username,
        "trusted_cert_id": cert_id,
        "trust_level": trust_level,
        "verification_method": verification_method
    }).execute()
    
    if not response.data:
        raise Exception("Failed to store trust relationship")
    return response.data[0]

def update_trust_level(trust_id: str, trust_level: str, verification_method: Optional[str] = None) -> dict:
    """Update trust level for a relationship."""
    data = {
        "trust_level": trust_level,
        "last_verified": datetime.now().isoformat()
    }
    if verification_method:
        data["verification_method"] = verification_method
    
    response = supabase.table("trust_relationships").update(data)\
        .eq("trust_id", trust_id)\
        .execute()
    
    if not response.data:
        raise Exception("Failed to update trust level")
    return response.data[0]

def store_verification_event(trust_id: str, event_type: str, method: Optional[str], success: bool, details: Optional[str] = None) -> dict:
    """Store a verification event."""
    response = supabase.table("verification_events").insert({
        "trust_id": trust_id,
        "event_type": event_type,
        "method": method,
        "success": success,
        "details": details
    }).execute()
    
    if not response.data:
        raise Exception("Failed to store verification event")
    return response.data[0]

def get_trust_status(username: str, cert_id: str) -> Optional[dict]:
    """Get trust status for a certificate."""
    response = supabase.table("trust_relationships").select("*")\
        .eq("username", username)\
        .eq("trusted_cert_id", cert_id)\
        .maybe_single()\
        .execute()
    return response.data

def get_verification_history(trust_id: str) -> List[dict]:
    """Get verification history for a trust relationship."""
    response = supabase.table("verification_events").select("*")\
        .eq("trust_id", trust_id)\
        .order("created_at", desc=True)\
        .execute()
    return response.data