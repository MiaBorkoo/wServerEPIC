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
from .session import supabase # Use relative import for the supabase client

# User-related CRUD functions

def store_user(username: str, auth_salt: str, enc_salt: str, auth_key: str, encrypted_mek: str) -> dict:
    # TODO: Consider returning the created user object or ID
# *** Password hashing section start, keep
    return()
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
        "totp_secret": secrets.token_urlsafe(32),  # Placeholder TOTP secret. TODO: Generate and store this securely.
        "created_at": datetime.now().isoformat()
    }).execute()
    if not response.data or hasattr(response, 'error') and response.error:
        raise Exception(f"Failed to store user: {response.error.message if hasattr(response, 'error') and response.error else 'Unknown error'}")
    return response.data[0]

def get_user_salts(username: str) -> dict | None:
    response = supabase.table("Users").select("auth_salt, enc_salt").eq("username", username).maybe_single().execute()
    if not response.data:
        return None
    return {"auth_salt": response.data["auth_salt"], "enc_salt": response.data["enc_salt"]}

def verify_user_auth(username: str, auth_key: str) -> bool:
    # TODO: This function should ideally return the user object upon success or raise specific exceptions for auth failure.
    response = supabase.table("Users").select("auth_key").eq("username", username).maybe_single().execute()
    return bool(response.data and response.data["auth_key"] == auth_key)

def get_encrypted_mek(username: str) -> str:
    response = supabase.table("Users").select("encrypted_mek").eq("username", username).maybe_single().execute()
    if not response.data:
        raise Exception("User not found") # TODO: Use custom exceptions (e.g., UserNotFoundException)
    return response.data["encrypted_mek"]

def update_user_password(username: str, new_auth_key: str, new_encrypted_mek: str) -> dict:
    # TODO: Consider what this function should return. A simple status or the updated user?
    response = supabase.table("Users").update({
        "auth_key": new_auth_key,
        "encrypted_mek": new_encrypted_mek,
    }).eq("username", username).execute()
    if not response.data or hasattr(response, 'error') and response.error:
        raise Exception(f"Failed to update password: {response.error.message if hasattr(response, 'error') and response.error else 'Unknown error'}") # TODO: Use custom exceptions
    return response.data[0]

# File-related CRUD functions

def create_file(owner_id: int, name: str, size: float, encrypted_file: str, integrity_hash: str) -> dict:
    # TODO: owner_id will likely change to user_uuid or similar from session/token
    response = supabase.table("Files").insert({
        "owner_id": owner_id,
        "name": name,
        "size": size,
        "encrypted_file": encrypted_file, # TODO: Consider storing file metadata separately from blob/content if files are large
        "integrity_hash": integrity_hash,
        "created_at": datetime.now().isoformat()
    }).execute()
    if not response.data or hasattr(response, 'error') and response.error:
        raise Exception(f"Failed to create file: {response.error.message if hasattr(response, 'error') and response.error else 'Unknown error'}")
    return response.data[0]

def create_shared_file(owner_id: int, recipient_id: int, file_id: str, encrypted_file_key: str, time_limit: int) -> dict:
    # TODO: owner_id and recipient_id will likely change based on user identification from session/token
    response = supabase.table("Shared").insert({
        "owner_id": owner_id,
        "recipient_id": recipient_id,
        "file_id": file_id,
        "encrypted_file_key": encrypted_file_key,
        "shared_at": datetime.now().isoformat(),
        "time_limit": time_limit # TODO: Implement logic to handle time_limit expiration
    }).execute()
    if not response.data or hasattr(response, 'error') and response.error:
        raise Exception(f"Failed to share file: {response.error.message if hasattr(response, 'error') and response.error else 'Unknown error'}")
    return response.data[0]

def get_user_files(user_id: int) -> tuple[list, list]:
    # TODO: user_id will likely change. Implement pagination for large file lists.
    owned_response = supabase.table("Files").select("file_uuid, name, size, created_at, integrity_hash").eq("owner_id", user_id).execute()
    # TODO: Ensure the join with Files table is efficient and correct for shared files
    shared_response = supabase.table("Shared").select("Files(file_uuid, name, size, created_at, integrity_hash), encrypted_file_key").eq("recipient_id", user_id).execute()
    return owned_response.data if owned_response.data else [], shared_response.data if shared_response.data else [] 