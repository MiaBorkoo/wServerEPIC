from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2 import PasswordHasher

# Password hashing configuration
ph = PasswordHasher(time_cost=1, memory_cost=4097152, parallelism=8, salt_len=16, hash_len=32)

def derive_mek_wrapper(client_key: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"MEK Wrapper"
    )
    return hkdf.derive(client_key)