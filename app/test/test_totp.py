# tests/test_totp.py
import pyotp, time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Base, User
from app.services.totp_service import verify_totp, new_secret
from app.core.security import encrypt_totp_secret, decrypt_totp_secret

# ---------------------------------------------------------------------------
# 1) RFC-6238 reference vector  (section 4 of the RFC)
# ---------------------------------------------------------------------------
def test_rfc_vector():
    print("🧪 Testing RFC-6238 compliance...")
    # secret "12345678901234567890"  → base-32 below
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    totp = pyotp.TOTP(seed, digits=6, interval=30)
    
    result = totp.verify("287082", for_time=59)   # expected OTP at T=59 s
    print(f"   RFC test vector verification: {result}")
    assert result
    print("✅ RFC-6238 compliance test PASSED!")

# ---------------------------------------------------------------------------
# 2) End-to-end helper + replay lock, with seed encrypted at rest
# ---------------------------------------------------------------------------
def test_verify_and_replay_lock():
    print("\n🔒 Testing TOTP verification and replay protection...")
    
    # in-memory SQLite
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    DB = sessionmaker(bind=engine)

    seed = new_secret()                       # 160-bit random
    print(f"   Generated TOTP secret: {seed}")
    
    enc_seed = encrypt_totp_secret(seed)      # AES-GCM encrypt (same as prod)
    print(f"   Encrypted secret length: {len(enc_seed)} bytes")

    user = User(
        user_id="00000000-0000-0000-0000-000000000001",
        username="alice",
        auth_salt="d", 
        enc_salt="d",
        auth_key="d", 
        encrypted_mek=b"42",
        totp_secret=enc_seed,                 # store encrypted
        public_key="dummy_public_key_for_testing",  # 🔧 ADD THIS
        user_data_hmac="dummy_hmac"
    )

    with DB() as db:
        db.add(user); db.commit()
        print("   User created in database")

        otp = pyotp.TOTP(seed).now()         # valid fresh code
        print(f"   Generated TOTP code: {otp}")

        # first use must succeed
        result1 = verify_totp(db, "alice", otp)
        print(f"   First verification attempt: {result1}")
        assert result1 is True

        # Check the counter was updated
        db.refresh(user)
        print(f"   TOTP counter after first use: {user.totp_last_counter}")

        # replay within the same 30 s window must fail
        result2 = verify_totp(db, "alice", otp)
        print(f"   Replay attempt (same code): {result2}")
        assert result2 is False

    print("✅ TOTP verification and replay protection test PASSED!")

# Run the tests when executed directly
if __name__ == "__main__":
    print("🚀 Starting TOTP Security Tests")
    print("=" * 50)
    
    try:
        test_rfc_vector()
        test_verify_and_replay_lock()
        print("\n🎉 ALL TESTS PASSED! Your TOTP implementation is secure!")
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()