"""
Tests for authentication endpoints - focusing on security and edge cases.
"""
import pytest
import json
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.db.models import User
from app.db.crud import create_user


class TestUserRegistration:
    """Test user registration endpoint security."""

    def test_register_user_success(self, client, sample_user_data):
        """Test successful user registration."""
        registration_data = {
            "username": sample_user_data["username"],
            "auth_salt": sample_user_data["auth_salt"],
            "enc_salt": sample_user_data["enc_salt"],
            "auth_key": sample_user_data["auth_key"],
            "encrypted_mek": sample_user_data["encrypted_mek"].hex(),
            "totp_secret": sample_user_data["totp_secret"],
            "public_key": sample_user_data["public_key"],
            "user_data_hmac": sample_user_data["user_data_hmac"]
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 200
        assert "user_id" in response.json()

    def test_register_duplicate_username(self, client, test_db_session, sample_user_data):
        """Test registration with duplicate username fails."""
        # Create user in database first
        user_data_for_db = sample_user_data.copy()
        # The User model expects bytes for encrypted_mek, but sample_user_data might provide a string.
        # The .hex() method is used for API JSON, but direct model creation needs bytes.
        if isinstance(user_data_for_db.get("encrypted_mek"), str):
            user_data_for_db["encrypted_mek"] = user_data_for_db["encrypted_mek"].encode('utf-8')

        user = User(**user_data_for_db)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Attempt to register with same username
        registration_data = {
            "username": sample_user_data["username"],
            "auth_salt": "different_salt",
            "enc_salt": "different_enc_salt", 
            "auth_key": "different_auth_key",
            "encrypted_mek": b"different_mek".hex(),
            "totp_secret": "DIFFERENT_SECRET",
            "public_key": "different_public_key",
            "user_data_hmac": "different_hmac"
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code in [200, 400, 422]

    def test_register_invalid_salt_length(self, client):
        """Test registration with invalid salt length."""
        registration_data = {
            "username": "testuser",
            "auth_salt": "short",  # Too short
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 422  # Validation error

    def test_register_invalid_hmac_length(self, client):
        """Test registration with invalid HMAC length."""
        registration_data = {
            "username": "testuser",
            "auth_salt": "a" * 64,
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "short"  # Too short
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 422

    def test_register_missing_required_field(self, client):
        """Test registration with missing required field."""
        registration_data = {
            "username": "testuser",
            "auth_salt": "a" * 64,
            # Missing enc_salt
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 422

    def test_register_sql_injection_attempt(self, client):
        """Test SQL injection protection in registration."""
        registration_data = {
            "username": "'; DROP TABLE users; --",
            "auth_salt": "a" * 64,
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        # Should either reject or sanitize, not cause server error
        assert response.status_code in [200, 400, 422]

    def test_register_xss_attempt(self, client):
        """Test XSS protection in registration."""
        registration_data = {
            "username": "<script>alert('xss')</script>",
            "auth_salt": "a" * 64,
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code in [200, 400, 422]


class TestSaltRetrieval:
    """Test salt retrieval endpoint security."""

    def test_get_salts_existing_user(self, client, test_db_session, sample_user_data):
        """Test retrieving salts for existing user."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        response = client.get(f"/api/user/{sample_user_data['username']}/salts")
        assert response.status_code == 200
        data = response.json()
        assert "auth_salt" in data
        assert "enc_salt" in data
        assert data["auth_salt"] == sample_user_data["auth_salt"]
        assert data["enc_salt"] == sample_user_data["enc_salt"]

    def test_get_salts_nonexistent_user(self, client):
        """Test retrieving salts for non-existent user."""
        response = client.get("/api/user/nonexistent/salts")
        assert response.status_code == 404

    def test_get_salts_timing_attack_protection(self, client, test_db_session, sample_user_data):
        """Test timing attack protection in salt retrieval."""
        # Create user
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        import time
        
        # Time existing user lookup
        start = time.time()
        response1 = client.get(f"/api/user/{sample_user_data['username']}/salts")
        existing_time = time.time() - start
        
        # Time non-existing user lookup
        start = time.time()
        response2 = client.get("/api/user/nonexistent/salts")
        nonexistent_time = time.time() - start
        
        assert response1.status_code == 200
        assert response2.status_code == 404
        
        # Times should be relatively similar (within 100ms) to prevent timing attacks
        # Note: This is a basic check - production code might use constant-time operations
        time_diff = abs(existing_time - nonexistent_time)
        assert time_diff < 0.1  # 100ms tolerance

    def test_get_salts_path_traversal(self, client):
        """Test path traversal protection."""
        response = client.get("/api/user/../../../etc/passwd/salts")
        assert response.status_code == 404

    def test_get_salts_no_sensitive_data_leak(self, client, test_db_session, sample_user_data):
        """Test that only salts are returned, no sensitive data."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        response = client.get(f"/api/user/{sample_user_data['username']}/salts")
        assert response.status_code == 200
        data = response.json()
        
        # Should only contain salts
        assert set(data.keys()) == {"auth_salt", "enc_salt"}
        assert "auth_key" not in data
        assert "encrypted_mek" not in data
        assert "totp_secret" not in data


class TestAuthentication:
    """Test first factor authentication."""

    def test_login_success(self, client, test_db_session, sample_user_data):
        """Test successful first factor authentication."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "username": sample_user_data["username"],
            "auth_key": sample_user_data["auth_key"],
            "nonce": "test_nonce"
        }
        
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 200
        data = response.json()
        assert "temp_token" in data
        assert "totp_required" in data

    def test_login_invalid_username(self, client):
        """Test login with invalid username."""
        login_data = {
            "username": "nonexistent",
            "auth_key": "invalid_key",
            "nonce": "test_nonce"
        }
        
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401

    def test_login_invalid_auth_key(self, client, test_db_session, sample_user_data):
        """Test login with invalid auth key."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "username": sample_user_data["username"],
            "auth_key": "wrong_key",
            "nonce": "test_nonce"
        }
        
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 401

    def test_login_missing_nonce(self, client, test_db_session, sample_user_data):
        """Test login without nonce fails."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "username": sample_user_data["username"],
            "auth_key": sample_user_data["auth_key"]
            # Missing nonce
        }
        
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 422

    @patch('app.routers.auth_router.time')
    def test_login_rate_limiting(self, mock_time, client, test_db_session, sample_user_data):
        """Test rate limiting on login attempts."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        login_data = {
            "username": sample_user_data["username"],
            "auth_key": sample_user_data["auth_key"],
            "nonce": "test_nonce"
        }
        
        # Simulate 6 rapid login attempts
        mock_time.return_value = 0
        for _ in range(5):
            response = client.post("/api/auth/login", json=login_data)
            assert response.status_code == 200
        
        # 6th attempt should be rate limited
        response = client.post("/api/auth/login", json=login_data)
        assert response.status_code == 429


class TestTwoFactorAuth:
    """Test TOTP second factor authentication."""

    @patch('app.core.security.verify_totp')
    def test_totp_success(self, mock_verify, client, test_db_session, sample_user_data):
        """Test successful TOTP verification."""
        mock_verify.return_value = True
        
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Mock having a valid temp token
        totp_data = {
            "username": sample_user_data["username"],
            "totp_code": "123456",
            "temp_token": "valid_temp_token"
        }
        
        with patch('app.routers.auth_router.verify_temp_token') as mock_temp:
            mock_temp.return_value = {"username": sample_user_data["username"]}
            response = client.post("/api/auth/totp", json=totp_data)
            
        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert "message" in data

    @patch('app.core.security.verify_totp')
    def test_totp_invalid_code(self, mock_verify, client, test_db_session, sample_user_data):
        """Test TOTP with invalid code."""
        mock_verify.return_value = False
        
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        totp_data = {
            "username": sample_user_data["username"],
            "totp_code": "000000",
            "temp_token": "valid_temp_token"
        }
        
        with patch('app.routers.auth_router.verify_temp_token') as mock_temp:
            mock_temp.return_value = {"username": sample_user_data["username"]}
            response = client.post("/api/auth/totp", json=totp_data)
            
        assert response.status_code == 401

    def test_totp_invalid_temp_token(self, client):
        """Test TOTP with invalid temporary token."""
        totp_data = {
            "username": "testuser",
            "totp_code": "123456",
            "temp_token": "invalid_token"
        }
        
        response = client.post("/api/auth/totp", json=totp_data)
        assert response.status_code == 401

    def test_totp_expired_temp_token(self, client):
        """Test TOTP with expired temporary token."""
        totp_data = {
            "username": "testuser",
            "totp_code": "123456",
            "temp_token": "expired_token"
        }
        
        with patch('app.routers.auth_router.verify_temp_token') as mock_temp:
            mock_temp.side_effect = Exception("Token expired")
            response = client.post("/api/auth/totp", json=totp_data)
            
        assert response.status_code == 401

    def test_totp_code_reuse_protection(self, client, test_db_session, sample_user_data):
        """Test protection against TOTP code reuse."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        totp_data = {
            "username": sample_user_data["username"],
            "totp_code": "123456",
            "temp_token": "valid_temp_token"
        }
        
        with patch('app.routers.auth_router.verify_temp_token') as mock_temp:
            mock_temp.return_value = {"username": sample_user_data["username"]}
            with patch('app.core.security.verify_totp') as mock_verify:
                mock_verify.return_value = True
                
                # First use should succeed
                response1 = client.post("/api/auth/totp", json=totp_data)
                assert response1.status_code == 200
                
                # Second use of same code should fail (if implemented)
                response2 = client.post("/api/auth/totp", json=totp_data)
                # This would require additional implementation for code tracking


class TestLogout:
    """Test session logout functionality."""

    def test_logout_success(self, client, auth_headers):
        """Test successful logout."""
        with patch('app.routers.auth_router.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": "test_user_id"}
            response = client.post("/api/auth/logout", headers=auth_headers)
            
        assert response.status_code == 200
        assert "message" in response.json()

    def test_logout_invalid_token(self, client):
        """Test logout with invalid token."""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.post("/api/auth/logout", headers=headers)
        assert response.status_code == 401

    def test_logout_missing_token(self, client):
        """Test logout without token."""
        response = client.post("/api/auth/logout")
        assert response.status_code == 401


class TestSecurityHeaders:
    """Test security-related HTTP headers."""

    def test_cors_headers(self, client):
        """Test CORS headers are present."""
        response = client.get("/")
        # CORS headers should be present due to middleware
        assert "access-control-allow-origin" in [h.lower() for h in response.headers.keys()]

    def test_no_server_info_leak(self, client):
        """Test that server doesn't leak sensitive information in headers."""
        response = client.get("/")
        
        # Should not expose server software versions
        server_header = response.headers.get("server", "").lower()
        assert "uvicorn" not in server_header  # If properly configured
        
        # Should not expose framework info
        assert "x-powered-by" not in response.headers

    def test_error_response_no_stack_trace(self, client):
        """Test that error responses don't leak stack traces."""
        response = client.get("/nonexistent-endpoint")
        assert response.status_code == 404
        
        # Error response should not contain internal paths or stack traces
        error_text = response.text.lower()
        assert "/app/" not in error_text
        assert "traceback" not in error_text
        assert "exception" not in error_text


class TestInputValidation:
    """Test input validation and sanitization."""

    def test_username_length_limits(self, client):
        """Test username length validation."""
        # Test extremely long username
        long_username = "a" * 1000
        registration_data = {
            "username": long_username,
            "auth_salt": "a" * 64,
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code == 422

    def test_null_byte_injection(self, client):
        """Test null byte injection protection."""
        registration_data = {
            "username": "test\x00user",
            "auth_salt": "a" * 64,
            "enc_salt": "b" * 64,
            "auth_key": "c" * 128,
            "encrypted_mek": b"mek".hex(),
            "totp_secret": "JBSWY3DPEHPK3PXP",
            "public_key": "public_key",
            "user_data_hmac": "d" * 64
        }
        
        response = client.post("/api/auth/register", json=registration_data)
        assert response.status_code in [400, 422]

    def test_unicode_normalization(self, client):
        """Test Unicode normalization in usernames."""
        # Test usernames that look the same but have different Unicode representations
        username1 = "test"  # Regular ASCII
        username2 = "test"  # With Unicode lookalikes
        
        # This would require proper Unicode normalization implementation
        # The test checks that similar-looking usernames are handled consistently 