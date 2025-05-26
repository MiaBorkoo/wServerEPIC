"""
Test configuration and fixtures for EPIC Server tests.
"""
import pytest
import tempfile
import os
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.db.database import get_db, DATABASE_URL
from app.db.models import Base


@pytest.fixture(scope="session")
def test_db_url():
    """Create a test database URL using SQLite in memory."""
    return "sqlite:///:memory:"


@pytest.fixture(scope="function")
def test_db_engine(test_db_url):
    """Create a test database engine for each test function."""
    engine = create_engine(
        test_db_url,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=False  # Set to True for SQL debugging
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def test_db_session(test_db_engine):
    """Create a test database session for each test function."""
    TestingSessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=test_db_engine
    )
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="function")
def client(test_db_session):
    """Create a test client with isolated database session."""
    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass
    
    original_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
        
    app.dependency_overrides = original_overrides # Restore original overrides, good practice


@pytest.fixture
def temp_file_storage():
    """Create temporary directory for file storage during tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "auth_salt": "a" * 64,  # 32-byte salt hex encoded
        "enc_salt": "b" * 64,   # 32-byte salt hex encoded
        "auth_key": "c" * 128,  # Argon2id hash
        "encrypted_mek": b"encrypted_mek_data",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
        "user_data_hmac": "d" * 64
    }


@pytest.fixture
def sample_user_data_2():
    """Second sample user data for sharing tests."""
    return {
        "username": "testuser2",
        "auth_salt": "e" * 64,
        "enc_salt": "f" * 64,
        "auth_key": "g" * 128,
        "encrypted_mek": b"encrypted_mek_data_2",
        "totp_secret": "JBSWY3DPEHPK3PXT",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEB...\n-----END PUBLIC KEY-----",
        "user_data_hmac": "h" * 64
    }


@pytest.fixture
def sample_file_data():
    """Sample file data for testing."""
    return {
        "filename_encrypted": b"encrypted_filename",
        "file_size_encrypted": b"encrypted_size",
        "file_data_hmac": "i" * 64,
        "content": b"test file content"
    }


@pytest.fixture
def auth_headers():
    """Sample authentication headers."""
    return {
        "Authorization": "Bearer test_jwt_token",
        "Content-Type": "application/json"
    }


@pytest.fixture
def mock_jwt_token():
    """Mock JWT token for testing."""
    return "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMTIzNDU2NzgtOTBhYi1jZGVmLTEyMzQtNTY3ODkwYWJjZGVmIn0.test_signature"


@pytest.fixture(autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    os.environ["DATABASE_URL"] = "sqlite:///:memory:"
    os.environ["SQL_DEBUG"] = "false"
    yield
    # Cleanup if needed 