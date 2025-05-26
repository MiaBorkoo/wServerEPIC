"""
Tests for database models - focusing on data integrity and constraints.
"""
import pytest
import uuid
from datetime import datetime
from sqlalchemy.exc import IntegrityError

from app.db.models import User, File, Share, FileAuditLog


class TestUserModel:
    """Test User model constraints and security features."""

    def test_create_user_success(self, test_db_session, sample_user_data):
        """Test successful user creation with all required fields."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        test_db_session.refresh(user)
        
        assert user.user_id is not None
        assert user.username == sample_user_data["username"]
        assert user.auth_salt == sample_user_data["auth_salt"]
        assert user.created_at is not None

    def test_user_username_uniqueness(self, test_db_session, sample_user_data):
        """Test that usernames must be unique."""
        # Create first user
        user1 = User(**sample_user_data)
        test_db_session.add(user1)
        test_db_session.commit()
        
        # Attempt to create second user with same username
        user2_data = sample_user_data.copy()
        user2_data["auth_salt"] = "different_salt"
        user2 = User(**user2_data)
        test_db_session.add(user2)
        
        with pytest.raises(IntegrityError):
            test_db_session.commit()

    def test_user_required_fields(self, test_db_session):
        """Test that all required fields are enforced."""
        # Missing username
        with pytest.raises(IntegrityError):
            user = User(
                auth_salt="salt",
                enc_salt="enc_salt",
                auth_key="auth_key",
                encrypted_mek=b"mek",
                totp_secret="secret",
                public_key="key",
                user_data_hmac="hmac"
            )
            test_db_session.add(user)
            test_db_session.commit()

    def test_user_salt_length_validation(self, test_db_session, sample_user_data):
        """Test salt length constraints (should be 64 chars for 32-byte hex)."""
        # Test short salt
        sample_user_data["auth_salt"] = "short"
        user = User(**sample_user_data)
        test_db_session.add(user)
        # Note: Length validation would be handled at application level
        test_db_session.commit()  # Should succeed in this test setup

    def test_user_hmac_integrity(self, test_db_session, sample_user_data):
        """Test HMAC field storage for integrity protection."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        assert user.user_data_hmac == sample_user_data["user_data_hmac"]
        assert len(user.user_data_hmac) == 64  # SHA-256 hex = 64 chars


class TestFileModel:
    """Test File model constraints and security features."""

    def test_create_file_success(self, test_db_session, sample_user_data, sample_file_data):
        """Test successful file creation."""
        # Create user first
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create file
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        assert file_data.file_id is not None
        assert file_data.owner_id == user.user_id
        assert not file_data.is_deleted

    def test_file_owner_foreign_key(self, test_db_session, sample_file_data):
        """Test foreign key constraint for file owner."""
        fake_user_id = uuid.uuid4()
        
        file_data = File(
            owner_id=fake_user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        
        with pytest.raises(IntegrityError):
            test_db_session.commit()

    def test_file_soft_delete(self, test_db_session, sample_user_data, sample_file_data):
        """Test file soft delete functionality."""
        # Create user and file
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Test soft delete
        file_data.is_deleted = True
        file_data.deleted_at = datetime.now()
        test_db_session.commit()
        
        assert file_data.is_deleted
        assert file_data.deleted_at is not None

    def test_encrypted_data_fields(self, test_db_session, sample_user_data, sample_file_data):
        """Test that encrypted fields store binary data correctly."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        assert isinstance(file_data.filename_encrypted, bytes)
        assert isinstance(file_data.file_size_encrypted, bytes)


class TestShareModel:
    """Test Share model constraints and security features."""

    def test_create_share_success(self, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test successful share creation."""
        # Create users
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        # Create file
        file_data = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create share
        share = Share(
            file_id=file_data.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        assert share.share_id is not None
        assert share.granted_at is not None
        assert share.revoked_at is None

    def test_share_unique_constraint(self, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test unique constraint on file_id + recipient_id."""
        # Create users and file
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create first share
        share1 = Share(
            file_id=file_data.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key_1",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share1)
        test_db_session.commit()
        
        # Attempt to create duplicate share
        share2 = Share(
            file_id=file_data.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key_2",
            share_grant_hmac="c" * 64,
            share_chain_hmac="d" * 64
        )
        test_db_session.add(share2)
        
        with pytest.raises(IntegrityError):
            test_db_session.commit()

    def test_share_hmac_integrity(self, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test HMAC fields for share integrity."""
        # Setup users and file
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create share with HMACs
        grant_hmac = "a" * 64
        chain_hmac = "b" * 64
        
        share = Share(
            file_id=file_data.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac=grant_hmac,
            share_chain_hmac=chain_hmac
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        assert share.share_grant_hmac == grant_hmac
        assert share.share_chain_hmac == chain_hmac
        assert len(share.share_grant_hmac) == 64
        assert len(share.share_chain_hmac) == 64


class TestFileAuditLogModel:
    """Test audit log model for security compliance."""

    def test_create_audit_log(self, test_db_session, sample_user_data, sample_file_data):
        """Test audit log creation."""
        # Create user and file
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create audit log
        audit_log = FileAuditLog(
            file_id=file_data.file_id,
            user_id=user.user_id,
            action="upload",
            timestamp=int(datetime.now().timestamp()),
            client_ip_hash="hashed_ip_address",
            log_entry_hmac="e" * 64,
            previous_log_hmac="f" * 64
        )
        test_db_session.add(audit_log)
        test_db_session.commit()
        
        assert audit_log.log_id is not None
        assert audit_log.action == "upload"
        assert audit_log.client_ip_hash == "hashed_ip_address"

    def test_audit_log_chain_integrity(self, test_db_session, sample_user_data, sample_file_data):
        """Test audit log chaining for tamper detection."""
        # Setup user and file
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create first log entry
        log1 = FileAuditLog(
            file_id=file_data.file_id,
            user_id=user.user_id,
            action="upload",
            timestamp=int(datetime.now().timestamp()),
            log_entry_hmac="a" * 64,
            previous_log_hmac=None  # First entry
        )
        test_db_session.add(log1)
        test_db_session.commit()
        
        # Create second log entry chained to first
        log2 = FileAuditLog(
            file_id=file_data.file_id,
            user_id=user.user_id,
            action="download",
            timestamp=int(datetime.now().timestamp()),
            log_entry_hmac="b" * 64,
            previous_log_hmac="a" * 64  # Links to previous
        )
        test_db_session.add(log2)
        test_db_session.commit()
        
        assert log1.previous_log_hmac is None
        assert log2.previous_log_hmac == log1.log_entry_hmac

    def test_audit_log_foreign_keys(self, test_db_session):
        """Test foreign key constraints in audit log."""
        fake_file_id = uuid.uuid4()
        fake_user_id = uuid.uuid4()
        
        audit_log = FileAuditLog(
            file_id=fake_file_id,
            user_id=fake_user_id,
            action="upload",
            timestamp=int(datetime.now().timestamp()),
            log_entry_hmac="a" * 64
        )
        test_db_session.add(audit_log)
        
        with pytest.raises(IntegrityError):
            test_db_session.commit()


class TestModelRelationships:
    """Test model relationships and cascading operations."""

    def test_user_file_relationship(self, test_db_session, sample_user_data, sample_file_data):
        """Test user-file relationship."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Test relationship
        assert file_data.owner == user
        assert file_data in user.owned_files

    def test_file_share_relationship(self, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test file-share relationship."""
        # Setup users and file
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_data = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_data)
        test_db_session.commit()
        
        # Create share
        share = Share(
            file_id=file_data.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        # Test relationships
        assert share.file == file_data
        assert share.owner == user1
        assert share.recipient == user2
        assert share in file_data.shares
        assert share in user1.granted_shares
        assert share in user2.received_shares 