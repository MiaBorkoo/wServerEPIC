"""
Tests for file sharing functionality - grant, revoke, and access control.
"""
import pytest
import uuid
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import UUID

from app.db.models import User, File, Share


class TestFileSharing:
    """Test file sharing functionality and security."""

    def test_share_file_success(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test successful file sharing."""
        # Create users
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        # Create file
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Share file
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 201
        data = response.json()
        assert "share_id" in data
        assert "message" in data

    def test_share_file_unauthorized(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test sharing file without ownership."""
        # Create users
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        # Create file owned by user1
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Try to share as user2
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user1.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 403

    def test_share_nonexistent_file(self, client, test_db_session, sample_user_data, sample_user_data_2, mock_jwt_token):
        """Test sharing non-existent file."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        fake_file_id = str(uuid.uuid4())
        
        share_data = {
            "file_id": fake_file_id,
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 404

    def test_share_with_nonexistent_user(self, client, test_db_session, sample_user_data, sample_file_data, mock_jwt_token):
        """Test sharing with non-existent recipient."""
        user1 = User(**sample_user_data)
        test_db_session.add(user1)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": "nonexistent_user",
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 404

    def test_share_duplicate_recipient(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test sharing with same recipient twice."""
        # Create users and file
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        # Create first share
        share1 = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key_1",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share1)
        test_db_session.commit()
        
        # Try to create duplicate share
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key_2".hex(),
            "permission_level": "read",
            "share_grant_hmac": "c" * 64,
            "share_chain_hmac": "d" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 400  # Duplicate share

    def test_share_invalid_permission_level(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test sharing with invalid permission level."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "invalid_permission",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 422

    def test_share_invalid_hmac(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test sharing with invalid HMAC."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "invalid_hmac",
            "share_chain_hmac": "b" * 64
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 422

    def test_share_with_expiration(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test sharing with expiration time."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Set expiration to 1 hour from now
        expiration = datetime.now() + timedelta(hours=1)
        
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64,
            "expires_at": expiration.isoformat()
        }
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.post(
                "/api/files/share",
                json=share_data,
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 201


class TestShareRevocation:
    """Test share revocation functionality."""

    def test_revoke_share_success(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test successful share revocation."""
        # Setup users, file, and share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        test_db_session.refresh(share)
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.delete(
                f"/api/files/share/{share.share_id}",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        
        # Verify share is revoked
        test_db_session.refresh(share)
        assert share.revoked_at is not None

    def test_revoke_share_unauthorized(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test revoking share without permission."""
        # Setup users, file, and share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        test_db_session.refresh(share)
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.delete(
                f"/api/files/share/{share.share_id}",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 403

    def test_revoke_nonexistent_share(self, client, test_db_session, sample_user_data, mock_jwt_token):
        """Test revoking non-existent share."""
        user1 = User(**sample_user_data)
        test_db_session.add(user1)
        test_db_session.commit()
        
        fake_share_id = str(uuid.uuid4())
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.delete(
                f"/api/files/share/{fake_share_id}",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 404

    def test_revoke_already_revoked_share(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test revoking already revoked share."""
        # Setup with already revoked share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64,
            revoked_at=datetime.now()  # Already revoked
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        test_db_session.refresh(share)
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            response = client.delete(
                f"/api/files/share/{share.share_id}",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 400  # Already revoked


class TestShareListing:
    """Test share listing functionality."""

    def test_list_file_shares_success(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test listing shares for a file."""
        # Setup: Create user1 (owner), user2, user3 (recipients).
        # Create file_record owned by user1.
        # Create share1 from user1 to user2 for file_record.
        # Create share2 from user1 to user3 for file_record.
        # Ensure all objects (users, file, shares) are added and committed to test_db_session and refreshed.
        # Example (actual setup will be more detailed):
        user1 = User(**sample_user_data)
        user2_data = sample_user_data_2.copy()
        user2 = User(**user2_data)
        user3_data = sample_user_data_2.copy()
        user3_data["username"] = "testuser3"
        user3_data["auth_salt"] = "x" * 64
        user3 = User(**user3_data)

        test_db_session.add_all([user1, user2, user3])
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        test_db_session.refresh(user3)

        file_record = File(owner_id=user1.user_id, **sample_file_data) # Simplified for brevity
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)

        share1 = Share(file_id=file_record.file_id, owner_id=user1.user_id, recipient_id=user2.user_id, encrypted_data_key=b"key1", share_grant_hmac="hmac1".ljust(64, '0'), share_chain_hmac="chain1".ljust(64, '0'))
        share2 = Share(file_id=file_record.file_id, owner_id=user1.user_id, recipient_id=user3.user_id, encrypted_data_key=b"key2", share_grant_hmac="hmac2".ljust(64, '0'), share_chain_hmac="chain2".ljust(64, '0'))
        test_db_session.add_all([share1, share2])
        test_db_session.commit()
        test_db_session.refresh(share1)
        test_db_session.refresh(share2)

        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1 # user1 (owner) listing shares for their file
            
            response = client.get(
                f"/api/files/{file_record.file_id}/shares", 
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2 # Expecting two shares
        share_ids_returned = {item['share_id'] for item in data}
        assert str(share1.share_id) in share_ids_returned
        assert str(share2.share_id) in share_ids_returned

    def test_list_received_shares_success(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test listing shares received by user."""
        # Setup users, file, and share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        
        # List shares received by user2
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.get(
                "/api/files/shares/received",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_shares_excludes_revoked(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test that revoked shares are excluded from listing."""
        # Setup with revoked share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add_all([user1, user2])
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)

        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
    
        # Create a share
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key_1",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        test_db_session.refresh(share)
    
        # Now revoke the share
        share.revoked_at = datetime.now()
        test_db_session.add(share)
        test_db_session.commit()
        test_db_session.refresh(share)
    
        # Create a second file and share it with user2 (this one will be active)
        other_file_data = sample_file_data.copy()
        other_file_data["file_data_hmac"] = "z" * 64
        other_file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=b"other_encrypted_filename",
            file_size_encrypted=b"other_encrypted_size",
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=other_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(other_file_record)
        test_db_session.commit()
        test_db_session.refresh(other_file_record)

        active_share_other_file = Share(
            file_id=other_file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key_active",
            share_grant_hmac="y" * 64,
            share_chain_hmac="x" * 64
        )
        test_db_session.add(active_share_other_file)
        test_db_session.commit()
        test_db_session.refresh(active_share_other_file)

        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2 # user2 is listing their received shares
            
            response = client.get(
                "/api/files/shares/received",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should only show active shares. The revoked one should not be listed.
        # We expect 1 active share (active_share_other_file)
        assert len(data) == 1
        assert data[0]["share_id"] == str(active_share_other_file.share_id)
        assert data[0]["revoked_at"] is None

    def test_list_shares_excludes_expired(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test that expired shares are excluded from listing."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Create expired share
        expired_share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64,
            expires_at=datetime.now() - timedelta(hours=1)  # Expired 1 hour ago
        )
        test_db_session.add(expired_share)
        test_db_session.commit()
        test_db_session.refresh(expired_share)
        
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.get(
                "/api/files/shares/received",
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        data = response.json()
        # Should not include expired shares
        assert len([s for s in data if s.get("expires_at") and 
                   datetime.fromisoformat(s["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc)]) == 0


class TestSharedFileAccess:
    """Test access to shared files."""

    def test_download_shared_file_success(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, temp_file_storage, mock_jwt_token):
        """Test downloading file via share permission."""
        # Setup users, file, and share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        # Create file in storage
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(temp_file_storage, file_uuid)
        with open(file_path, 'wb') as f:
            f.write(sample_file_data["content"])
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=file_path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Create share
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64
        )
        test_db_session.add(share)
        test_db_session.commit()
        test_db_session.refresh(share)
        
        # Download as recipient
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 200
        assert response.content == sample_file_data["content"]

    def test_download_expired_shared_file(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, temp_file_storage, mock_jwt_token):
        """Test downloading file with expired share."""
        # Setup with expired share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Create expired share
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64,
            expires_at=datetime.now() - timedelta(hours=1)
        )
        test_db_session.add(share)
        test_db_session.commit()
        test_db_session.refresh(share)
        
        # Try to download
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 403  # Access denied due to expired share

    def test_download_revoked_shared_file(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, temp_file_storage, mock_jwt_token):
        """Test downloading file with revoked share."""
        # Setup with revoked share
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Create revoked share
        share = Share(
            file_id=file_record.file_id,
            owner_id=user1.user_id,
            recipient_id=user2.user_id,
            encrypted_data_key=b"encrypted_data_key",
            share_grant_hmac="a" * 64,
            share_chain_hmac="b" * 64,
            revoked_at=datetime.now()
        )
        test_db_session.add(share)
        test_db_session.commit()
        test_db_session.refresh(share)
        
        # Try to download
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user2
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": f"Bearer {mock_jwt_token}"}
            )
        
        assert response.status_code == 403  # Access denied due to revoked share


class TestShareSecurity:
    """Test share security features."""

    def test_hmac_integrity_verification(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test HMAC integrity verification in shares."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Create share with proper HMAC validation mock
        share_data = {
            "file_id": str(file_record.file_id),
            "recipient_username": user2.username,
            "encrypted_data_key": b"encrypted_data_key".hex(),
            "permission_level": "read",
            "share_grant_hmac": "a" * 64,
            "share_chain_hmac": "b" * 64
        }
        
        # Mock HMAC validation failure
        with patch('app.core.security.get_current_user') as mock_get_current_user:
            mock_get_current_user.return_value = user1
            
            with patch('app.routers.files_router.verify_share_hmac') as mock_hmac:
                mock_hmac.return_value = False  # HMAC verification fails
                
                response = client.post(
                    "/api/files/share",
                    json=share_data,
                    headers={"Authorization": f"Bearer {mock_jwt_token}"}
                )
        
        assert response.status_code == 400  # HMAC verification failed

    def test_share_permission_levels(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, mock_jwt_token):
        """Test different share permission levels."""
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        test_db_session.refresh(user1)
        test_db_session.refresh(user2)
        
        file_record = File(
            owner_id=user1.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        test_db_session.refresh(file_record)
        
        # Test each permission level
        permission_levels = ["read", "write", "admin"]
        
        for permission in permission_levels:
            # Ensure a unique recipient for each share attempt if using the same file, or use different files
            # For this test, we are re-sharing to the same user but the endpoint should ideally handle this
            # by either updating the existing share or raising a conflict. 
            # The current Share model has UNIQUE(file_id, recipient_id), so re-sharing to same recipient is an issue.
            # Let's assume the goal is to test if these permission strings are accepted by the Pydantic model.
            # If the share creation fails due to unique constraint, this test will not correctly check permission levels.

            # To avoid IntegrityError, we'll create a new recipient user for each permission level test
            # or, more simply, we will not commit the share, just test the call. 
            # However, the endpoint creates the share. A better approach for *this* test is to ensure
            # it focuses on the *creation* part and perhaps not on subsequent conflicts if the same file/recipient is used.

            # For now, let's assume the endpoint logic handles or the test setup avoids duplicate shares for this specific test.
            # A robust way would be to use different files or different recipients for each permission level test.
            # Given the current structure, the easiest is to test if the API call succeeds with these permissions.
            # The `test_share_duplicate_recipient` already covers the duplication scenario.
            
            share_data = {
                "file_id": str(file_record.file_id),
                "recipient_username": user2.username, # This will fail on 2nd iteration if not handled
                "encrypted_data_key": b"encrypted_data_key".hex(),
                "permission_level": permission,
                "share_grant_hmac": f"hmac_for_{permission}", # Ensure unique, valid length
                "share_chain_hmac": f"chain_hmac_for_{permission}"
            }
            # Ensure HMACs are 64 chars
            share_data["share_grant_hmac"] = (share_data["share_grant_hmac"] * (64 // len(share_data["share_grant_hmac"]) + 1))[:64]
            share_data["share_chain_hmac"] = (share_data["share_chain_hmac"] * (64 // len(share_data["share_chain_hmac"]) + 1))[:64]

            # Clean up any previous share to user2 for this file to avoid unique constraint violation
            existing_share = test_db_session.query(Share).filter_by(file_id=file_record.file_id, recipient_id=user2.user_id).first()
            if existing_share:
                test_db_session.delete(existing_share)
                test_db_session.commit()

            with patch('app.core.security.get_current_user') as mock_get_current_user:
                mock_get_current_user.return_value = user1
                
                response = client.post(
                    "/api/files/share",
                    json=share_data,
                    headers={"Authorization": f"Bearer {mock_jwt_token}"}
                )
            
            assert response.status_code == 201, f"Failed for permission: {permission}"
            # Clean up the created share so the next iteration doesn't hit unique constraint
            if response.status_code == 201:
                created_share_id = response.json()["share_id"]
                share_to_delete = test_db_session.query(Share).filter_by(share_id=UUID(created_share_id)).first()
                if share_to_delete:
                    test_db_session.delete(share_to_delete)
                    test_db_session.commit() 