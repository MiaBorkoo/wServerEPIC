"""
Tests for file operations - upload, download, delete, and security.
"""
import pytest
import uuid
import tempfile
import os
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime
from io import BytesIO
import base64

from app.db.models import User, File, FileAuditLog


class TestFileUpload:
    """Test file upload functionality and security."""

    def test_upload_file_success(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test successful file upload."""
        # Create user
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Mock authentication
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            # Create test file
            test_file_content = sample_file_data["content"]
            test_file = BytesIO(test_file_content)
            
            # Mock file system operations within the router to use the temp_file_storage
            with patch('app.routers.files_router.os.path.join', side_effect=lambda *args: os.path.join(temp_file_storage, args[-1])) as mock_join, \
                 patch('app.routers.files_router.os.makedirs') as mock_makedirs, \
                 patch('app.routers.files_router.open', mock_open()) as mock_file_open, \
                 patch('app.routers.files_router.os.rename') as mock_rename, \
                 patch('app.routers.files_router.os.remove') as mock_remove:

                response = client.post(
                    "/api/files/upload",
                    files={"file": ("test.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": base64.b64encode(sample_file_data["filename_encrypted"]).decode('utf-8'),
                        "file_size_encrypted": base64.b64encode(sample_file_data["file_size_encrypted"]).decode('utf-8'),
                        "file_data_hmac": sample_file_data["file_data_hmac"]
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code == 201
        data = response.json()
        assert "file_id" in data
        # In the router, the message is part of the error detail, not success
        # assert "message" in data 

        assert mock_join.call_count >= 2 
        mock_makedirs.assert_any_call(temp_file_storage, exist_ok=True)
        
        final_filename_used = None
        # The actual filename (UUID string) is the last component of the path arguments to os.path.join
        # The rename operation (if it happens) will have the final definitive name based on DB file_id.
        # We look for a call to os.path.join that uses temp_file_storage and capture the filename part.
        for call_args_tuple in mock_join.call_args_list:
            args, _ = call_args_tuple
            if len(args) > 1 and args[0] == temp_file_storage: # Expecting (temp_file_storage, uuid_str)
                 final_filename_used = args[1]
                 break # Found a plausible candidate
        if not final_filename_used and mock_rename.called:
            # If renamed, the target of rename is the final path
            final_path_target = mock_rename.call_args[0][1]
            final_filename_used = os.path.basename(final_path_target)


        assert final_filename_used is not None, "File path construction with temp_file_storage did not happen as expected."
        
        mock_file_open.assert_any_call(os.path.join(temp_file_storage, final_filename_used), 'wb')
        
        handle = mock_file_open()
        handle.write.assert_called_once_with(test_file_content)

        assert mock_rename.call_count >= 1

    def test_upload_file_unauthorized(self, client, sample_file_data):
        """Test file upload without authentication."""
        test_file = BytesIO(sample_file_data["content"])
        
        response = client.post(
            "/api/files/upload",
            files={"file": ("test.txt", test_file, "text/plain")},
            data={
                "filename_encrypted": sample_file_data["filename_encrypted"].hex(),
                "file_size_encrypted": sample_file_data["file_size_encrypted"].hex(),
                "file_data_hmac": sample_file_data["file_data_hmac"]
            }
        )
        
        assert response.status_code == 401

    def test_upload_file_invalid_hmac(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test file upload with invalid HMAC."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            test_file = BytesIO(sample_file_data["content"])
            
            with patch('app.routers.files_router.UPLOAD_DIR', temp_file_storage):
                response = client.post(
                    "/api/files/upload",
                    files={"file": ("test.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": sample_file_data["filename_encrypted"].hex(),
                        "file_size_encrypted": sample_file_data["file_size_encrypted"].hex(),
                        "file_data_hmac": "invalid_hmac"
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code == 400

    def test_upload_large_file(self, client, test_db_session, sample_user_data, temp_file_storage):
        """Test upload of large file (near limit)."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create large file content (just under 2GiB limit)
        large_content = b"a" * (1024 * 1024)  # 1MB for testing
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            test_file = BytesIO(large_content)
            
            with patch('app.routers.files_router.UPLOAD_DIR', temp_file_storage):
                response = client.post(
                    "/api/files/upload",
                    files={"file": ("large.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": b"encrypted_large_filename".hex(),
                        "file_size_encrypted": b"encrypted_large_size".hex(),
                        "file_data_hmac": "a" * 64
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code == 201

    def test_upload_exceed_quota(self, client, test_db_session, sample_user_data, temp_file_storage):
        """Test upload that exceeds storage quota."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Mock user already at quota limit
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            with patch('app.routers.files_router.check_user_quota') as mock_quota:
                mock_quota.return_value = False  # Quota exceeded
                
                test_file = BytesIO(b"test content")
                
                response = client.post(
                    "/api/files/upload",
                    files={"file": ("test.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": b"encrypted_filename".hex(),
                        "file_size_encrypted": b"encrypted_size".hex(),
                        "file_data_hmac": "a" * 64
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code == 413  # Payload Too Large

    def test_upload_malicious_filename(self, client, test_db_session, sample_user_data, temp_file_storage):
        """Test upload with potentially malicious filename."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            # Malicious filename attempts
            malicious_names = [
                "../../../etc/passwd",
                "..\\..\\windows\\system32\\config\\sam",
                "test\x00.exe",
                "con.txt",  # Windows reserved name
                "test.php.txt"
            ]
            
            for malicious_name in malicious_names:
                test_file = BytesIO(b"test content")
                
                with patch('app.routers.files_router.UPLOAD_DIR', temp_file_storage):
                    response = client.post(
                        "/api/files/upload",
                        files={"file": (malicious_name, test_file, "text/plain")},
                        data={
                            "filename_encrypted": b"encrypted_filename".hex(),
                            "file_size_encrypted": b"encrypted_size".hex(),
                            "file_data_hmac": "a" * 64
                        },
                        headers={"Authorization": "Bearer test_token"}
                    )
                
                # Should either succeed (with sanitized name) or reject
                assert response.status_code in [201, 400, 422]

    def test_upload_zero_byte_file(self, client, test_db_session, sample_user_data, temp_file_storage):
        """Test upload of zero-byte file."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            test_file = BytesIO(b"")  # Empty file
            
            with patch('app.routers.files_router.UPLOAD_DIR', temp_file_storage):
                response = client.post(
                    "/api/files/upload",
                    files={"file": ("empty.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": b"encrypted_empty".hex(),
                        "file_size_encrypted": b"encrypted_zero".hex(),
                        "file_data_hmac": "a" * 64
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code in [201, 400]

    def test_upload_creates_audit_log(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test that file upload creates audit log entry."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            test_file = BytesIO(sample_file_data["content"])
            
            with patch('app.routers.files_router.UPLOAD_DIR', temp_file_storage):
                response = client.post(
                    "/api/files/upload",
                    files={"file": ("test.txt", test_file, "text/plain")},
                    data={
                        "filename_encrypted": sample_file_data["filename_encrypted"].hex(),
                        "file_size_encrypted": sample_file_data["file_size_encrypted"].hex(),
                        "file_data_hmac": sample_file_data["file_data_hmac"]
                    },
                    headers={"Authorization": "Bearer test_token"}
                )
        
        assert response.status_code == 201
        
        # Check audit log was created
        audit_logs = test_db_session.query(FileAuditLog).filter_by(action="upload").all()
        assert len(audit_logs) >= 1


class TestFileDownload:
    """Test file download functionality and security."""

    def test_download_file_success(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test successful file download."""
        # Create user and file
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create file in storage
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(temp_file_storage, file_uuid)
        with open(file_path, 'wb') as f:
            f.write(sample_file_data["content"])
        
        # Create file record
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=file_path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        assert response.content == sample_file_data["content"]

    def test_download_file_unauthorized(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data, temp_file_storage):
        """Test downloading file without permission."""
        # Create two users
        user1 = User(**sample_user_data)
        user2 = User(**sample_user_data_2)
        test_db_session.add(user1)
        test_db_session.add(user2)
        test_db_session.commit()
        
        # Create file owned by user1
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
        
        # Try to download as user2
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user2.user_id), "sub": str(user2.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 403

    def test_download_nonexistent_file(self, client, test_db_session, sample_user_data):
        """Test downloading non-existent file."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        fake_file_id = str(uuid.uuid4())
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": fake_file_id},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 404

    def test_download_deleted_file(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test downloading soft-deleted file."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path="/fake/path",
            is_deleted=True,
            deleted_at=datetime.now()
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 404

    def test_download_creates_audit_log(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test that file download creates audit log entry."""
        # Setup same as successful download test
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(temp_file_storage, file_uuid)
        with open(file_path, 'wb') as f:
            f.write(sample_file_data["content"])
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=file_path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        
        # Check audit log was created
        audit_logs = test_db_session.query(FileAuditLog).filter_by(action="download").all()
        assert len(audit_logs) >= 1

    def test_download_file_path_traversal_protection(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test protection against path traversal in file downloads."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create file record with malicious path
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path="../../../etc/passwd"  # Malicious path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/download",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        # Should fail safely, not expose system files
        assert response.status_code in [404, 403, 500]


class TestFileList:
    """Test file listing functionality."""

    def test_list_files_success(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test successful file listing."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create multiple files
        for i in range(3):
            file_record = File(
                owner_id=user.user_id,
                filename_encrypted=sample_file_data["filename_encrypted"],
                file_size_encrypted=sample_file_data["file_size_encrypted"],
                upload_timestamp=int(datetime.now().timestamp()),
                file_data_hmac=sample_file_data["file_data_hmac"],
                server_storage_path=f"/files/{uuid.uuid4()}"
            )
            test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.get(
                "/api/files",
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

    def test_list_files_excludes_deleted(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test that deleted files are excluded from listing."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create regular file
        file1 = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        
        # Create deleted file
        file2 = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}",
            is_deleted=True,
            deleted_at=datetime.now()
        )
        
        test_db_session.add(file1)
        test_db_session.add(file2)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.get(
                "/api/files",
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1  # Only non-deleted file

    def test_list_files_unauthorized(self, client):
        """Test file listing without authentication."""
        response = client.get("/api/files")
        assert response.status_code == 401

    def test_list_files_pagination(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test file listing with pagination parameters."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create many files
        for i in range(20):
            file_record = File(
                owner_id=user.user_id,
                filename_encrypted=sample_file_data["filename_encrypted"],
                file_size_encrypted=sample_file_data["file_size_encrypted"],
                upload_timestamp=int(datetime.now().timestamp()) + i,
                file_data_hmac=sample_file_data["file_data_hmac"],
                server_storage_path=f"/files/{uuid.uuid4()}"
            )
            test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            # Test pagination if implemented
            response = client.get(
                "/api/files?limit=10&offset=0",
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200


class TestFileDelete:
    """Test file deletion functionality."""

    def test_delete_file_success(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test successful file deletion."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        # Create file
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(temp_file_storage, file_uuid)
        with open(file_path, 'wb') as f:
            f.write(sample_file_data["content"])
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=file_path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.delete(
                "/api/files/delete",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        
        # Verify file is marked as deleted
        test_db_session.refresh(file_record)
        assert file_record.is_deleted
        assert file_record.deleted_at is not None
        
        # Verify physical file is removed
        assert not os.path.exists(file_path)

    def test_delete_file_unauthorized(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test deleting file without permission."""
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
        
        # Try to delete as user2
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user2.user_id), "sub": str(user2.user_id)}
            
            response = client.delete(
                "/api/files/delete",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 403

    def test_delete_nonexistent_file(self, client, test_db_session, sample_user_data):
        """Test deleting non-existent file."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        fake_file_id = str(uuid.uuid4())
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.delete(
                "/api/files/delete",
                json={"file_id": fake_file_id},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 404

    def test_delete_already_deleted_file(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test deleting already deleted file."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}",
            is_deleted=True,
            deleted_at=datetime.now()
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.delete(
                "/api/files/delete",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 404

    def test_delete_creates_audit_log(self, client, test_db_session, sample_user_data, sample_file_data, temp_file_storage):
        """Test that file deletion creates audit log entry."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_uuid = str(uuid.uuid4())
        file_path = os.path.join(temp_file_storage, file_uuid)
        with open(file_path, 'wb') as f:
            f.write(sample_file_data["content"])
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=file_path
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.delete(
                "/api/files/delete",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        
        # Check audit log was created
        audit_logs = test_db_session.query(FileAuditLog).filter_by(action="delete").all()
        assert len(audit_logs) >= 1


class TestFileMetadata:
    """Test file metadata operations."""

    def test_get_file_metadata_success(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test successful file metadata retrieval."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/metadata",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "file_id" in data
        assert "filename_encrypted" in data
        assert "upload_timestamp" in data

    def test_get_file_metadata_unauthorized(self, client, test_db_session, sample_user_data, sample_user_data_2, sample_file_data):
        """Test metadata retrieval without permission."""
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
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user2.user_id), "sub": str(user2.user_id)}
            
            response = client.post(
                "/api/files/metadata",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 403

    def test_metadata_no_sensitive_data_leak(self, client, test_db_session, sample_user_data, sample_file_data):
        """Test that metadata doesn't leak sensitive server information."""
        user = User(**sample_user_data)
        test_db_session.add(user)
        test_db_session.commit()
        
        file_record = File(
            owner_id=user.user_id,
            filename_encrypted=sample_file_data["filename_encrypted"],
            file_size_encrypted=sample_file_data["file_size_encrypted"],
            upload_timestamp=int(datetime.now().timestamp()),
            file_data_hmac=sample_file_data["file_data_hmac"],
            server_storage_path=f"/files/{uuid.uuid4()}"
        )
        test_db_session.add(file_record)
        test_db_session.commit()
        
        with patch('app.core.security.verify_token') as mock_verify:
            mock_verify.return_value = {"user_id": str(user.user_id), "sub": str(user.user_id)}
            
            response = client.post(
                "/api/files/metadata",
                json={"file_id": str(file_record.file_id)},
                headers={"Authorization": "Bearer test_token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should not contain sensitive server paths
        assert "server_storage_path" not in data
        # Encrypted data should be present
        assert "filename_encrypted" in data
        assert "file_size_encrypted" in data 