"""initial_sqlite_schema

Revision ID: ea0b044f8dc1
Revises: 
Create Date: 2025-01-XX XX:XX:XX.XXXXXX

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'ea0b044f8dc1'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create users table - Using String(36) for UUIDs in SQLite
    op.create_table('users',
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('username', sa.String(255), nullable=False),
        sa.Column('auth_salt', sa.String(64), nullable=False),
        sa.Column('auth_salt_2', sa.String(64), nullable=False),
        sa.Column('enc_salt', sa.String(64), nullable=False),
        sa.Column('auth_hash', sa.String(128), nullable=False),
        sa.Column('encrypted_mek', sa.LargeBinary(), nullable=False),
        sa.Column('totp_secret', sa.LargeBinary(), nullable=False),
        sa.Column('totp_last_counter', sa.BigInteger(), nullable=True),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('user_data_hmac', sa.String(64), nullable=False),
        sa.PrimaryKeyConstraint('user_id'),
        sa.UniqueConstraint('username')
    )

    # Create files table
    op.create_table('files',
        sa.Column('file_id', sa.String(36), nullable=False),
        sa.Column('owner_id', sa.String(36), nullable=False),
        sa.Column('filename_encrypted', sa.LargeBinary(), nullable=False),
        sa.Column('file_size_encrypted', sa.LargeBinary(), nullable=False),
        sa.Column('upload_timestamp', sa.BigInteger(), nullable=False),
        sa.Column('file_data_hmac', sa.String(64), nullable=False),
        sa.Column('server_storage_path', sa.String(255), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=True),
        sa.Column('deleted_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['owner_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('file_id')
    )

    # Create shares table
    op.create_table('shares',
        sa.Column('share_id', sa.String(36), nullable=False),
        sa.Column('file_id', sa.String(36), nullable=False),
        sa.Column('owner_id', sa.String(36), nullable=False),
        sa.Column('recipient_id', sa.String(36), nullable=False),
        sa.Column('encrypted_data_key', sa.LargeBinary(), nullable=False),
        sa.Column('granted_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('share_grant_hmac', sa.String(64), nullable=False),
        sa.Column('share_chain_hmac', sa.String(64), nullable=False),
        sa.ForeignKeyConstraint(['file_id'], ['files.file_id'], ),
        sa.ForeignKeyConstraint(['owner_id'], ['users.user_id'], ),
        sa.ForeignKeyConstraint(['recipient_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('share_id'),
        sa.UniqueConstraint('file_id', 'recipient_id', name='unique_file_recipient')
    )

    # Create audit log table
    op.create_table('file_audit_log',
        sa.Column('log_id', sa.String(36), nullable=False),
        sa.Column('file_id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('timestamp', sa.BigInteger(), nullable=False),
        sa.Column('client_ip_hash', sa.String(64), nullable=True),
        sa.Column('log_entry_hmac', sa.String(64), nullable=False),
        sa.Column('previous_log_hmac', sa.String(64), nullable=True),
        sa.ForeignKeyConstraint(['file_id'], ['files.file_id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('log_id')
    )

    op.create_index('idx_file_timestamp', 'file_audit_log', ['file_id', 'timestamp'])

def downgrade() -> None:
    op.drop_table('file_audit_log')
    op.drop_table('shares')
    op.drop_table('files')
    op.drop_table('users') 