"""File tables

Revision ID: file_tables
Revises: combined_tofu_tables
Create Date: 2024-03-21

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = 'file_tables'
down_revision = 'combined_tofu_tables'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Files table
    op.create_table(
        'files',
        sa.Column('file_uuid', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('owner_id', sa.String(50), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('size', sa.Float, nullable=False),
        sa.Column('encrypted_file', sa.Text, nullable=False),
        sa.Column('integrity_hash', sa.String(128), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

    # Shared Files table
    op.create_table(
        'shared_files',
        sa.Column('share_id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('file_id', UUID(as_uuid=True), sa.ForeignKey('files.file_uuid', ondelete='CASCADE'), nullable=False),
        sa.Column('owner_id', sa.String(50), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('recipient_id', sa.String(50), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('encrypted_file_key', sa.String(256), nullable=False),
        sa.Column('shared_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True))
    )

    # Add indexes for better query performance
    op.create_index('idx_files_owner', 'files', ['owner_id'])
    op.create_index('idx_shared_files_owner', 'shared_files', ['owner_id'])
    op.create_index('idx_shared_files_recipient', 'shared_files', ['recipient_id'])
    op.create_index('idx_shared_files_expires', 'shared_files', ['expires_at'])

def downgrade() -> None:
    # Drop in reverse order due to foreign key dependencies
    op.drop_table('shared_files')
    op.drop_table('files') 