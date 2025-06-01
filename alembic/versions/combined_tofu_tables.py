"""Combined TOFU tables

Revision ID: combined_tofu_tables
Revises: 
Create Date: 2024-03-21

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision = 'combined_tofu_tables'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Users table
    op.create_table(
        'users',
        sa.Column('username', sa.String(50), primary_key=True),
        sa.Column('auth_salt', sa.String(64), nullable=False),
        sa.Column('enc_salt', sa.String(64), nullable=False),
        sa.Column('auth_key', sa.String(128), nullable=False),
        sa.Column('encrypted_mek', sa.String(256), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

    # Device Certificates table
    op.create_table(
        'device_certificates',
        sa.Column('cert_id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('username', sa.String(50), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('device_id', sa.String(64), nullable=False),
        sa.Column('public_key', sa.LargeBinary, nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('signature', sa.LargeBinary, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.UniqueConstraint('username', 'device_id', name='uq_device_certificates_user_device')
    )

    # Trust Relationships table
    op.create_table(
        'trust_relationships',
        sa.Column('trust_id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('username', sa.String(50), sa.ForeignKey('users.username'), nullable=False),
        sa.Column('trusted_cert_id', UUID(as_uuid=True), sa.ForeignKey('device_certificates.cert_id', ondelete='CASCADE'), nullable=False),
        sa.Column('trust_level', sa.String(20), nullable=False),  # 'untrusted', 'tofu', 'verified'
        sa.Column('verification_method', sa.String(20)),  # 'qr', 'voice', etc.
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

    # Verification Events table
    op.create_table(
        'verification_events',
        sa.Column('event_id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('trust_id', UUID(as_uuid=True), sa.ForeignKey('trust_relationships.trust_id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(20), nullable=False),  # 'verify', 'revoke', etc.
        sa.Column('method', sa.String(20)),  # 'qr', 'voice', etc.
        sa.Column('success', sa.Boolean, nullable=False),
        sa.Column('details', sa.Text),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )

    # Add indexes for better query performance
    op.create_index('idx_device_certs_username', 'device_certificates', ['username'])
    op.create_index('idx_trust_username', 'trust_relationships', ['username'])
    op.create_index('idx_trust_cert_id', 'trust_relationships', ['trusted_cert_id'])
    op.create_index('idx_verification_trust_id', 'verification_events', ['trust_id'])
    op.create_index('idx_verification_created_at', 'verification_events', ['created_at'])

def downgrade() -> None:
    # Drop in reverse order due to foreign key dependencies
    op.drop_table('verification_events')
    op.drop_table('trust_relationships')
    op.drop_table('device_certificates')
    op.drop_table('users') 