"""add_tofu_tables

Revision ID: c6c1ec2167f7
Revises: 9857ebd0cff8
Create Date: 2025-06-05 11:12:27.717757

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c6c1ec2167f7'
down_revision: Union[str, None] = '9857ebd0cff8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create device_certificates table
    op.create_table('device_certificates',
        sa.Column('cert_id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('device_id', sa.String(64), nullable=False),
        sa.Column('public_key', sa.LargeBinary(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('signature', sa.LargeBinary(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.PrimaryKeyConstraint('cert_id'),
        sa.UniqueConstraint('user_id', 'device_id', name='unique_user_device')
    )
    op.create_index('idx_device_user_id', 'device_certificates', ['user_id'])

    # Create trust_relationships table
    op.create_table('trust_relationships',
        sa.Column('trust_id', sa.String(36), nullable=False),
        sa.Column('user_id', sa.String(36), nullable=False),
        sa.Column('trusted_cert_id', sa.String(36), nullable=False),
        sa.Column('trust_level', sa.String(20), nullable=False),
        sa.Column('verification_method', sa.String(20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.user_id'], ),
        sa.ForeignKeyConstraint(['trusted_cert_id'], ['device_certificates.cert_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('trust_id')
    )
    op.create_index('idx_trust_user_id', 'trust_relationships', ['user_id'])
    op.create_index('idx_trust_cert_id', 'trust_relationships', ['trusted_cert_id'])

    # Create verification_events table
    op.create_table('verification_events',
        sa.Column('event_id', sa.String(36), nullable=False),
        sa.Column('trust_id', sa.String(36), nullable=False),
        sa.Column('event_type', sa.String(20), nullable=False),
        sa.Column('method', sa.String(20), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['trust_id'], ['trust_relationships.trust_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index('idx_verification_trust_id', 'verification_events', ['trust_id'])
    op.create_index('idx_verification_created_at', 'verification_events', ['created_at'])


def downgrade() -> None:
    op.drop_table('verification_events')
    op.drop_table('trust_relationships')
    op.drop_table('device_certificates')
