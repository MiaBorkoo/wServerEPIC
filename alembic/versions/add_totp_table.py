"""add totp table

Revision ID: add_totp_table
Revises: a699d561e032
Create Date: 2025-06-01 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_totp_table'
down_revision = 'a699d561e032'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create TOTP table
    op.create_table(
        'user_totp',
        sa.Column('username', sa.String(50), sa.ForeignKey('users.username', ondelete='CASCADE'), primary_key=True),
        sa.Column('totp_secret', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False)
    )
    
    # Add index for better query performance
    op.create_index('idx_user_totp_username', 'user_totp', ['username'])

def downgrade() -> None:
    # Drop TOTP table and its index
    op.drop_index('idx_user_totp_username', table_name='user_totp')
    op.drop_table('user_totp') 