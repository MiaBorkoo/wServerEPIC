"""add_auth_salt_2_and_fix_auth_hash

Revision ID: 9857ebd0cff8
Revises: 6824db4ccd06
Create Date: 2025-06-05 11:07:46.635955

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9857ebd0cff8'
down_revision: Union[str, None] = '6824db4ccd06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add missing auth_salt_2 column
    op.add_column('users', sa.Column('auth_salt_2', sa.String(64), nullable=False, server_default=''))
    
    # Rename auth_key column to auth_hash to match SQLAlchemy model
    op.alter_column('users', 'auth_key', new_column_name='auth_hash')
    
    # Remove the temporary server_default after adding the column
    op.alter_column('users', 'auth_salt_2', server_default=None)


def downgrade() -> None:
    # Rename auth_hash back to auth_key
    op.alter_column('users', 'auth_hash', new_column_name='auth_key')
    
    # Remove auth_salt_2 column
    op.drop_column('users', 'auth_salt_2')
