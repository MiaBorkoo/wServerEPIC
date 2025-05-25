"""remove_permission_level_from_shares

Revision ID: 4212bd91c299
Revises: 6a500fdea007
Create Date: 2025-05-25 20:30:41.185185

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4212bd91c299'
down_revision: Union[str, None] = '6a500fdea007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove permission_level column from shares table
    op.drop_column('shares', 'permission_level')


def downgrade() -> None:
    # Add back permission_level column to shares table
    op.add_column('shares', sa.Column('permission_level', sa.String(20), nullable=False, server_default='read'))
