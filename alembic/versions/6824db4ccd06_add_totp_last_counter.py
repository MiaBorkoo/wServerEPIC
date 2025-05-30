"""add totp_last_counter

Revision ID: 6824db4ccd06
Revises: ea0b044f8dc1
Create Date: 2025-05-30 17:09:05.596284

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6824db4ccd06'
down_revision: Union[str, None] = 'ea0b044f8dc1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
