"""add totp_last_counter

Revision ID: 2965532d0812
Revises: 6c518c6b5d96
Create Date: 2025-05-30 13:53:58.775701

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2965532d0812'
down_revision: Union[str, None] = '6c518c6b5d96'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_last_counter", sa.BigInteger()))



def downgrade() -> None:
    op.drop_column("users", "totp_last_counter")

