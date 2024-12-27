# pylint: disable=all
"""

Revision ID: 8e3978646935
Revises: 3f947ef59696
Create Date: 2024-04-14 00:55:35.048719

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8e3978646935"
down_revision: Union[str, None] = "3f947ef59696"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "authorization_codes",
        sa.Column("nonce", sa.String(), nullable=True),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_column("authorization_codes", "nonce", schema="auth")
