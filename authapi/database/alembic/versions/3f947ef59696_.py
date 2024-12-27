# pylint: disable=all
"""

Revision ID: 3f947ef59696
Revises: 882caf233a8d
Create Date: 2024-04-08 20:44:29.164226

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "3f947ef59696"
down_revision: Union[str, None] = "882caf233a8d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id_", sa.String(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("user_agent", sa.String(), nullable=False),
        sa.Column("scopes", sa.ARRAY(sa.String()), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column(
            "last_active_time",
            sa.DateTime(),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["auth.users.id_"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id_", "user_id"),
        schema="auth",
    )


def downgrade() -> None:
    op.drop_table("sessions", schema="auth")
