"""setup

Revision ID: 27bd1d973b2d
Revises: 
Create Date: 2023-12-24 11:47:54.172330

"""
import random
import string
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from authapi.api.tools import blake2b_hash

# revision identifiers, used by Alembic.
revision: str = "27bd1d973b2d"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "scopes",
        sa.Column("id_", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id_"),
        schema="auth",
    )
    op.execute(sa.text("INSERT INTO auth.scopes (id_) VALUES ('admin')"))
    op.execute(sa.text("INSERT INTO auth.scopes (id_) VALUES ('read')"))
    op.execute(sa.text("INSERT INTO auth.scopes (id_) VALUES ('write')"))
    op.create_table(
        "users",
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("pwd_hash", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("username"),
        schema="auth",
    )
    letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
    result_str = "".join(random.choice(letters) for i in range(64))
    pwd_hash = blake2b_hash(result_str)
    op.execute(
        sa.text(
            f"INSERT INTO auth.users (username,pwd_hash) VALUES ('admin','{pwd_hash}')"
        )
    )
    op.create_table(
        "user_scopes",
        sa.Column("scope_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["scope_id"],
            ["auth.scopes.id_"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["auth.users.username"],
        ),
        sa.PrimaryKeyConstraint("scope_id", "user_id"),
        schema="auth",
    )
    op.execute(
        sa.text(
            "INSERT INTO auth.user_scopes (scope_id,user_id) VALUES ('admin','admin')"
        )
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("user_scopes", schema="auth")
    op.drop_table("users", schema="auth")
    op.drop_table("scopes", schema="auth")
    # ### end Alembic commands ###
