# pylint: disable=all
"""

Revision ID: 4c15bf461b81
Revises: 
Create Date: 2024-03-30 10:55:36.917681

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import orm

from authapi.database.alembic.migration import initial_setup

# revision identifiers, used by Alembic.
revision: str = "4c15bf461b81"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###

    op.create_table(
        "certs",
        sa.Column("alg", sa.String(), nullable=False),
        sa.Column("cert", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("alg"),
        schema="auth",
    )
    op.create_table(
        "clients",
        sa.Column("id_", sa.Uuid(), nullable=False),
        sa.Column("secret_hash", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id_"),
        schema="auth",
    )
    op.create_table(
        "roles",
        sa.Column("id_", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id_"),
        schema="auth",
    )
    op.create_table(
        "scopes",
        sa.Column("id_", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id_"),
        schema="auth",
    )
    op.create_table(
        "users",
        sa.Column("id_", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("pwd_hash", sa.String(), nullable=False),
        sa.Column("first_name", sa.String(), nullable=False),
        sa.Column("surname", sa.String(), nullable=False),
        sa.Column("dob", sa.DateTime(), nullable=False),
        sa.Column("postcode", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id_"),
        sa.UniqueConstraint("email"),
        schema="auth",
    )
    op.create_table(
        "client_grants",
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("grant_type", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["auth.clients.id_"],
        ),
        sa.PrimaryKeyConstraint("client_id", "grant_type"),
        schema="auth",
    )
    op.create_table(
        "client_redirect_uris",
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("redirect_uri", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["auth.clients.id_"],
        ),
        sa.PrimaryKeyConstraint("client_id", "redirect_uri"),
        schema="auth",
    )
    op.create_table(
        "client_roles",
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["auth.clients.id_"],
        ),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["auth.roles.id_"],
        ),
        sa.PrimaryKeyConstraint("client_id", "role_id"),
        schema="auth",
    )
    op.create_table(
        "role_scopes",
        sa.Column("scope_id", sa.String(), nullable=False),
        sa.Column("role_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["auth.roles.id_"],
        ),
        sa.ForeignKeyConstraint(
            ["scope_id"],
            ["auth.scopes.id_"],
        ),
        sa.PrimaryKeyConstraint("scope_id", "role_id"),
        schema="auth",
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["role_id"],
            ["auth.roles.id_"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["auth.users.id_"],
        ),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
        schema="auth",
    )
    # ### end Alembic commands ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)
    initial_setup(session)


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("user_roles", schema="auth")
    op.drop_table("role_scopes", schema="auth")
    op.drop_table("client_roles", schema="auth")
    op.drop_table("client_redirect_uris", schema="auth")
    op.drop_table("client_grants", schema="auth")
    op.drop_table("users", schema="auth")
    op.drop_table("scopes", schema="auth")
    op.drop_table("roles", schema="auth")
    op.drop_table("clients", schema="auth")
    op.drop_table("certs", schema="auth")
    # ### end Alembic commands ###
