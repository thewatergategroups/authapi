"""
Postgres Database table definitions
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from trekkers import BaseSql


class CertModel(BaseSql):
    """table definition for storing private key certificates"""

    __tablename__ = "certs"
    __table_args__ = {"schema": "auth"}
    alg: Mapped[str] = mapped_column(primary_key=True)
    cert: Mapped[bytes]


class UserModel(BaseSql):
    """
    table definition for storing user data
    Username is email
    """

    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}
    id_: Mapped[UUID] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(unique=True)
    pwd_hash: Mapped[str]
    first_name: Mapped[str]
    surname: Mapped[str]
    dob: Mapped[datetime]
    postcode: Mapped[str]


class RoleModel(BaseSql):
    """
    User Roles too simplify adding permissions
    """

    __tablename__ = "roles"
    __table_args__ = {"schema": "auth"}

    id_: Mapped[str] = mapped_column(primary_key=True)


class UserRoleMapModel(BaseSql):
    """
    table definition that maps users to their assigned roles
    """

    __tablename__ = "user_roles"
    __table_args__ = {"schema": "auth"}
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.id_", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        ForeignKey("auth.roles.id_", ondelete="CASCADE"), primary_key=True
    )


class ScopesModel(BaseSql):
    """table definition for storing avaliable scopes"""

    __tablename__ = "scopes"
    __table_args__ = {"schema": "auth"}
    id_: Mapped[str] = mapped_column(primary_key=True)


class RoleScopeMapModel(BaseSql):
    """table definition for storing what scopes users have"""

    __tablename__ = "role_scopes"
    __table_args__ = {"schema": "auth"}
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("auth.scopes.id_", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        ForeignKey("auth.roles.id_", ondelete="CASCADE"), primary_key=True
    )


class ClientModel(BaseSql):
    """table definition for storing client data"""

    __tablename__ = "clients"
    __table_args__ = {"schema": "auth"}
    id_: Mapped[UUID] = mapped_column(primary_key=True)
    secret_hash: Mapped[str]
    type: Mapped[str]
    name: Mapped[str]
    description: Mapped[str]


class ClientGrantMapModel(BaseSql):
    """table definition that maps clients to their allowed grant types"""

    __tablename__ = "client_grants"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_", ondelete="CASCADE"),
        primary_key=True,
    )
    grant_type: Mapped[str] = mapped_column(primary_key=True)


class ClientRoleMapModel(BaseSql):
    """table definition that maps clients to their allowed scopes"""

    __tablename__ = "client_roles"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        ForeignKey("auth.roles.id_", ondelete="CASCADE"), primary_key=True
    )


class ClientRedirectsModel(BaseSql):
    """table definition that maps clients to their allowed redirect_urls"""

    __tablename__ = "client_redirect_uris"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_", ondelete="CASCADE"), primary_key=True
    )
    redirect_uri: Mapped[str] = mapped_column(primary_key=True)
