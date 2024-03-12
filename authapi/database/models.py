"""
Postgres Database table definitions
"""

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
    """table definition for storing user data"""

    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}
    username: Mapped[str] = mapped_column(primary_key=True)
    pwd_hash: Mapped[str]


class ScopesModel(BaseSql):
    """table definition for storing avaliable scopes"""

    __tablename__ = "scopes"
    __table_args__ = {"schema": "auth"}
    id_: Mapped[str] = mapped_column(primary_key=True)


class UserScopeModel(BaseSql):
    """table definition for storing what scopes users have"""

    __tablename__ = "user_scopes"
    __table_args__ = {"schema": "auth"}
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("auth.scopes.id_"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("auth.users.username"), primary_key=True
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


class ClientGrantMap(BaseSql):
    """table definition that maps clients to their allowed grant types"""

    __tablename__ = "client_grants"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_"), primary_key=True
    )
    grant_type: Mapped[str] = mapped_column(primary_key=True)


class ClientScopeMap(BaseSql):
    """table definition that maps clients to their allowed scopes"""

    __tablename__ = "client_scopes"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_"), primary_key=True
    )
    scope: Mapped[str] = mapped_column(ForeignKey("auth.scopes.id_"), primary_key=True)


class ClientRedirects(BaseSql):
    """table definition that maps clients to their allowed redirect_urls"""

    __tablename__ = "client_redirect_uris"
    __table_args__ = {"schema": "auth"}
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_"), primary_key=True
    )
    redirect_uri: Mapped[str] = mapped_column(primary_key=True)
