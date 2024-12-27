"""
Postgres Database table definitions
"""

from typing import TYPE_CHECKING
from datetime import datetime, timedelta, timezone
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy import ForeignKey, ARRAY, delete, func, select, String
from sqlalchemy.orm import Mapped, mapped_column
from trekkers import BaseSql
from ..api.tools import generate_random_password, blake2b_hash

if TYPE_CHECKING:
    from ..api.endpoints.oidc.schemas import RefreshTokenStatus


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
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now()  # pylint: disable=not-callable
    )

    @classmethod
    async def select_id_from_email(cls, email: str, session: AsyncSession):
        """select from the database"""
        return await session.scalar(select(cls.id_).where(cls.email == email))

    @classmethod
    async def select_email_from_id(cls, id_: str, session: AsyncSession):
        """select from the database"""
        return (
            await session.execute(select(cls.email).where(cls.id_ == id_))
        ).scalar_one()


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

    @classmethod
    async def get_user_roles(cls, user_id: UUID, session: AsyncSession):
        """return user roles"""
        return (
            await session.scalars(
                select(UserRoleMapModel.role_id).where(
                    UserRoleMapModel.user_id == user_id
                )
            )
        ).all()


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

    @classmethod
    def get_roles_scopes_stmt(cls, role_ids: list[str]):
        """
        Get user roles stmt
        """
        return select(cls.scope_id).where(cls.role_id.in_(role_ids))


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


class AuthorizationCodeModel(BaseSql):
    """Authorization code intermediary table"""

    __tablename__ = "authorization_codes"
    __table_args__ = {"schema": "auth"}
    code: Mapped[str] = mapped_column(primary_key=True)
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_", ondelete="CASCADE")
    )
    scopes: Mapped[list] = mapped_column(type_=ARRAY(String))
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.id_", ondelete="CASCADE"), primary_key=True
    )
    redirect_uri: Mapped[str]
    code_challenge: Mapped[str] = mapped_column(nullable=True)
    code_challenge_method: Mapped[str] = mapped_column(nullable=True)
    nonce: Mapped[str] = mapped_column(nullable=True)

    async def insert(self, session: AsyncSession):
        """Insert into the database"""
        await session.execute(insert(type(self)).values(self.as_dict()))

    @classmethod
    async def delete(cls, code: str, session: AsyncSession):
        """delete from the database"""
        await session.execute(delete(cls).where(cls.code == code))

    @classmethod
    async def select(cls, code: str, session: AsyncSession):
        """select from the database"""
        return await session.scalar(select(cls).where(cls.code == code))


class SessionModel(BaseSql):
    """Keep track of issued tokens and their status"""

    __tablename__ = "sessions"
    __table_args__ = {"schema": "auth"}

    id_: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("auth.users.id_", ondelete="CASCADE"), primary_key=True
    )
    ip_address: Mapped[str]
    user_agent: Mapped[str]
    scopes: Mapped[list] = mapped_column(type_=ARRAY(String))
    expires_at: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(
        server_default=func.now()  # pylint: disable=not-callable
    )
    last_active_time: Mapped[datetime] = mapped_column(
        server_default=func.now()  # pylint: disable=not-callable
    )

    @classmethod
    async def insert(
        cls,
        user_id: str,
        ip_address: str,
        user_agent: str,
        scopes: list[str],
        session: AsyncSession,
        expires_at: datetime | None = None,
    ):
        """Insert into the database"""
        expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(days=1))
        id_ = generate_random_password()

        await session.execute(
            insert(cls).values(
                id_=blake2b_hash(id_),
                user_id=user_id,
                ip_address=ip_address,
                scopes=scopes,
                user_agent=user_agent,
                expires_at=expires_at,
            )
        )
        return id_, expires_at

    @classmethod
    async def delete(cls, id_: str, session: AsyncSession):
        """delete from the database"""
        await session.execute(delete(cls).where(cls.id_ == blake2b_hash(id_)))

    @classmethod
    async def select(cls, id_: str, session: AsyncSession):
        """select from the database"""
        return await session.scalar(select(cls).where(cls.id_ == blake2b_hash(id_)))


class RefreshTokenModel(BaseSql):
    """Stored refresh tokens"""

    __tablename__ = "refresh_tokens"
    __table_args__ = {"schema": "auth"}

    id_: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.users.id_", ondelete="CASCADE"), primary_key=True
    )
    client_id: Mapped[UUID] = mapped_column(
        ForeignKey("auth.clients.id_", ondelete="CASCADE")
    )
    expires_at: Mapped[datetime]
    issued_at: Mapped[datetime] = mapped_column(
        server_default=func.now()  # pylint: disable=not-callable
    )
    status: Mapped[str]
    scopes: Mapped[list] = mapped_column(type_=ARRAY(String))

    @classmethod
    async def insert(
        cls,
        user_id: str,
        client_id: str,
        scopes: list[str],
        status: "RefreshTokenStatus",
        session: AsyncSession,
    ):
        """Insert into the database"""
        id_ = generate_random_password()

        await session.execute(
            insert(cls).values(
                id_=blake2b_hash(id_),
                user_id=user_id,
                client_id=client_id,
                scopes=scopes,
                status=status,
                expires_at=(datetime.now(timezone.utc) + timedelta(days=1)),
            )
        )
        return id_

    @classmethod
    async def delete(cls, id_: str, session: AsyncSession):
        """delete from the database"""
        await session.execute(delete(cls).where(cls.id_ == blake2b_hash(id_)))

    @classmethod
    async def select(cls, id_: str, session: AsyncSession):
        """select from the database"""
        return await session.scalar(select(cls).where(cls.id_ == blake2b_hash(id_)))
