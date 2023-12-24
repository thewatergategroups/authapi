from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from trekkers import BaseSql


class UserModel(BaseSql):
    __tablename__ = "users"
    __table_args__ = {"schema": "auth"}
    username: Mapped[str] = mapped_column(primary_key=True)
    pwd_hash: Mapped[str]


class ScopesModel(BaseSql):
    __tablename__ = "scopes"
    __table_args__ = {"schema": "auth"}
    id_: Mapped[str] = mapped_column(primary_key=True)


class UserScopeModel(BaseSql):
    __tablename__ = "user_scopes"
    __table_args__ = {"schema": "auth"}
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("auth.scopes.id_"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        ForeignKey("auth.users.username"), primary_key=True
    )
