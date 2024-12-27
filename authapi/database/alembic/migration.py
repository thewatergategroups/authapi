"""
Initial Setup and migration functions
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session
from yumi import Scopes

from authapi.api.tools import blake2b_hash
from authapi.database.models import (
    RoleModel,
    RoleScopeMapModel,
    ScopesModel,
    UserModel,
    UserRoleMapModel,
)
from authapi.schemas import Alg
from authapi.settings import get_settings


def insert_role(
    id_: str,
    scopes: list[Scopes],
    session: Session,
):
    """insert role and scopes"""
    session.execute(insert(RoleModel).values(id_=id_).on_conflict_do_nothing())
    session.execute(
        insert(RoleScopeMapModel)
        .values([dict(scope_id=scope, role_id=id_) for scope in scopes])
        .on_conflict_do_nothing()
    )


def initial_setup(session: Session):
    """
    Setup initial database rows
    """
    for alg in Alg:
        alg.insert_cert(session, alg.generate_private_key())
    session.execute(
        insert(ScopesModel)
        .values([dict(id_=scope.value) for scope in Scopes])
        .on_conflict_do_nothing()
    )
    admin_user_id = uuid4()
    pwd_hash = blake2b_hash(get_settings().admin_password)
    session.execute(
        insert(UserModel)
        .values(
            id_=admin_user_id,
            email="admin@email.com",
            pwd_hash=pwd_hash,
            first_name="admin",
            surname="user",
            dob=datetime.now(timezone.utc).isoformat(),
            postcode="",
        )
        .on_conflict_do_nothing()
    )
    insert_role("admin", [scope.value for scope in Scopes], session)
    insert_role(
        "standard",
        [scope.value for scope in Scopes if scope != Scopes.ADMIN],
        session,
    )
    insert_role(
        "readonly",
        [scope.value for scope in Scopes if scope not in (Scopes.ADMIN, Scopes.WRITE)],
        session,
    )

    session.execute(
        insert(UserRoleMapModel)
        .values(user_id=admin_user_id, role_id="admin")
        .on_conflict_do_nothing()
    )
