"""
Initial Setup and migration functions
"""

from datetime import datetime, timezone
from uuid import uuid4
from authapi.api.tools import blake2b_hash
from authapi.database.models import (
    RoleModel,
    RoleScopeMapModel,
    ScopesModel,
    UserModel,
    UserRoleMapModel,
)
from yumi import Scopes
from authapi.schemas import Alg
from authapi.settings import get_settings
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session


def initial_setup(session: Session):
    """
    Setup initial database rows
    """
    for alg in Alg:
        alg.insert_cert(session, alg.generate_private_key())
    session.execute(
        insert(ScopesModel).values([dict(id_=scope.value) for scope in Scopes])
    )
    admin_user_id = uuid4()
    pwd_hash = blake2b_hash(get_settings().admin_password)
    session.execute(
        insert(UserModel).values(
            id_=admin_user_id,
            email="admin@email.com",
            pwd_hash=pwd_hash,
            first_name="admin",
            surname="user",
            dob=datetime.now(timezone.utc).isoformat(),
            postcode="",
        )
    )
    session.execute(insert(RoleModel).values(id_="admin"))
    session.execute(insert(RoleModel).values(id_="standard"))
    session.execute(insert(RoleModel).values(id_="readonly"))
    session.execute(
        insert(RoleScopeMapModel).values(
            [
                dict(scope_id=Scopes.ADMIN.value, role_id="admin"),
                dict(scope_id=Scopes.READ.value, role_id="admin"),
                dict(scope_id=Scopes.WRITE.value, role_id="admin"),
                dict(scope_id=Scopes.OPENID.value, role_id="admin"),
                dict(scope_id=Scopes.EMAIL.value, role_id="admin"),
                dict(scope_id=Scopes.PROFILE.value, role_id="admin"),
                dict(scope_id=Scopes.READ.value, role_id="standard"),
                dict(scope_id=Scopes.WRITE.value, role_id="standard"),
                dict(scope_id=Scopes.OPENID.value, role_id="standard"),
                dict(scope_id=Scopes.EMAIL.value, role_id="standard"),
                dict(scope_id=Scopes.PROFILE.value, role_id="standard"),
                dict(scope_id=Scopes.READ.value, role_id="readonly"),
                dict(scope_id=Scopes.OPENID.value, role_id="readonly"),
                dict(scope_id=Scopes.EMAIL.value, role_id="readonly"),
                dict(scope_id=Scopes.PROFILE.value, role_id="readonly"),
            ]
        )
    )
    session.execute(
        insert(UserRoleMapModel).values(user_id=admin_user_id, role_id="admin")
    )
