"""
Endpoints to manipulate users
Requires admin permissions
"""

from uuid import UUID, uuid4
from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import UserInfo
from ....database.models import (
    UserModel,
    RoleScopeMapModel,
    RoleModel,
    UserRoleMapModel,
)
from ....deps import get_async_session
from ...tools import blake2b_hash
from ...validator import has_admin_scope, validate_jwt
from .schemas import (
    RoleAddBody,
    UserAddBody,
    RoleScopesBody,
    UserUpdateBody,
    AddUserRoleBody,
)

router = APIRouter(
    tags=["users"],
    dependencies=[Depends(has_admin_scope())],
)


@router.post("/users/add")
async def create_user(
    data: UserAddBody,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(UserModel.email == data.email)
    )
    if us_exists:
        raise HTTPException(400, "User already Exists")

    await session.execute(
        insert(UserModel).values(
            id_=uuid4(),
            email=data.email,
            pwd_hash=passwd,
            first_name=data.first_name,
            surname=data.surname,
            dob=data.dob,
            postcode=data.postcode,
        )
    )

    return {"detail": "success"}


@router.post("/users/user/roles")
async def add_user_role(
    data: AddUserRoleBody,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""

    await session.execute(
        insert(UserRoleMapModel)
        .values(user_id=data.user_id, role_id=data.role_id)
        .on_conflict_do_nothing()
    )

    return {"detail": "success"}


@router.get("/users/user/roles")
async def get_user_roles(
    user_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""

    return (
        await session.scalars(
            select(UserRoleMapModel.role_id).where(UserRoleMapModel.user_id == user_id)
        )
    ).all()


@router.patch("/users/update")
async def update_user(
    data: UserUpdateBody,
    session: AsyncSession = Depends(get_async_session),
):
    """update user endpoint"""
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(UserModel.email == data.email)
    )
    if not us_exists:
        raise HTTPException(400, "User already Exists")

    await session.execute(
        update(UserModel)
        .where(UserModel.email == data.email)
        .values(
            pwd_hash=passwd,
            email=data.email,
            first_name=data.first_name,
            surname=data.surname,
            dob=data.dob,
            postcode=data.postcode,
        )
    )

    return {"detail": "success"}


@router.get("/users")
async def get_users(session: AsyncSession = Depends(get_async_session)):
    """get all users"""
    users = (await session.scalars(select(UserModel.email))).all()
    return users


@router.get("/users/user")
async def get_user(
    user_info: UserInfo = Depends(validate_jwt),
    session: AsyncSession = Depends(get_async_session),
):
    """Get user information"""
    roles = await get_user_roles(user_info.username, session)
    user = await session.scalar(
        select(UserModel).where(UserModel.id_ == user_info.username)
    )
    if not user:
        raise HTTPException(400, "user not found")
    return {
        **user.as_dict(included_keys=[user.get_all_keys(["pws_hash"])]),
        "roles": roles,
    }


@router.get("/roles/add")
async def add_role(
    body: RoleAddBody,
    session: AsyncSession = Depends(get_async_session),
):
    """Add role with scopes"""
    await session.execute(insert(RoleModel).values(id_=body.role_id))
    stmt = (
        insert(RoleScopeMapModel)
        .values([dict(scope_id=scope, role_id=body.role_id) for scope in body.scopes])
        .on_conflict_do_nothing()
    )
    await session.execute(stmt)
    return {"detail": "success"}


@router.post("/roles/scopes")
async def add_role_scopes(
    data: RoleScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add role scopes"""
    await session.execute(
        insert(RoleScopeMapModel).values(scope_id=data.scope, role_id=data.role_id)
    )
    return {"detail": "success"}


@router.get("/roles/scopes")
async def get_role_scopes(
    role_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    """get user scopes"""
    scopes = (
        await session.scalars(
            select(RoleScopeMapModel.scope_id).where(
                RoleScopeMapModel.role_id == role_id
            )
        )
    ).all()
    return scopes
