"""
Endpoints to manipulate users
Requires admin permissions
"""

from uuid import UUID, uuid4

from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import delete, exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import UserInfo

from ....database.models import (
    RoleModel,
    RoleScopeMapModel,
    UserModel,
    UserRoleMapModel,
)
from ....deps import get_async_session
from ...tools import blake2b_hash
from ...validator import session_has_admin_scope

from .schemas import (
    AddUserRoleBody,
    RoleAddBody,
    RoleScopesBody,
    UserAddBody,
    UserUpdateBody,
)

router = APIRouter(
    tags=["users"],
    dependencies=[Depends(session_has_admin_scope())],
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


async def get_user_roles(user_id: UUID, session: AsyncSession):
    """Get User roles"""
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
async def get_users(
    session: AsyncSession = Depends(get_async_session),
):
    """get all users"""
    users = (await session.scalars(select(UserModel))).all()
    response = list()
    for user in users:
        response.append(
            {
                **user.as_dict(included_keys=user.get_all_keys(["pwd_hash"])),
                "roles": await get_user_roles(user.id_, session),
            }
        )
    return response


@router.get("/users/user")
async def get_user(
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(session_has_admin_scope()),
):
    """Get user information"""
    user = await session.scalar(
        select(UserModel).where(UserModel.email == user_info.sub)
    )
    roles = await get_user_roles(user.id_, session)
    if not user:
        raise HTTPException(400, "user not found")
    return {
        **user.as_dict(included_keys=user.get_all_keys(["pwd_hash", "id_"])),
        "roles": roles,
    }


@router.get("/roles")
async def get_roles(session: AsyncSession = Depends(get_async_session)):
    """get roles"""
    return (await session.scalars(select(RoleModel))).all()


@router.delete("/roles/role")
async def delete_role(role_id: str, session: AsyncSession = Depends(get_async_session)):
    """delete roles"""
    await session.execute(delete(RoleModel).where(RoleModel.id_ == role_id))
    return dict(detail="success")


@router.post("/roles/add")
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
        insert(RoleScopeMapModel).values(scope_id=data.scope_id, role_id=data.role_id)
    )
    return dict(detail="success")


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


@router.delete("/roles/scopes")
async def get_role_scope(
    role_id: str,
    scope_id: str,
    session: AsyncSession = Depends(get_async_session),
):
    """get user scopes"""
    await session.execute(
        delete(RoleScopeMapModel).where(
            RoleScopeMapModel.role_id == role_id,
            RoleScopeMapModel.scope_id == scope_id,
        )
    )
    return {"detail": "success"}
