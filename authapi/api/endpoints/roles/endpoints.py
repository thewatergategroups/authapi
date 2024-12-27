"""
Role Endpoints
Requires admin permissions
"""

from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import delete, exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import RoleModel, RoleScopeMapModel
from ....deps import get_async_session
from ...validator import session_has_admin_scope

from .schemas import RoleAddPatchBody, RoleScopesBody

router = APIRouter(
    tags=["Roles Authenticated"],
    prefix="/roles",
    dependencies=[Depends(session_has_admin_scope())],
)


@router.get("")
async def get_roles(session: AsyncSession = Depends(get_async_session)):
    """get roles"""
    response = list()
    roles = (await session.scalars(select(RoleModel))).all()
    for role in roles:
        scopes = await session.scalars(
            select(RoleScopeMapModel).where(RoleScopeMapModel.role_id == role.id_)
        )
        response.append(dict(id_=role.id_, scopes=[scope.scope_id for scope in scopes]))

    return response


@router.delete("/role")
async def delete_role(id_: str, session: AsyncSession = Depends(get_async_session)):
    """delete roles"""
    await session.execute(
        delete(RoleScopeMapModel).where(RoleScopeMapModel.role_id == id_)
    )
    await session.execute(delete(RoleModel).where(RoleModel.id_ == id_))
    return dict(detail="success")


@router.post("/role")
async def add_role(
    data: RoleAddPatchBody,
    session: AsyncSession = Depends(get_async_session),
):
    """Add role with scopes"""
    does_exists = await session.scalar(
        select(exists(RoleModel)).where(RoleModel.id_ == data.id_)
    )
    if does_exists:
        raise HTTPException(400, "Role already Exists")

    await session.execute(insert(RoleModel).values(id_=data.id_))
    stmt = (
        insert(RoleScopeMapModel)
        .values([dict(scope_id=scope, role_id=data.id_) for scope in data.scopes])
        .on_conflict_do_nothing()
    )
    await session.execute(stmt)
    return dict(detail="success")


@router.patch("/role")
async def update_role(
    data: RoleAddPatchBody,
    session: AsyncSession = Depends(get_async_session),
):
    """Add role with scopes"""
    does_exists = await session.scalar(
        select(exists(RoleModel)).where(RoleModel.id_ == data.id_)
    )
    if not does_exists:
        raise HTTPException(400, "Role does not exist")
    await session.execute(
        delete(RoleScopeMapModel).where(
            RoleScopeMapModel.role_id == data.id_,
            RoleScopeMapModel.scope_id.notin_(data.scopes),
        )
    )

    stmt = (
        insert(RoleScopeMapModel)
        .values([dict(scope_id=scope, role_id=data.id_) for scope in data.scopes])
        .on_conflict_do_nothing()
    )
    await session.execute(stmt)
    return dict(detail="success")


@router.post("/role/scopes")
async def add_role_scopes(
    data: RoleScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add role scopes"""
    await session.execute(
        insert(RoleScopeMapModel).values(scope_id=data.scope_id, role_id=data.role_id)
    )
    return dict(detail="success")


@router.get("/role/scopes")
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


@router.delete("/role/scopes")
async def delete_role_scope(
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
    return dict(detail="success")
