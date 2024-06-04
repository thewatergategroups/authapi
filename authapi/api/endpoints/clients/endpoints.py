"""
Open ID connect and oAuth Authenticated endpoints.
Requires Admin credentials
"""

from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from sqlalchemy import delete, exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import (
    ClientGrantMapModel,
    ClientModel,
    ClientRedirectsModel,
    ClientRoleMapModel,
)
from ....deps import get_async_session
from ...tools import blake2b_hash, generate_random_password
from ...validator import session_has_admin_scope
from .schemas import (
    ClientAddBody,
    ClientGrantBody,
    ClientPatchBody,
    ClientRedirectBody,
    ClientScopesBody,
)

router = APIRouter(
    prefix="/clients",
    tags=["Clients Authenticated"],
    dependencies=[Depends(session_has_admin_scope())],
)


@router.get("")
async def get_clients(session: AsyncSession = Depends(get_async_session)):
    """Get existing clients"""
    clients = (await session.scalars(select(ClientModel.id_))).all()
    return [await get_client(client, session) for client in clients]


@router.get("/client")
async def get_client(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get specific client information"""
    client = await session.scalar(
        select(ClientModel).where(ClientModel.id_ == client_id)
    )
    if not client:
        raise HTTPException(404, "client not found")
    roles = await get_client_roles(client_id, session)
    redirects = await get_client_redirects(client_id, session)
    grants = await get_client_grants(client_id, session)
    return {
        **client.as_dict(included_keys=["id_", "type", "name", "description"]),
        "roles": roles,
        "redirect_uris": redirects,
        "grant_types": grants,
    }


async def upsert_client_mappings(
    client_id: str,
    grant_types: list[str],
    redirect_uris: list[str],
    roles: list[str],
    session: AsyncSession,
):
    """Upsert client mappings"""
    await session.execute(
        insert(ClientGrantMapModel)
        .values([dict(client_id=client_id, grant_type=gt.value) for gt in grant_types])
        .on_conflict_do_nothing()
    )
    await session.execute(
        insert(ClientRoleMapModel)
        .values([dict(client_id=client_id, role_id=role) for role in roles])
        .on_conflict_do_nothing()
    )
    await session.execute(
        insert(ClientRedirectsModel)
        .values(
            [
                dict(client_id=client_id, redirect_uri=redirect)
                for redirect in redirect_uris
            ]
        )
        .on_conflict_do_nothing()
    )


@router.post("/client")
async def create_client(
    data: ClientAddBody, session: AsyncSession = Depends(get_async_session)
):
    """Create a new client"""
    secret = generate_random_password()
    secret_hash = blake2b_hash(secret)
    id_ = uuid4()
    us_exists = await session.scalar(
        select(exists(ClientModel)).where(ClientModel.id_ == id_)
    )
    if us_exists:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Client already exists")

    await session.execute(
        insert(ClientModel).values(
            id_=id_,
            secret_hash=secret_hash,
            type=data.type.value,
            name=data.name,
            description=data.description,
        )
    )
    await upsert_client_mappings(
        id_, data.grant_types, data.redirect_uris, data.roles, session
    )
    return JSONResponse(
        {
            "client_id": str(id_),
            "client_secret": secret,
            "redirect_uris": data.redirect_uris,
            "grant_types": data.grant_types,
            "roles": data.roles,
            "type": data.type,
        },
        201,
    )


@router.patch("/client")
async def update_client(
    data: ClientPatchBody, session: AsyncSession = Depends(get_async_session)
):
    """Update a clients information"""
    us_exists = await session.scalar(
        select(exists(ClientModel)).where(ClientModel.id_ == data.id_)
    )
    if not us_exists:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Client doesn't exists")
    await session.execute(
        update(ClientModel)
        .where(ClientModel.id_ == data.id_)
        .values(
            type=data.type.value,
            name=data.name,
            description=data.description,
        )
    )
    await upsert_client_mappings(
        data.id_, data.grant_types, data.redirect_uris, data.roles, session
    )
    return dict(detail="success")


@router.post("/client/role")
async def add_client_role(
    data: ClientScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client roles"""
    await session.execute(
        insert(ClientRoleMapModel)
        .values([{"client_id": data.client_id, "role_id": role} for role in data.roles])
        .on_conflict_do_nothing()
    )
    return dict(detail="success")


@router.get("/client/roles")
async def get_client_roles(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client roles"""
    roles = (
        await session.scalars(
            select(ClientRoleMapModel.role_id).where(
                ClientRoleMapModel.client_id == client_id
            )
        )
    ).all()
    return roles


@router.delete("/client/role")
async def delete_client_roles(
    data: ClientScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client scopes"""
    await session.execute(
        delete(ClientRoleMapModel).where(
            ClientRoleMapModel.client_id == data.client_id,
            ClientRoleMapModel.role_id.in_(data.roles),
        )
    )
    return dict(detail="success")


@router.post("/client/redirect")
async def add_client_redirects(
    data: ClientRedirectBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client redirects"""
    await session.execute(
        insert(ClientRedirectsModel).values(
            [
                {"client_id": data.client_id, "redirect_uri": redirect}
                for redirect in data.redirect_uris
            ]
        )
    )
    return dict(detail="success")


@router.get("/client/redirects")
async def get_client_redirects(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client redirects"""
    redirects = (
        await session.scalars(
            select(ClientRedirectsModel.redirect_uri).where(
                ClientRedirectsModel.client_id == client_id
            )
        )
    ).all()
    return redirects


@router.delete("/client/redirect")
async def delete_client_redirects(
    data: ClientRedirectBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client redirects"""
    await session.execute(
        delete(ClientRedirectsModel).where(
            ClientRedirectsModel.client_id == data.client_id,
            ClientRedirectsModel.redirect_uri.in_(data.redirect_uris),
        )
    )
    return dict(detail="success")


@router.post("/client/grants")
async def add_client_grants(
    data: ClientGrantBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client grants"""
    await session.execute(
        insert(ClientGrantMapModel).values(
            [
                {"client_id": data.client_id, "grant_type": grant}
                for grant in data.grants
            ]
        )
    )
    return dict(detail="success")


@router.get("client/grants")
async def get_client_grants(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client grants"""
    scopes = (
        await session.scalars(
            select(ClientGrantMapModel.grant_type).where(
                ClientGrantMapModel.client_id == client_id
            )
        )
    ).all()
    return scopes


@router.delete("/client/grants")
async def delete_client_grants(
    data: ClientGrantBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client grants"""
    await session.execute(
        delete(ClientGrantMapModel).where(
            ClientGrantMapModel.client_id == data.client_id,
            ClientGrantMapModel.grant_type.in_(data.grants),
        )
    )
    return dict(detail="success")
