"""
Open ID connect and oAuth Authenticated endpoints.
Requires Admin credentials
"""

from uuid import UUID, uuid4

from fastapi import Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from sqlalchemy import exists, insert, select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import (
    ClientGrantMap,
    ClientModel,
    ClientRedirects,
    ClientScopeMap,
)
from ....deps import get_async_session
from ...tools import blake2b_hash, generate_random_password
from ...validator import has_admin_scope
from .schemas import (
    ClientAddBody,
    ClientGrantBody,
    ClientRedirectBody,
    ClientScopesBody,
)

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
    dependencies=[Depends(has_admin_scope())],
)


@router.post("/create")
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
        raise HTTPException(500, "Please try again")

    await session.execute(
        insert(ClientModel).values(
            id_=id_,
            secret_hash=secret_hash,
            type=data.type.value,
            name=data.name,
            description=data.description,
        )
    )
    await session.execute(
        insert(ClientGrantMap).values(
            [{"client_id": id_, "grant_type": gt.value} for gt in data.grant_types]
        )
    )
    await session.execute(
        insert(ClientScopeMap).values(
            [{"client_id": id_, "scope": scope} for scope in data.scopes]
        )
    )
    await session.execute(
        insert(ClientRedirects).values(
            [
                {"client_id": id_, "redirect_uri": redirect}
                for redirect in data.redirect_uris
            ]
        )
    )
    return JSONResponse(
        {
            "client_id": str(id_),
            "client_secret": secret,
            "redirect_uris": data.redirect_uris,
            "grant_types": data.grant_types,
            "scopes": data.scopes,
            "type": data.type,
        },
        201,
    )


@router.get("")
async def get_clients(session: AsyncSession = Depends(get_async_session)):
    """Get existing clients"""

    users = (await session.scalars(select(ClientModel.id_, ClientModel.name))).all()
    return users


@router.post("/scopes")
async def add_client_scopes(
    data: ClientScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client scopes"""
    await session.execute(
        insert(ClientScopeMap).values(
            [{"client_id": data.client_id, "scope": scope} for scope in data.scopes]
        )
    )
    return {"detail": "success"}


@router.get("/scopes")
async def get_client_scopes(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client scopes"""
    scopes = (
        await session.scalars(
            select(ClientScopeMap.scope).where(ClientScopeMap.client_id == client_id)
        )
    ).all()
    return scopes


@router.delete("/scopes")
async def delete_client_scopes(
    data: ClientScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client scopes"""
    await session.execute(
        delete(ClientScopeMap).where(
            ClientScopeMap.client_id == data.client_id,
            ClientScopeMap.scope.in_(data.scopes),
        )
    )
    return {"detail": "success"}


@router.post("/redirect")
async def add_client_redirects(
    data: ClientRedirectBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client redirects"""
    await session.execute(
        insert(ClientRedirects).values(
            [
                {"client_id": data.client_id, "redirect_uri": redirect}
                for redirect in data.redirect_uris
            ]
        )
    )
    return {"detail": "success"}


@router.get("/redirects")
async def get_client_redirects(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client redirects"""
    scopes = (
        await session.scalars(
            select(ClientRedirects.redirect_uri).where(
                ClientRedirects.client_id == client_id
            )
        )
    ).all()
    return scopes


@router.delete("/redirect")
async def delete_client_redirects(
    data: ClientRedirectBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client redirects"""
    await session.execute(
        delete(ClientRedirects).where(
            ClientRedirects.client_id == data.client_id,
            ClientRedirects.redirect_uri.in_(data.redirect_uris),
        )
    )
    return {"detail": "success"}


@router.post("/grants")
async def add_client_grants(
    data: ClientGrantBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add client grants"""
    await session.execute(
        insert(ClientGrantMap).values(
            [
                {"client_id": data.client_id, "grant_type": grant}
                for grant in data.grants
            ]
        )
    )
    return {"detail": "success"}


@router.get("/grants")
async def get_client_grants(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    """get client grants"""
    scopes = (
        await session.scalars(
            select(ClientGrantMap.grant_type).where(
                ClientGrantMap.client_id == client_id
            )
        )
    ).all()
    return scopes


@router.delete("/grants")
async def delete_client_grants(
    data: ClientGrantBody,
    session: AsyncSession = Depends(get_async_session),
):
    """delete client grants"""
    await session.execute(
        delete(ClientGrantMap).where(
            ClientGrantMap.client_id == data.client_id,
            ClientGrantMap.grant_type.in_(data.grants),
        )
    )
    return {"detail": "success"}


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
    scopes = await get_client_scopes(client_id, session)
    redirects = await get_client_redirects(client_id, session)
    grants = await get_client_grants(client_id, session)
    return {
        **client.as_dict(included_keys=["id_", "type", "name", "description"]),
        "scopes": scopes,
        "redirect_uris": redirects,
        "grant_types": grants,
    }
