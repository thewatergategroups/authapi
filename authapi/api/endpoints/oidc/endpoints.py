from uuid import UUID, uuid4
from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from ....deps import get_async_session
from ....database.models import (
    ClientModel,
    ClientGrantMap,
    ClientRedirects,
    ClientScopeMap,
)
from ...tools import blake2b_hash, generate_random_password
from ...validator import validate_jwt, has_admin_scope
from .schemas import (
    ClientAddBody,
    ClientRedirectBody,
    ClientScopesBody,
    ClientGrantBody,
)

router = APIRouter(
    prefix="/clients",
    tags=["users"],
    dependencies=[Depends(validate_jwt), Depends(has_admin_scope())],
)


@router.post("/create")
async def create_client(
    data: ClientAddBody, session: AsyncSession = Depends(get_async_session)
):
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
            [{"client_id": id_, "scope": redirect} for redirect in data.redirect_uris]
        )
    )
    return {"client_id": id_, "client_secret": secret}


@router.get("")
async def get_clients(session: AsyncSession = Depends(get_async_session)):
    users = (await session.scalars(select(ClientModel.id_, ClientModel.name))).all()
    return users


@router.post("/scopes")
async def add_client_scopes(
    data: ClientScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
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
    scopes = (
        await session.scalars(
            select(ClientScopeMap).where(ClientScopeMap.client_id == client_id)
        )
    ).all()
    return scopes


@router.post("/redirect")
async def add_client_redirects(
    data: ClientRedirectBody,
    session: AsyncSession = Depends(get_async_session),
):
    await session.execute(
        insert(ClientRedirects).values(
            [
                {"client_id": data.client_id, "scope": redirect}
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
    scopes = (
        await session.scalars(
            select(ClientRedirects).where(ClientRedirects.client_id == client_id)
        )
    ).all()
    return scopes


@router.post("/grants")
async def add_client_grants(
    data: ClientGrantBody,
    session: AsyncSession = Depends(get_async_session),
):
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
    scopes = (
        await session.scalars(
            select(ClientGrantMap).where(ClientGrantMap.client_id == client_id)
        )
    ).all()
    return scopes


@router.get("/client")
async def get_client(
    client_id: UUID,
    session: AsyncSession = Depends(get_async_session),
):
    client = await session.scalar(
        select(ClientModel).where(ClientModel.id_ == client_id)
    )
    if not client:
        raise HTTPException(404, "client not found")
    scopes = await get_client_scopes(client_id, session)
    redirects = await get_client_redirects(client_id, session)
    grants = await get_client_grants(client_id, session)
    return {
        **client.as_dict(),
        "scopes": scopes,
        "redirect_uris": redirects,
        "grant_types": grants,
    }
