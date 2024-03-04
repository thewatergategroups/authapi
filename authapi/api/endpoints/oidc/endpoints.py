from datetime import datetime, timedelta
from uuid import UUID, uuid4
from fastapi import Depends, HTTPException, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.routing import APIRouter
import jwt
from sqlalchemy import exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....schemas import Alg
from ....deps import get_async_session
from ....database.models import (
    ClientModel,
    ClientGrantMap,
    ClientRedirects,
    ClientScopeMap,
)
from yumi import UserInfo
from ...tools import blake2b_hash, generate_random_password
from ...validator import validate_jwt, has_admin_scope
from .schemas import (
    ClientAddBody,
    ClientRedirectBody,
    ClientScopesBody,
    ClientGrantBody,
    ResponseTypes,
    AUTHORIZATION_CODES,
)

router = APIRouter(
    prefix="/clients",
    tags=["clients"],
    dependencies=[Depends(validate_jwt), Depends(has_admin_scope())],
)


@router.get("/oidc/authorize")
async def authorize_oidc_request(
    response_type: ResponseTypes,
    client_id: UUID,
    redirect_uri: str,
    scopes: list[str],
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(validate_jwt),
):
    allowed_scopes = (
        (
            await session.execute(
                select(ClientScopeMap).where(
                    ClientScopeMap.scope.in_(list(set(user_info.scopes) & set(scopes))),
                    ClientScopeMap.client_id == client_id,
                )
            )
        )
        .scalars()
        .all()
    )
    if not allowed_scopes:
        raise HTTPException(401, "Requested Scopes not allowed")

    uri_allowed = (
        await session.execute(
            select(ClientRedirects.redirect_uri).where(
                ClientRedirects.client_id == client_id,
                ClientRedirects.redirect_uri == redirect_uri,
            )
        )
    ).scalar_one_or_none()
    if uri_allowed is None:
        raise HTTPException(401, "redirect Uri not allowed")

    if response_type == ResponseTypes.CODE:
        grant_allowed = (
            await session.execute(
                select(ClientGrantMap.grant_type).where(
                    ClientGrantMap.client_id == client_id,
                    ClientGrantMap.grant_type == "authorization_code",
                )
            )
        ).scalar_one_or_none()

        if not grant_allowed:
            raise HTTPException(401, "grant type not allowed")

        code = generate_random_password()
        AUTHORIZATION_CODES[code] = client_id
        return RedirectResponse(f"{redirect_uri}?code={code}", 302)

    elif response_type == ResponseTypes.TOKEN:
        raise HTTPException(400, "response type not implemented")

    raise HTTPException(400, "response type doesn't exist")


# @router.get("/oidc/token")
# async def get_token():
#     now = datetime.now()
#     payload = {
#         "sub": client_id,
#         "exp": (now + timedelta(hours=1)).timestamp(),
#         "scopes": [
#             *[scope for scope in user_info.scopes if scope in scopes],
#             f"user:{user_info.username}",
#         ],
#         "aud": "local",
#         "iss": "authapi",
#         "iat": now.timestamp(),
#     }
#     token = jwt.encode(
#         payload,
#         Alg.EC.load_private_key(),
#         algorithm=Alg.EC.value,
#         headers={"kid": Alg.EC.load_public_key()["kid"]},
#     )
#     return {"token": token}


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
            [
                {"client_id": id_, "redirect_uri": redirect}
                for redirect in data.redirect_uris
            ]
        )
    )
    return JSONResponse(
        {
            "client_id": id_,
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
