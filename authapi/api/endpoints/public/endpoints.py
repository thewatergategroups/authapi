from datetime import datetime, timedelta
from typing import Annotated
from fastapi import Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
import jwt
from uuid import UUID
from ...validator import has_admin_scope
from yumi import Scopes, UserInfo
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from ....deps import get_async_session
from ....database.models import (
    UserModel,
    UserScopeModel,
    ClientModel,
    ClientRedirects,
    ClientGrantMap,
    ClientScopeMap,
)
from .schemas import UserLoginBody
from ...tools import blake2b_hash, generate_random_password
from ....schemas import Alg
from ..oidc.schemas import GrantTypes, OidcTokenBody, AUTHORIZATION_CODES, ResponseTypes

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/jwks")
async def get_jwks():
    return {"keys": Alg.get_public_keys()}


def build_user_token(username: str, scopes: list[str] | None = None, alg: Alg = Alg.EC):
    now = datetime.now()
    payload = {
        "sub": username,
        "exp": (now + timedelta(hours=1)).timestamp(),
        "aud": "local",
        "iss": "authapi",
        "iat": now.timestamp(),
    }
    if scopes is not None:
        payload["scopes"] = scopes
    return jwt.encode(
        payload,
        alg.load_private_key(),
        algorithm=alg.value,
        headers={"kid": alg.load_public_key()["kid"]},
    )


@router.post("/login")
async def get_password_flow_token(
    data: UserLoginBody,
    session: AsyncSession = Depends(get_async_session),
):
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(
            UserModel.username == data.username, UserModel.pwd_hash == passwd
        )
    )
    if not us_exists:
        raise HTTPException(401, "Unauthorized")

    scopes = (
        await session.scalars(
            select(UserScopeModel.scope_id).where(
                UserScopeModel.user_id == data.username
            )
        )
    ).all()
    allowed_scopes = [scope for scope in data.scopes if scope in scopes]

    if not allowed_scopes:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "user does not have any of the requested scope",
        )
    token = build_user_token(data.username, data.scopes, data.alg)
    if data.redirect_uri is not None:
        return RedirectResponse(
            data.redirect_uri, 302, headers={"Authorization": f"Bearer {token}"}
        )
    return {"token": token}


@router.get("/oidc/authorize")
async def authorize_oidc_request(
    response_type: ResponseTypes,
    client_id: UUID,
    redirect_uri: str,
    scopes: Annotated[list[str], Query()],
    alg: Alg = Alg.EC,
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(has_admin_scope()),
):
    """state is a base64 encoded string"""

    grant_allowed = (
        await session.execute(
            select(ClientGrantMap.grant_type).where(
                ClientGrantMap.client_id == client_id,
                ClientGrantMap.grant_type == GrantTypes.AUTHORIZATION_CODE.value,
            )
        )
    ).scalar_one_or_none()

    if not grant_allowed:
        raise HTTPException(401, "grant type not allowed")

    allowed_scopes = (
        (
            await session.execute(
                select(ClientScopeMap.scope).where(
                    ClientScopeMap.scope.in_(scopes),
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

    if response_type == ResponseTypes.TOKEN:
        token, expires_in = build_client_token(
            str(client_id), allowed_scopes, alg, user_info.username
        )
        return {
            "token": token,
            "token_type": "Bearer",
            "scopes": scopes,
            "expires_in": expires_in,
        }

    elif response_type == ResponseTypes.ID_TOKEN:
        if Scopes.OPENID not in allowed_scopes:
            raise HTTPException(
                "openid scope required to be present to get an id token"
            )
        token = build_user_token(user_info.username, alg=alg)
        return {"id_token": token}

    elif response_type == ResponseTypes.CODE:
        code = generate_random_password()
        AUTHORIZATION_CODES[code] = {
            "client_id": client_id,
            "scopes": allowed_scopes,
            "username": user_info.username,
            "redirect_uri": redirect_uri,
        }
        return {"code": code}

    raise HTTPException(400, f"Response type {response_type} not implemented")
    # elif response_type == ResponseTypes.ID_T_T:
    #     token, expires_in = build_client_token(str(client_id), final_scopes, alg)
    #     return {
    #         "token": token,
    #         "id_token": build_user_token(user_info.username, alg=alg),
    #         "token_type": "Bearer",
    #         "scopes": scopes,
    #         "expires_in": expires_in,
    #     }

    # elif response_type == ResponseTypes.C_ID_T:
    #     token = build_user_token(user_info.username, alg=alg)

    #     return {"id_token": token, "code": code}

    # return RedirectResponse(f"{redirect_uri}?code={code}&state={state}", 302)


def auth_code_flow_validation(data: OidcTokenBody):
    """validate input parameters to auth code flow"""
    code_data = AUTHORIZATION_CODES.pop(data.code, None)
    if code_data is None and data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        raise HTTPException(401, "Authorization code not found")
    client_id = code_data["client_id"]
    username = code_data["username"]
    if client_id != data.client_id:
        raise HTTPException(401, "authorization code not related to this client")
    if code_data["redirect_uri"] != data.redirect_uri:
        raise HTTPException("redirect URI changed")
    return code_data["scopes"], username


async def implicit_flow(data: OidcTokenBody, session: AsyncSession):
    grant_allowed = (
        await session.execute(
            select(ClientGrantMap.grant_type).where(
                ClientGrantMap.client_id == data.client_id,
                ClientGrantMap.grant_type == GrantTypes.IMPLICIT.value,
            )
        )
    ).scalar_one_or_none()

    if not grant_allowed:
        raise HTTPException(401, "grant type not allowed")

    return (
        (
            await session.execute(
                select(ClientScopeMap.scope).where(
                    ClientScopeMap.scope.in_(data.scopes),
                    ClientScopeMap.client_id == data.client_id,
                )
            )
        )
        .scalars()
        .all()
    )


def build_client_token(
    client_id: str, scopes: list[str], alg: Alg, username: str | None = None
):
    now = datetime.now()

    expires_in = (now + timedelta(hours=1)).timestamp()
    payload = {
        "sub": client_id,
        "exp": expires_in,
        "scopes": scopes,
        "aud": "local",
        "iss": "authapi",
        "iat": now.timestamp(),
    }
    if username:
        payload["du"] = username
    return (
        jwt.encode(
            payload,
            alg.load_private_key(),
            algorithm=alg.value,
            headers={"kid": alg.load_public_key()["kid"]},
        ),
        expires_in,
    )


@router.post("/oidc/token")
async def get_token(
    data: OidcTokenBody,
    session: AsyncSession = Depends(get_async_session),
):

    client_secret_hash = (
        await session.execute(
            select(ClientModel.secret_hash).where(ClientModel.id_ == data.client_id)
        )
    ).scalar_one_or_none()
    if client_secret_hash is None:
        raise HTTPException(404, "client not found")

    if blake2b_hash(data.client_secret) != client_secret_hash:
        raise HTTPException("incorrect client hash")

    if data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        scopes, username = auth_code_flow_validation(data)
    elif data.grant_type == GrantTypes.IMPLICIT:
        scopes = await implicit_flow(data, session)

    token, expires_in = build_client_token(str(data.client_id), data.scopes, data.alg)
    response = {
        "token": token,
        "token_type": "Bearer",
        "scopes": scopes,
        "expires_in": expires_in,
    }

    if Scopes.OPENID in scopes:
        user_token = build_user_token(username)
        response["id_token"] = user_token

    return response


# @router.get("/.well-known/openid-configuration")
# async def get_well_known_open_id():
#     return {
#         "issuer": "authapi",
#         "authorization_endpoint": "https://yourdomain.com/oauth2/authorize",
#         "token_endpoint": "https://yourdomain.com/oauth2/token",
#         "userinfo_endpoint": "https://yourdomain.com/oauth2/userinfo",
#         "jwks_uri": "https://yourdomain.com/oauth2/keys",
#         "response_types_supported": ["code", "token"],
#         "subject_types_supported": ["public"],
#         "id_token_signing_alg_values_supported": [alg.value for alg in Alg],
#         "scopes_supported": ["openid", "profile", "email"],
#         "token_endpoint_auth_methods_supported": ["client_secret_basic"],
#         "claims_supported": ["sub", "email", "preferred_username", "name"],
#         "code_challenge_methods_supported": ["plain", "S256"],
#     }
