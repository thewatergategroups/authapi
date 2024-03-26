"""
Public endpoints for authentication and authorization
"""

import base64
from datetime import datetime, timedelta
import hashlib
from uuid import UUID

from fastapi.templating import Jinja2Templates
import jwt
from fastapi import Cookie, Depends, HTTPException, Header, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRouter
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import Scopes, UserInfo, Jwt

from ..oidc.endpoints import get_client


from ....database.models import (
    ClientGrantMap,
    ClientModel,
    ClientRedirects,
    ClientScopeMap,
    UserModel,
    UserScopeModel,
)
from ....deps import get_async_session, get_templates
from ....settings import get_settings
from ....schemas import Alg
from ...tools import blake2b_hash, generate_random_password
from ...validator import has_admin_scope, has_openid_scope, validate_jwt
from ..oidc.schemas import (
    AUTHORIZATION_CODES,
    GrantTypes,
    OidcTokenBody,
    ResponseTypes,
    ClientType,
    CodeChallengeMethods,
)
from .schemas import UserLoginBody

router = APIRouter(tags=["public"])


@router.get("/keys")
async def get_jwks():
    """
    Returns avaliable public keys
    No Authentication required
    """
    return {"keys": Alg.get_public_keys()}


def build_user_token(
    username: str,
    scopes: list[str] | None = None,
    alg: Alg = Alg.EC,
    audience: str = "local",
):
    """Function to creates a user token based on the passed in information"""
    now = datetime.now()
    payload = Jwt(
        sub=username,
        exp=(now + timedelta(hours=1)).timestamp(),
        aud=audience,
        iss=get_settings().jwt_config.jwks_server_url,
        iat=now.timestamp(),
    )
    if scopes is not None:
        payload.scopes = scopes
    return jwt.encode(
        payload.model_dump(exclude_none=True),
        alg.load_private_key(),
        algorithm=alg.value,
        headers={"kid": alg.load_public_key()["kid"]},
    )


@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    """Serve login page"""
    return get_templates().TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def get_password_flow_token(
    data: UserLoginBody = Depends(UserLoginBody.as_form),
    original_url: str = Cookie(None),
    session: AsyncSession = Depends(get_async_session),
):
    """
    Returns a user token for a user who authenticated with a username and password
    """
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
    allowed_scopes = scopes
    if data.scope is not None:
        allowed_scopes = [scope for scope in data.scope.split(" ") if scope in scopes]

    if not allowed_scopes:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "user does not have any of the requested scope",
        )

    token = build_user_token(data.username, allowed_scopes, data.alg)
    response = JSONResponse({"token": token}, 200)
    if original_url:
        response = RedirectResponse(original_url, 303)
    response.set_cookie("token", token)

    return response


@router.get("/oauth2/authorize")
async def authorize_oidc_request(
    response_type: ResponseTypes,
    client_id: UUID,
    redirect_uri: str,
    state: str,
    scope: str,
    code_challenge: str | None = None,
    code_challenge_method: CodeChallengeMethods | None = None,
    alg: Alg = Alg.EC,
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(has_admin_scope()),
):
    """
    Authorization endpoint for OIDC and oAuth flows.
    Authenticated with a User token
    """
    scopes = scope.split(" ")
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
        token, _ = build_client_token(
            str(client_id), allowed_scopes, alg, user_info.username
        )
        return RedirectResponse(
            f"{redirect_uri}?access_token={token}&token_type=Bearer&state={state}", 302
        )

    elif response_type == ResponseTypes.ID_TOKEN:
        if Scopes.OPENID not in allowed_scopes:
            raise HTTPException(
                "openid scope required to be present to get an id token"
            )
        token = build_user_token(user_info.username, alg=alg)
        return RedirectResponse(f"{redirect_uri}?id_token={token}&state={state}", 302)

    elif response_type == ResponseTypes.CODE:

        code = generate_random_password()
        AUTHORIZATION_CODES[code] = {
            "client_id": client_id,
            "scopes": allowed_scopes,
            "username": user_info.username,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        return RedirectResponse(f"{redirect_uri}?code={code}&state={state}", 302)

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

    # return


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
        raise HTTPException(400, "redirect URI changed")

    code_challenge_method = code_data["code_challenge_method"]
    code_challenge = code_data["code_challenge"]
    if code_challenge_method == CodeChallengeMethods.PLAIN:
        if code_challenge != data.code_verifier:
            raise HTTPException(401, "incorrect code challenge")
    elif code_challenge_method == CodeChallengeMethods.S256:
        hashed_code_verifier = (
            base64.urlsafe_b64encode(
                hashlib.sha256(data.code_verifier.encode()).digest()
            )
            .decode()
            .rstrip("=")
        )
        if hashed_code_verifier != code_challenge:
            raise HTTPException(401, "Incorrect code challenge")
    elif code_challenge is not None and code_challenge_method is not None:
        raise HTTPException(400, "Code challenge method not allowed")

    return code_data["scopes"], username


async def implicit_flow(data: OidcTokenBody, session: AsyncSession):
    """validate input parameters to the implicit flow"""

    if data.scope is None:
        raise HTTPException(400, "scope is a required parameter")

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
    scopes = data.scope.split(" ")
    return (
        (
            await session.execute(
                select(ClientScopeMap.scope).where(
                    ClientScopeMap.scope.in_(scopes),
                    ClientScopeMap.client_id == data.client_id,
                )
            )
        )
        .scalars()
        .all()
    )


def build_client_token(
    client_id: str,
    scopes: list[str],
    alg: Alg,
    username: str | None = None,
    audience: str = "local",
):
    """build a client token based on the passed in information"""
    now = datetime.now()

    expires_in = int((now + timedelta(hours=1)).timestamp())
    payload = Jwt(
        sub=client_id,
        exp=expires_in,
        aud=audience,
        iss=get_settings().jwt_config.jwks_server_url,
        iat=now.timestamp(),
        scopes=scopes,
    )
    if username:
        payload.du = username
    return (
        jwt.encode(
            payload.model_dump(exclude_none=True),
            alg.load_private_key(),
            algorithm=alg.value,
            headers={"kid": alg.load_public_key()["kid"]},
        ),
        expires_in,
    )


@router.post("/token")
async def get_token(
    data: OidcTokenBody = Depends(OidcTokenBody.as_form),
    session: AsyncSession = Depends(get_async_session),
):
    """
    Get client token
    Authenticated with a Client ID and Client Secret
    """
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

    token, expires_in = build_client_token(str(data.client_id), scopes, data.alg)
    response = {
        "access_token": token,
        "token_type": "Bearer",
        "scopes": scopes,
        "expires_in": expires_in,
    }

    if Scopes.OPENID in scopes:
        user_token = build_user_token(username, audience=str(data.client_id))
        response["id_token"] = user_token

    return response


@router.get("/.well-known/openid-configuration")
async def get_well_known_open_id():
    """
    Endpoint to return the OIDC configuration for
    third party applications to use this service as an IDP
    """
    domain = get_settings().jwt_config.jwks_server_url
    return {
        "issuer": domain,
        "authorization_endpoint": f"{domain}/oauth2/authorize",
        "token_endpoint": f"{domain}/token",
        "userinfo_endpoint": f"{domain}/userinfo",
        "jwks_uri": f"{domain}/keys",
        "response_types_supported": ResponseTypes.get_all(),
        "response_modes_supported": ["query"],
        "subject_types_supported": ClientType.get_all(),
        "id_token_signing_alg_values_supported": [alg.value for alg in Alg],
        "scopes_supported": [item.value for item in Scopes],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": Jwt.get_claims(),
        "code_challenge_methods_supported": CodeChallengeMethods.get_all(),
    }


@router.get("/userinfo")
async def get_userinfo(
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(validate_jwt),
    _=Depends(has_openid_scope),
):
    """Return client identity"""
    return await get_client(UUID(user_info.username), session)
