"""
Public endpoints for authentication and authorization
"""

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Cookie, Depends, HTTPException, Header, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.routing import APIRouter
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import Jwt, NotAuthorized, Scopes, UserInfo


from ....database.models import (
    ClientGrantMapModel,
    ClientModel,
    ClientRedirectsModel,
    ClientRoleMapModel,
    RoleScopeMapModel,
    UserModel,
    UserRoleMapModel,
    AuthorizationCodeModel,
    RefreshTokenModel,
    SessionModel,
)
from ....deps import get_async_session, get_templates
from ....schemas import Alg
from ....settings import get_settings
from ...tools import blake2b_hash, generate_random_password
from ...validator import (
    session_has_admin_scope,
    validate_client_token,
    session_status,
    validate_session,
)
from ..oidc.schemas import (
    ClientType,
    CodeChallengeMethods,
    GrantTypes,
    OidcTokenBody,
    ResponseTypes,
    RefreshTokenStatus,
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
    email: str,
    scopes: list[str] | None = None,
    alg: Alg = Alg.EC,
    audience: str = "local",
):
    """Function to creates a user token based on the passed in information"""
    now = datetime.now()
    payload = Jwt(
        sub=email,
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


@router.get("/iframe-js", response_class=Response)
def iframe_js():
    """Get session checking javascript to be run the in the browser"""
    js_code = (
        """
        window.addEventListener('message', function(event) {
        """
        + f"""
            if (event.origin !== "{get_settings().jwt_config.jwks_server_url}") {{
        """
        + """
                return; // }Ignore messages from untrusted origins
            }
            if (event.data.action === 'checkStatus') {
                checkStatus(); // Function that checks the session status
            }
        });
        // Function to simulate a session check
        function checkStatus() {
            console.log('Checking status within iframe');
        """
        + f"""
            fetch('{get_settings().jwt_config.jwks_server_url}/session/status', {{ credentials: 'include' }})
        """
        + """
                .then(response => response.json())
                .then(data => {
                    if (!data.session_active) {
        """
        + f"""
                            window.location.href = '{get_settings().jwt_config.jwks_server_url}/login';
        """
        + """
                            console.log('Session is inactive, please log in again.');
                    } else {
                        console.log('Session is active, no action needed.');
                    }
                })
                .catch(error => {
                    console.error('Failed to retrieve session status:', error);
                    // Handle errors, e.g., notify parent
                });
        }

        // Expose the checkStatus function to the parent window
        window.checkStatus = checkStatus;

        // Optionally check status when iframe loads
        window.onload = checkStatus;
    """
    )
    return Response(content=js_code, media_type="application/javascript")


@router.get("/login", response_class=HTMLResponse)
async def get_login(request: Request, redirect_url: str = None):
    """Serve login page"""
    return get_templates().TemplateResponse(
        "login.html", {"request": request, "redirect_url": redirect_url}
    )


@router.get("/session/status")
async def get_session_status(
    session_id: Annotated[str | None, Cookie()] = None,
    origin: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_async_session),
):
    """Check the status of the currently active session"""
    if origin is None:
        origin = "null"
    try:
        await session_status(session_id, session)
        content = dict(session_active=True)
    except NotAuthorized:
        content = dict(session_active=False)
    return JSONResponse(
        content=content,
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        },
    )


@router.post("/logout")
async def logout(
    session_id: Annotated[str | None, Cookie()] = None,
    session: AsyncSession = Depends(get_async_session),
    _=Depends(validate_session),
):
    """Log out of the application"""
    await SessionModel.delete(session_id, session)
    return {"detail": "Success"}


@router.post("/login")
async def login(
    request: Request,
    data: UserLoginBody = Depends(UserLoginBody.as_form),
    user_agent: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Returns a user token for a user who authenticated with a username and password
    """
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(
            UserModel.email == data.email, UserModel.pwd_hash == passwd
        )
    )
    if not us_exists:
        raise HTTPException(401, "Unauthorized")

    user_id = await UserModel.select_id_from_email(data.email, session)

    scopes = (
        await session.scalars(
            select(RoleScopeMapModel.scope_id).where(
                RoleScopeMapModel.role_id.in_(
                    select(UserRoleMapModel.role_id).where(
                        UserRoleMapModel.user_id == user_id
                    )
                )
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
    if user_agent is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "user agent must be present",
        )
    session_id, expires_at = await SessionModel.insert(
        user_id, request.client.host, user_agent, allowed_scopes, session
    )
    id_token = build_user_token(data.email, alg=data.alg)
    response = JSONResponse({"id_token": id_token}, 200)
    response.set_cookie(
        "session_id",
        session_id,
        expires=expires_at,  # secure=True, httponly=True
    )
    if data.redirect_url:
        response.status_code = 303
        response.headers["Location"] = data.redirect_url
    response.set_cookie(
        "id_token",
        id_token,
        expires=expires_at,  #  secure=True, httponly=True
    )
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
    user_info: UserInfo = Depends(session_has_admin_scope()),
):
    """
    Authorization endpoint for OIDC and oAuth flows.
    Authenticated with a User token
    """
    scopes = scope.split(" ")
    grant_allowed = (
        await session.execute(
            select(ClientGrantMapModel.grant_type).where(
                ClientGrantMapModel.client_id == client_id,
                ClientGrantMapModel.grant_type == GrantTypes.AUTHORIZATION_CODE.value,
            )
        )
    ).scalar_one_or_none()

    if not grant_allowed:
        raise HTTPException(401, "grant type not allowed")

    allowed_scopes = (
        await session.scalars(
            select(RoleScopeMapModel.scope_id).where(
                RoleScopeMapModel.role_id.in_(
                    select(ClientRoleMapModel.role_id).where(
                        ClientRoleMapModel.client_id == client_id
                    )
                ),
                RoleScopeMapModel.scope_id.in_(scopes),
            ),
        )
    ).all()
    if not allowed_scopes:
        raise HTTPException(401, "Requested Scopes not allowed")

    uri_allowed = (
        await session.execute(
            select(ClientRedirectsModel.redirect_uri).where(
                ClientRedirectsModel.client_id == client_id,
                ClientRedirectsModel.redirect_uri == redirect_uri,
            )
        )
    ).scalar_one_or_none()
    if uri_allowed is None:
        raise HTTPException(401, "redirect Uri not allowed")

    if response_type == ResponseTypes.TOKEN:
        token, _ = build_client_token(
            str(client_id), allowed_scopes, alg, user_info.sub
        )
        return RedirectResponse(
            f"{redirect_uri}?access_token={token}&token_type=Bearer&state={state}", 302
        )

    elif response_type == ResponseTypes.ID_TOKEN:
        if Scopes.OPENID not in allowed_scopes:
            raise HTTPException(
                "openid scope required to be present to get an id token"
            )
        token = build_user_token(user_info.sub, alg=alg)
        return RedirectResponse(f"{redirect_uri}?id_token={token}&state={state}", 302)

    elif response_type == ResponseTypes.CODE:
        user_id = await UserModel.select_id_from_email(user_info.sub, session)
        if user_id is None:
            raise HTTPException(401, "user not found")

        code = generate_random_password()
        code_model = AuthorizationCodeModel(
            code=code,
            client_id=client_id,
            scopes=allowed_scopes,
            user_id=user_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        await code_model.insert(session)

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


async def auth_code_flow_validation(data: OidcTokenBody, session: AsyncSession):
    """validate input parameters to auth code flow"""
    code_data = await AuthorizationCodeModel.select(data.code, session)
    await AuthorizationCodeModel.delete(data.code, session)

    if code_data is None and data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        raise HTTPException(401, "Authorization code not found")
    if code_data.client_id != data.client_id:
        raise HTTPException(401, "authorization code not related to this client")
    if code_data.redirect_uri != data.redirect_uri:
        raise HTTPException(400, "redirect URI changed")

    if code_data.code_challenge_method == CodeChallengeMethods.PLAIN:
        if code_data.code_challenge != data.code_verifier:
            raise HTTPException(401, "incorrect code challenge")
    elif code_data.code_challenge_method == CodeChallengeMethods.S256:
        hashed_code_verifier = (
            base64.urlsafe_b64encode(
                hashlib.sha256(data.code_verifier.encode()).digest()
            )
            .decode()
            .rstrip("=")
        )
        if hashed_code_verifier != code_data.code_challenge:
            raise HTTPException(401, "Incorrect code challenge")
    elif (
        code_data.code_challenge is not None
        and code_data.code_challenge_method is not None
    ):
        raise HTTPException(400, "Code challenge method not allowed")

    return code_data.scopes, code_data.user_id


async def implicit_flow(data: OidcTokenBody, session: AsyncSession):
    """validate input parameters to the implicit flow"""

    if data.scope is None:
        raise HTTPException(400, "scope is a required parameter")

    grant_allowed = (
        await session.execute(
            select(ClientGrantMapModel.grant_type).where(
                ClientGrantMapModel.client_id == data.client_id,
                ClientGrantMapModel.grant_type == GrantTypes.IMPLICIT.value,
            )
        )
    ).scalar_one_or_none()

    if not grant_allowed:
        raise HTTPException(401, "grant type not allowed")
    scopes = data.scope.split(" ")

    return (
        await session.scalars(
            select(RoleScopeMapModel.scope_id).where(
                RoleScopeMapModel.role_id.in_(
                    select(ClientRoleMapModel.role_id).where(
                        ClientRoleMapModel.client_id == data.client_id
                    )
                ),
                RoleScopeMapModel.scope_id.in_(scopes),
            )
        )
    ).all()


async def refresh_token_flow(data: OidcTokenBody, session: AsyncSession):
    """validate input parameters to the refresh token flow"""
    if data.refresh_token is None:
        raise HTTPException(400, "refresh token is a required parameter")

    token = await RefreshTokenModel.select(data.refresh_token, session)

    if not token:
        raise HTTPException(401, "token not valid")

    if token.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        await RefreshTokenModel.delete(data.refresh_token, session)
        raise HTTPException(401, "Refresh token has expired")

    if data.client_id != token.client_id:
        raise HTTPException(
            401,
            "client who got issued the token is not the same as the client making the request",
        )
    if token.status != RefreshTokenStatus.ACTIVE:
        raise HTTPException(401, "Refresh token is not active")

    return token.scopes, token.user_id


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

    response = dict()
    user_id = None
    email = None
    if blake2b_hash(data.client_secret) != client_secret_hash:
        raise HTTPException("incorrect client hash")
    if data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        scopes, user_id = await auth_code_flow_validation(data, session)
        response["refresh_token"] = await RefreshTokenModel.insert(
            user_id, data.client_id, scopes, RefreshTokenStatus.ACTIVE, session
        )
    elif data.grant_type == GrantTypes.IMPLICIT:
        scopes = await implicit_flow(data, session)

    elif data.grant_type == GrantTypes.REFRESH_TOKEN:
        scopes, user_id = await refresh_token_flow(data, session)
    if user_id is not None:
        email = await UserModel.select_email_from_id(user_id, session)
    token, expires_in = build_client_token(str(data.client_id), scopes, data.alg, email)

    response.update(
        access_token=token,
        token_type="Bearer",
        scopes=scopes,
        expires_in=expires_in,
    )

    if Scopes.OPENID in scopes and email is not None:
        user_token = build_user_token(email, audience=str(data.client_id))
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
        "end_session_endpoint": f"{domain}/logout",
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
    user_info: UserInfo = Depends(validate_client_token),
):
    """Return user identity from client"""

    user = await session.scalar(
        select(UserModel).where(UserModel.email == user_info.du)
    )
    if user is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "user information doesn't exist"
        )
    included_keys = []
    if (
        Scopes.EMAIL.value in user_info.scopes
        or Scopes.PROFILE.value in user_info.scopes
    ):
        included_keys = ["email"]
    if Scopes.PROFILE.value in user_info.scopes:
        included_keys += [
            "first_name",
            "surname",
            "dob",
            "postcode",
            "created_at",
        ]
    return user.as_dict(included_keys=included_keys)
