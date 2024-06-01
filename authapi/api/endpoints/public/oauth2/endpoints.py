"""
Public endpoints for authentication and authorization
"""

import base64
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Header, status
from fastapi.responses import RedirectResponse
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import Jwt, Scopes, UserInfo


from .....database.models import (
    ClientGrantMapModel,
    ClientModel,
    ClientRedirectsModel,
    ClientRoleMapModel,
    RoleScopeMapModel,
    UserModel,
    UserRoleMapModel,
    AuthorizationCodeModel,
    RefreshTokenModel,
)
from .....deps import get_async_session
from .....schemas import Alg
from .....settings import get_settings
from ....tools import blake2b_hash, generate_random_password
from ....validator import (
    session_has_admin_scope,
    validate_client_token,
)
from ...clients.schemas import (
    ClientType,
    CodeChallengeMethods,
    GrantTypes,
    OidcTokenBody,
    ResponseTypes,
    RefreshTokenStatus,
)
from .helpers import (
    build_client_token,
    auth_code_flow_validation,
    implicit_flow,
    refresh_token_flow,
)
from ..users.helpers import build_user_token


router = APIRouter(tags=["OAuth2 Public"])


@router.get("/oauth2/authorize")
async def authorize_oidc_request(
    response_type: ResponseTypes,
    client_id: UUID,
    redirect_uri: str,
    state: str,
    scope: str,
    code_challenge: str | None = None,
    code_challenge_method: CodeChallengeMethods | None = None,
    nonce: str | None = None,
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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "grant type not allowed")

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
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Requested Scopes not allowed"
        )

    uri_allowed = (
        await session.execute(
            select(ClientRedirectsModel.redirect_uri).where(
                ClientRedirectsModel.client_id == client_id,
                ClientRedirectsModel.redirect_uri == redirect_uri,
            )
        )
    ).scalar_one_or_none()
    if uri_allowed is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "redirect Uri not allowed")

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
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found")

        code = generate_random_password()
        code_model = AuthorizationCodeModel(
            code=code,
            client_id=client_id,
            scopes=allowed_scopes,
            user_id=user_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
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


@router.post("/token")
async def get_token(
    session: AsyncSession = Depends(get_async_session),
    data: OidcTokenBody = Depends(OidcTokenBody.as_form),
    authorization: Annotated[str | None, Header()] = None,
):
    """
    Get client token
    Authenticated with a Client ID and Client Secret
    """
    if data.client_id is None and data.client_secret is None:
        ### support basic auth
        if authorization is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "Client ID and Client Secret Missing",
            )
        type_, value = authorization.split(" ")
        if type_.lower() != "basic":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY)
        client_id, data.client_secret = (
            base64.b64decode(value.encode()).decode().split(":")
        )
        data.client_id = UUID(client_id)
        ###

    client_secret_hash = (
        await session.execute(
            select(ClientModel.secret_hash).where(ClientModel.id_ == data.client_id)
        )
    ).scalar_one_or_none()
    if client_secret_hash is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "client not found")

    response = dict()
    user_id = None
    email = None
    nonce = None
    if blake2b_hash(data.client_secret) != client_secret_hash:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "incorrect client hash")
    if data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        scopes, user_id, nonce = await auth_code_flow_validation(data, session)
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
    if (
        Scopes.OPENID.value in scopes and email is not None
    ):  # implies user id is also not None
        groups = None
        if Scopes.GROUPS in scopes:
            groups = await UserRoleMapModel.get_user_roles(user_id, session)
        user_token = build_user_token(
            email, audience=str(data.client_id), nonce=nonce, groups=groups
        )
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
    if Scopes.EMAIL in user_info.scopes or Scopes.PROFILE in user_info.scopes:
        included_keys = ["email"]
    if Scopes.PROFILE in user_info.scopes:
        included_keys += [
            "first_name",
            "surname",
            "dob",
            "postcode",
            "created_at",
        ]
    response = user.as_dict(included_keys=included_keys)
    if Scopes.GROUPS in user_info.scopes:
        response["groups"] = await UserRoleMapModel.get_user_roles(user.id_, session)
    return response
