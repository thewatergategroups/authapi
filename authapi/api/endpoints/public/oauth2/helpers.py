"""
Helper Functions
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import jwt
from yumi import Jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from .....settings import get_settings
from .....schemas import Alg
from .....database.models import (
    ClientGrantMapModel,
    ClientRoleMapModel,
    RoleScopeMapModel,
    AuthorizationCodeModel,
    RefreshTokenModel,
)
from ...clients.schemas import (
    CodeChallengeMethods,
    GrantTypes,
    OidcTokenBody,
    RefreshTokenStatus,
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


async def auth_code_flow_validation(data: OidcTokenBody, session: AsyncSession):
    """validate input parameters to auth code flow"""
    code_data = await AuthorizationCodeModel.select(data.code, session)
    await AuthorizationCodeModel.delete(data.code, session)

    if code_data is None and data.grant_type == GrantTypes.AUTHORIZATION_CODE:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Authorization code not found"
        )
    if code_data.client_id != data.client_id:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "authorization code not related to this client",
        )
    if code_data.redirect_uri != data.redirect_uri:
        raise HTTPException(400, "redirect URI changed")

    if code_data.code_challenge_method == CodeChallengeMethods.PLAIN:
        if code_data.code_challenge != data.code_verifier:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "incorrect code challenge"
            )
    elif code_data.code_challenge_method == CodeChallengeMethods.S256:
        hashed_code_verifier = (
            base64.urlsafe_b64encode(
                hashlib.sha256(data.code_verifier.encode()).digest()
            )
            .decode()
            .rstrip("=")
        )
        if hashed_code_verifier != code_data.code_challenge:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Incorrect code challenge"
            )
    elif (
        code_data.code_challenge is not None
        and code_data.code_challenge_method is not None
    ):
        raise HTTPException(400, "Code challenge method not allowed")

    return code_data.scopes, code_data.user_id, code_data.nonce


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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "grant type not allowed")
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
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token not valid")

    if token.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        await RefreshTokenModel.delete(data.refresh_token, session)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token has expired")

    if data.client_id != token.client_id:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "client who got issued the token is not the same as the client making the request",
        )
    if token.status != RefreshTokenStatus.ACTIVE:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token is not active")

    return token.scopes, token.user_id
