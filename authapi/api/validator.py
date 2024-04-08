"""
Session validator for endpoint security.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import quote

from fastapi import Cookie, Depends, HTTPException, Request, status, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import NotAuthorized, Scopes, UserInfo

from authapi.settings import get_settings
from ..database.models import SessionModel, UserModel
from ..deps import get_async_session, get_jwt_client


async def validate_session(
    request: Request,
    session_id: Annotated[str | None, Cookie()] = None,
    user_agent: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_async_session),
) -> UserInfo:
    """Validate user session
    1. The Authorization header
    2. the token cookie
    """
    try:
        if session_id is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session id missing")
        session_model = await SessionModel.select(session_id, session)
        if session_model is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session doesn't exist")
        if session_model.user_agent != user_agent:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "User agent doesn't match"
            )
        if session_model.ip_address != request.client.host:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "client location changed")
        if session_model.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
            await SessionModel.delete(session_id, session)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has expired")
        if session_model.last_active_time < (
            datetime.now(timezone.utc) - timedelta(minutes=20)
        ).replace(tzinfo=None):
            await SessionModel.delete(session_id, session)
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Session has expired due to inactivity"
            )
        email = await UserModel.select_email_from_id(session_model.user_id, session)
        return UserInfo(sub=email, scopes=session_model.scopes)

    except NotAuthorized as exc:
        redirect_url = quote(f"{request.url}?{request.query_params}")
        headers = {
            "Location": f"/login?redirect_url={redirect_url}",
        }
        raise HTTPException(
            status.HTTP_303_SEE_OTHER, "You are not authenticated", headers
        ) from exc


def session_has_admin_scope():
    """Check if the token has the admin scope"""
    return session_has_scope(Scopes.ADMIN)


def session_has_openid_scope():
    """Check if the token has the openid scope"""
    return session_has_scope(Scopes.OPENID)


def session_has_scope(scope: Scopes):
    """
    1. Get the token with the validate_jwt dependency
    2. check of the passed in scope exists
    """

    def _has_scope(user_info: Annotated[UserInfo, Depends(validate_session)]):
        if scope.value not in user_info.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        return user_info

    return _has_scope


def validate_client_token(
    auth: Annotated[
        HTTPAuthorizationCredentials | None, Depends(HTTPBearer(auto_error=False))
    ]
) -> UserInfo:
    """Validate the JWT token either passed in
    1. The Authorization header
    """
    try:
        user = get_jwt_client().validate_jwt(
            auth.credentials,
            issuer=get_settings().jwt_config.jwks_server_url,
        )
        if Scopes.OPENID.value not in user.scopes:
            raise HTTPException(403, "openid scope not present")
        return user
    except NotAuthorized as exc:
        raise HTTPException(401, "You are not authenticated") from exc
