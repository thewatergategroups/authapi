"""
JWT validator for endpoint security.
Calls itself to get the JWT public keys
"""

from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from urllib.parse import quote
from yumi import NotAuthorized, Scopes, UserInfo

from ..deps import get_jwt_client
from ..settings import get_settings


def validate_jwt(
    auth: Annotated[
        HTTPAuthorizationCredentials | None, Depends(HTTPBearer(auto_error=False))
    ],
    request: Request,
    token: Annotated[str | None, Cookie()] = None,
) -> UserInfo:
    """Validate the JWT token either passed in
    1. The Authorization header
    2. the token cookie
    """
    try:
        return get_jwt_client().validate_jwt(
            auth.credentials if auth else token,
            issuer=get_settings().jwt_config.jwks_server_url,
        )
    except NotAuthorized as exc:
        redirect_url = quote(f"{request.url}?{request.query_params}")
        headers = {
            "Location": f"/login?redirect_url={redirect_url}",
        }
        raise HTTPException(303, "You are not authenticated", headers) from exc


def has_admin_scope():
    """Check if the token has the admin scope"""
    return has_scope(Scopes.ADMIN)


def has_openid_scope():
    """Check if the token has the openid scope"""
    return has_scope(Scopes.OPENID)


def has_scope(scope: Scopes):
    """
    1. Get the token with the validate_jwt dependency
    2. check of the passed in scope exists
    """

    def _has_scope(user_info: Annotated[UserInfo, Depends(validate_jwt)]):
        if scope.value not in user_info.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        return user_info

    return _has_scope
