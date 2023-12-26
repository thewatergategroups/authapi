import logging
from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import decode
from pydantic import BaseModel
from .deps import get_jwks_client
from ..certificates import Alg


class JWT(BaseModel):
    aud: str
    sub: str
    scopes: list[str]
    exp: int | None = None
    # client:str | None = None
    # iat:str
    # iss:str
    # jti:str


class UserInfo(BaseModel):
    username: str
    scopes: list[str]


def validate_jwt(auth: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]):
    try:
        signing_key = get_jwks_client().get_signing_key_from_jwt(auth.credentials)
        jwt = JWT(
            **decode(
                auth.credentials,
                key=signing_key.key,
                algorithms=[value.value for value in Alg],
                audience="local",
            )
        )
        return UserInfo(username=jwt.sub, scopes=jwt.scopes)
    except Exception as exc:
        logging.exception("failed to decode jwt")
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "could not verify token"
        ) from exc


def has_admin_scope():
    return has_scope("admin")


def has_scope(scope: str):
    def _has_scope(user_info: Annotated[UserInfo, Depends(validate_jwt)]):
        if scope not in user_info.scopes:
            raise HTTPException(status.HTTP_403_FORBIDDEN)
        return user_info

    return _has_scope
