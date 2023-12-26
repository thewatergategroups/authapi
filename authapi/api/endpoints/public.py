from datetime import datetime, timedelta
import logging
import time
from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
import jwt
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_async_session
from ...database.models import UserModel, UserScopeModel
from ..schemas import AuthData
from ..tools import blake2b_hash
from ...schemas import Alg

router = APIRouter(prefix="/public", tags=["public"])


@router.post("/login")
async def get_token(
    data: AuthData,
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
    for key in data.scopes:
        if key not in scopes:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "user does not have requested scope"
            )

    payload = {
        "sub": data.username,
        "exp": (datetime.now() + timedelta(hours=1)).timestamp(),
        "scopes": data.scopes,
        "aud": "local",
    }
    return {
        "token": jwt.encode(
            payload,
            data.alg.load_private_key(),
            algorithm=data.alg.value,
            headers={"kid": data.alg.load_public_key()["kid"]},
        )
    }


@router.get("/jwks")
async def get_jwks():
    return {"keys": Alg.get_public_keys()}
