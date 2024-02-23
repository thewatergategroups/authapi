from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
import jwt
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession
from ....deps import get_async_session
from ....database.models import UserModel, UserScopeModel
from .schemas import UserLoginBody
from ...tools import blake2b_hash
from ....schemas import Alg

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/jwks")
async def get_jwks():
    return {"keys": Alg.get_public_keys()}


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
    now = datetime.now()
    payload = {
        "sub": data.username,
        "exp": (now + timedelta(hours=1)).timestamp(),
        "scopes": data.scopes,
        "aud": "local",
        "iss": "authapi",
        "iat": now.timestamp(),
    }
    return {
        "token": jwt.encode(
            payload,
            data.alg.load_private_key(),
            algorithm=data.alg.value,
            headers={"kid": data.alg.load_public_key()["kid"]},
        )
    }
