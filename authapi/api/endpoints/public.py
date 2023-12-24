from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_async_session
from ...database.models import UserModel
from ..schemas import AuthData
from ..tools import blake2b_hash

router = APIRouter(prefix="/public")


@router.post("/auth")
async def get_token(
    data: AuthData,
    session: AsyncSession = Depends(get_async_session),
):
    passwd = blake2b_hash(data.password)
    exists = await session.scalar(
        select(exists(UserModel)).where(
            UserModel.username == data.username, UserModel.pwd_hash == passwd
        )
    )
    if not exists:
        raise HTTPException(401, "Unauthorized")

    return {"detail": "success"}
