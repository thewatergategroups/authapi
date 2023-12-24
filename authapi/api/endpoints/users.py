import logging
from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_async_session
from ...database.models import UserModel, UserScopeModel
from ..schemas import AuthData, UserScopesData
from ..tools import blake2b_hash

router = APIRouter(prefix="/users")


@router.post("/create")
async def create_user(
    data: AuthData,
    session: AsyncSession = Depends(get_async_session),
):
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(UserModel.username == data.username)
    )
    if us_exists:
        raise HTTPException(400, "User already Exists")

    await session.execute(
        insert(UserModel).values(username=data.username, pwd_hash=passwd)
    )

    return {"detail": "success"}


@router.get("")
async def get_user(session: AsyncSession = Depends(get_async_session)):
    users = (await session.scalars(select(UserModel.username))).all()
    return users


@router.post("/scopes")
async def add_user_scopes(
    data: UserScopesData,
    session: AsyncSession = Depends(get_async_session),
):
    await session.execute(
        insert(UserScopeModel).values(scope_id=data.scope, user_id=data.username)
    )
    return {"detail": "success"}


@router.get("/scopes")
async def add_user_scopes(
    username: str,
    session: AsyncSession = Depends(get_async_session),
):
    scopes = (
        await session.scalars(
            select(UserScopeModel.scope_id).where(UserScopeModel.user_id == username)
        )
    ).all()
    return scopes
