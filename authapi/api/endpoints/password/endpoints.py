"""
Endpoints to manipulate users
Requires admin permissions
"""

from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import exists, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import UserInfo

from ....database.models import UserModel, UserScopeModel
from ....deps import get_async_session
from ...tools import blake2b_hash
from ...validator import has_admin_scope, validate_jwt
from .schemas import UserAddBody, UserScopesBody, UserUpdateBody

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(has_admin_scope())],
)


@router.post("/create")
async def create_user(
    data: UserAddBody,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""
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


@router.patch("/update")
async def update_user(
    data: UserUpdateBody,
    session: AsyncSession = Depends(get_async_session),
):
    """update user endpoint"""
    passwd = blake2b_hash(data.password)
    us_exists = await session.scalar(
        select(exists(UserModel)).where(UserModel.username == data.username)
    )
    if not us_exists:
        raise HTTPException(400, "User already Exists")

    await session.execute(
        update(UserModel)
        .where(UserModel.username == data.username)
        .values(pwd_hash=passwd)
    )

    return {"detail": "success"}


@router.get("")
async def get_users(session: AsyncSession = Depends(get_async_session)):
    """get all users"""
    users = (await session.scalars(select(UserModel.username))).all()
    return users


@router.post("/scopes")
async def add_user_scopes(
    data: UserScopesBody,
    session: AsyncSession = Depends(get_async_session),
):
    """add user scopes"""
    await session.execute(
        insert(UserScopeModel).values(scope_id=data.scope, user_id=data.username)
    )
    return {"detail": "success"}


@router.get("/scopes")
async def get_user_scopes(
    username: str,
    session: AsyncSession = Depends(get_async_session),
):
    """get user scopes"""
    scopes = (
        await session.scalars(
            select(UserScopeModel.scope_id).where(UserScopeModel.user_id == username)
        )
    ).all()
    return scopes


@router.get("/user")
async def get_user(
    user_info: UserInfo = Depends(validate_jwt),
    session: AsyncSession = Depends(get_async_session),
):
    """Get user information"""
    scopes = await get_user_scopes(user_info.username, session)
    return {"username": user_info.username, "scopes": scopes}