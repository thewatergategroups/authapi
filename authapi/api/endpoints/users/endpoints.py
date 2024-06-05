"""
User Endpoints
Requires admin permissions
"""

from uuid import UUID, uuid4

from fastapi import Depends, HTTPException, status
from fastapi.routing import APIRouter
from sqlalchemy import delete, exists, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from yumi import UserInfo

from ....database.models import UserModel, UserRoleMapModel
from ....deps import get_async_session
from ...tools import blake2b_hash
from ...validator import session_has_admin_scope

from .schemas import AddUserRoleBody, UserAddBody, UserUpdateBody

router = APIRouter(
    tags=["Users Authenticated"],
    prefix="/users",
    dependencies=[Depends(session_has_admin_scope())],
)


async def get_user_roles(user_id: UUID, session: AsyncSession):
    """Get User roles"""
    return (
        await session.scalars(
            select(UserRoleMapModel.role_id).where(UserRoleMapModel.user_id == user_id)
        )
    ).all()


@router.get("")
async def get_users(
    session: AsyncSession = Depends(get_async_session),
):
    """get all users"""
    users = (await session.scalars(select(UserModel))).all()
    response = list()
    for user in users:
        response.append(
            {
                **user.as_dict(included_keys=user.get_all_keys(["pwd_hash"])),
                "roles": await get_user_roles(user.id_, session),
            }
        )
    return response


@router.post("/user")
async def create_user(
    data: UserAddBody,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""
    us_exists = await session.scalar(
        select(exists(UserModel)).where(UserModel.email == data.email.strip())
    )
    if us_exists:
        raise HTTPException(400, "User already Exists")

    passwd = blake2b_hash(data.password.strip())
    user_id = uuid4()
    await session.execute(
        insert(UserModel).values(
            id_=user_id,
            email=data.email.strip(),
            pwd_hash=passwd,
            first_name=data.first_name.strip(),
            surname=data.surname.strip(),
            dob=data.dob,
            postcode=data.postcode.strip(),
        )
    )
    if data.roles is not None:
        await session.execute(
            insert(UserRoleMapModel)
            .values([dict(user_id=user_id, role_id=role_id) for role_id in data.roles])
            .on_conflict_do_nothing()
        )

    return dict(detail="success")


@router.patch("/user")
async def update_user(
    data: UserUpdateBody,
    session: AsyncSession = Depends(get_async_session),
):
    """update user endpoint"""
    user_id = await session.scalar(
        select(UserModel.id_).where(UserModel.email == data.email.strip())
    )
    if user_id is None:
        raise HTTPException(400, "User doesn't Exists")
    values = dict()
    if data.password is not None:
        values["pwd_hash"] = blake2b_hash(data.password.strip())
    if data.new_email is not None:
        values["email"] = data.new_email.strip()
    if data.first_name is not None:
        values["first_name"] = data.first_name.strip()
    if data.surname is not None:
        values["surname"] = data.surname.strip()
    if data.dob is not None:
        values["dob"] = data.dob
    if data.postcode is not None:
        values["postcode"] = data.postcode.strip()
    if not values:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "no fields to update")
    await session.execute(
        update(UserModel).where(UserModel.email == data.email.strip()).values(**values)
    )
    if data.roles is not None:
        await session.execute(
            insert(UserRoleMapModel)
            .values([dict(user_id=user_id, role_id=role_id) for role_id in data.roles])
            .on_conflict_do_nothing()
        )

    return dict(detail="success")


@router.delete("/user")
async def delete_user(
    user_email: str,
    session: AsyncSession = Depends(get_async_session),
):
    """delete a user"""
    user_id = await session.scalar(
        select(UserModel.id_).where(UserModel.email == user_email.strip())
    )
    if user_id is None:
        raise HTTPException(400, "User doesn't Exists")
    ### temporary hack - need to recreate migrations to get cascading behaviour
    await session.execute(
        delete(UserRoleMapModel).where(UserRoleMapModel.user_id == user_id)
    )
    ###
    await session.execute(delete(UserModel).where(UserModel.id_ == user_id))
    return dict(detail="success")


@router.get("/me")
async def get_me(
    session: AsyncSession = Depends(get_async_session),
    user_info: UserInfo = Depends(session_has_admin_scope()),
):
    """Get user information"""
    user = await session.scalar(
        select(UserModel).where(UserModel.email == user_info.sub)
    )
    roles = await get_user_roles(user.id_, session)
    if not user:
        raise HTTPException(400, "user not found")
    return {
        **user.as_dict(included_keys=user.get_all_keys(["pwd_hash", "id_"])),
        "roles": roles,
    }


@router.post("/user/roles")
async def add_user_role(
    data: AddUserRoleBody,
    session: AsyncSession = Depends(get_async_session),
):
    """create new user endpoint. stores a hash of the password"""

    await session.execute(
        insert(UserRoleMapModel)
        .values(user_id=data.user_id.strip(), role_id=data.role_id.strip())
        .on_conflict_do_nothing()
    )

    return dict(detail="success")
