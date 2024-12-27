"""
Scopes Endpoints
Admin credentials required
"""

from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import delete, exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import ScopesModel
from ....deps import get_async_session
from ...validator import session_has_admin_scope
from .schemas import ScopeBody

router = APIRouter(
    prefix="/scopes",
    tags=["Scopes Authenticated"],
    dependencies=[Depends(session_has_admin_scope())],
)


@router.post("/scope")
async def add_scope(
    data: ScopeBody, session: AsyncSession = Depends(get_async_session)
):
    """Add new scope if it doesnt exist"""
    does_exists = await session.scalar(
        select(exists(ScopesModel)).where(ScopesModel.id_ == data.id_)
    )
    if does_exists:
        raise HTTPException(400, "Scope already Exists")

    await session.execute(insert(ScopesModel).values(id_=data.id_))

    return dict(detail="success")


@router.get("")
async def get_scopes(session: AsyncSession = Depends(get_async_session)):
    """get existing scopes"""
    return (await session.scalars(select(ScopesModel))).all()


@router.delete("/scope")
async def delete_scope(id_: str, session: AsyncSession = Depends(get_async_session)):
    """delete existing scope"""
    does_exists = await session.scalar(
        select(exists(ScopesModel)).where(ScopesModel.id_ == id_)
    )
    if not does_exists:
        raise HTTPException(400, "Scope doesn't exists")

    await session.execute(delete(ScopesModel).where(ScopesModel.id_ == id_))
    return dict(detail="success")
