"""
Scopes Endpoints
Admin credentials required
"""

from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import exists, insert, select
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
        select(exists(ScopesModel)).where(ScopesModel.id_ == data.scope)
    )
    if does_exists:
        raise HTTPException(400, "Scope already Exists")

    await session.execute(insert(ScopesModel).values(id_=data.scope))

    return dict(detail="success")


@router.get("")
async def get_scopes(session: AsyncSession = Depends(get_async_session)):
    """get existing scopes"""
    return (await session.scalars(select(ScopesModel))).all()
