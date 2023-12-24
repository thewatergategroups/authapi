from fastapi import Depends, HTTPException
from fastapi.routing import APIRouter
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from ..deps import get_async_session
from ...database.models import ScopesModel
from ..schemas import ScopeData

router = APIRouter(prefix="/scopes", tags=["scopes"])


@router.post("/create")
async def add_scope(
    data: ScopeData, session: AsyncSession = Depends(get_async_session)
):
    exists = await session.execute(
        select(exists(ScopesModel)).where(ScopesModel.id_ == data.scope)
    )
    if exists:
        raise HTTPException(400, "Scope already Exists")

    await session.execute(insert(ScopesModel).values(id_=data.scope))

    return {"detail": "success"}


@router.get("")
async def get_scopes(session: AsyncSession = Depends(get_async_session)):
    scopes = (await session.scalars(select(ScopesModel.id_))).all()
    return scopes
