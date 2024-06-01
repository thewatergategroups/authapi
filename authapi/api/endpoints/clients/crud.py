"""
Database Crud for common operations
"""

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from ....database.models import (
    ClientGrantMapModel,
    ClientModel,
    ClientRedirectsModel,
    ClientRoleMapModel,
)
from ...tools import blake2b_hash
from .schemas import ClientAddBody


async def insert_client(
    id_: str, secret: str, data: ClientAddBody, session: AsyncSession
):
    """
    Create Client
    """
    secret_hash = blake2b_hash(secret)
    await session.execute(
        insert(ClientModel).values(
            id_=id_,
            secret_hash=secret_hash,
            type=data.type.value,
            name=data.name,
            description=data.description,
        )
    )
    await session.execute(
        insert(ClientGrantMapModel).values(
            [{"client_id": id_, "grant_type": gt.value} for gt in data.grant_types]
        )
    )
    await session.execute(
        insert(ClientRoleMapModel).values(
            [{"client_id": id_, "role_id": role} for role in data.roles]
        )
    )
    await session.execute(
        insert(ClientRedirectsModel).values(
            [
                {"client_id": id_, "redirect_uri": redirect}
                for redirect in data.redirect_uris
            ]
        )
    )
