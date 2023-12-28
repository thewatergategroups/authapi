from .settings import get_settings
from trekkers.config import get_async_sessionmaker, get_sync_sessionmaker
from yumi import JwtClient
from functools import lru_cache


async def get_async_session():
    async with get_async_sessionmaker(get_settings().db_settings).begin() as session:
        yield session


@lru_cache
def get_jwt_client():
    return JwtClient(get_settings().jwt_config)


def get_sync_sessionm():
    return get_sync_sessionmaker(get_settings().db_settings)
