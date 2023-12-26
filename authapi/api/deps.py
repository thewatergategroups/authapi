from functools import lru_cache
from ..settings import get_settings
from jwt import PyJWKClient
from trekkers.config import get_async_sessionmaker


async def get_async_session():
    async with get_async_sessionmaker(get_settings().db_settings).begin() as session:
        yield session


@lru_cache
def get_jwks_client():
    return PyJWKClient(f"{get_settings().jwks_server_url}/public/jwks", timeout=5)
