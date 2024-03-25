"""
API dependencies
"""

from functools import lru_cache

from fastapi.templating import Jinja2Templates
from trekkers.config import get_async_sessionmaker, get_sync_sessionmaker
from yumi import JwtClient

from .settings import get_settings


async def get_async_session():
    """
    return a generator of the async postgres session for use in endpoints.
    goes out of scope and closes connection at the end of endpoint execution
    """
    async with get_async_sessionmaker(get_settings().db_settings).begin() as session:
        yield session


def get_sync_sessionm():
    """
    return a generator of the sync postgres session for use in endpoints.
    goes out of scope and closes connection at the end of endpoint execution
    """
    return get_sync_sessionmaker(get_settings().db_settings)


@lru_cache
def get_jwt_client():
    """
    Return a global jwt client. LRU cache ensures one object per application
    """
    return JwtClient(get_settings().jwt_config)


@lru_cache
def get_templates():
    """Return Jinja2 templates for login page"""
    return Jinja2Templates(directory="templates")
