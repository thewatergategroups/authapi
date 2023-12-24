from ..settings import get_settings

from trekkers.config import get_async_sessionmaker


async def get_async_session():
    async with get_async_sessionmaker(get_settings().db_settings).begin() as session:
        yield session

