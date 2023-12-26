"""
Consts, Enums and Models
"""
from functools import lru_cache
from pydantic import BaseSettings
from trekkers.config import DbSettings, get_sync_sessionmaker
import pathlib

TOP_LEVEL_PATH = pathlib.Path(__file__).parent.resolve()


class Settings(BaseSettings):
    """Application Settings"""

    salt: str = ""
    certs_folder: str = "./certs"
    jwks_server_url: str = "http://0.0.0.0:8000"
    log_level: str = "INFO"
    db_settings: DbSettings = DbSettings(
        env_script_location=f"{TOP_LEVEL_PATH}/database/alembic"
    )


@lru_cache
def get_settings():
    """Get history wrapper"""
    return Settings()


def get_sync_sessionm():
    return get_sync_sessionmaker(get_settings().db_settings)
