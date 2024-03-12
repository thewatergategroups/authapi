"""
Application Settings
"""

import pathlib
from functools import lru_cache

from pydantic import BaseSettings
from trekkers.config import DbSettings
from yumi import JwtConfig, LogConfig


class Settings(BaseSettings):
    """Application Settings"""

    salt: str = ""
    admin_password: str = ""
    db_settings: DbSettings = DbSettings(
        env_script_location=f"{pathlib.Path(__file__).parent.resolve()}/database/alembic"
    )
    log_config: LogConfig = LogConfig()
    jwt_config: JwtConfig = JwtConfig(jwks_server_url="http://0.0.0.0:8000")


@lru_cache
def get_settings():
    """Get application settings global object"""
    return Settings()
