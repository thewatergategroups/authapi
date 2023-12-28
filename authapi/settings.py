"""
Consts, Enums and Models
"""
from functools import lru_cache
from pydantic import BaseSettings
from trekkers.config import DbSettings
import pathlib
from yumi import LogConfig, JwtConfig

TOP_LEVEL_PATH = pathlib.Path(__file__).parent.resolve()


class Settings(BaseSettings):
    """Application Settings"""

    salt: str = ""
    db_settings: DbSettings = DbSettings(
        env_script_location=f"{TOP_LEVEL_PATH}/database/alembic"
    )
    log_config: LogConfig = LogConfig()
    jwt_config: JwtConfig = JwtConfig(jwks_server_url="http://0.0.0.0:8000")


@lru_cache
def get_settings():
    """Get history wrapper"""
    return Settings()
