import uvicorn
from .settings import Settings
from trekkers import database
from enum import Enum
from typing import Callable


def api(*args, **kwargs):
    """API for querying data"""
    uvicorn.run(
        "authapi.api.app:create_app",
        workers=1,
        reload=True,
        host="0.0.0.0",
        factory=True,
        port=8000,
    )


def db(settings: Settings, action: str, revision: str | None, *args, **kwargs):
    database(settings.db_settings, action, revision)


class Entrypoints(Enum):
    def __init__(self, entrypoint: str, function: Callable):
        super().__init__()
        self.entrypoint = entrypoint
        self.function = function

    API = "api", api
    DATABASE = "db", db

    @classmethod
    def get_entrypoint(cls, entrypoint: str):
        for entry in cls:
            if entrypoint == entry.entrypoint:
                return entry.function
        raise KeyError(f"Entrypoint {entrypoint} not found...")

    @classmethod
    def get_all_names(cls):
        return [value.entrypoint for value in cls]
