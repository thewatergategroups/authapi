"""
Application entrypoints
"""

import uvicorn
from trekkers import database
from yumi import Entrypoints

from .settings import Settings


def api(*_, **__):
    """API for querying data"""
    uvicorn.run(
        "authapi.api.app:create_app",
        workers=1,
        reload=True,
        host="0.0.0.0",
        factory=True,
        port=8000,
    )


def db(settings: Settings, action: str, revision: str | None, *_, **__):
    """Database migration function"""
    database(settings.db_settings, action, revision)


class Entry(Entrypoints):
    """Avaliable Entrypoint definitions"""

    API = "api", api
    DATABASE = "db", db
