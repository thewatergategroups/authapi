import uvicorn
from .settings import Settings
from trekkers import database
from yumi import Entrypoints


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


class Entry(Entrypoints):
    API = "api", api
    DATABASE = "db", db
