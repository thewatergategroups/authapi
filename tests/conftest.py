from multiprocessing import Process
import time
from trekkers import database
import uvicorn
from authapi.settings import get_settings
from authapi.api.app import create_app
from authapi.settings import Settings
import pytest


@pytest.fixture(autouse=True, scope="session")
def setup():
    settings = get_settings()
    setenv(settings)
    database(settings.db_settings, "upgrade", "head")


def setenv(settings: Settings):

    settings.db_settings.pgdatabase = "postgres"
    settings.db_settings.pgpassword = "postgres"
    settings.db_settings.pguser = "postgres"
    settings.db_settings.pghost = "localhost"
    settings.db_settings.pgport = "5431"
    settings.db_settings.db_schema = "auth"
    settings.admin_password = "password"
    settings.salt = "salt"


def app():
    uvicorn.run(create_app(), host="0.0.0.0", port=8000, log_level="info")


@pytest.fixture(scope="session")
def server():
    api = Process(target=app, daemon=True)
    api.start()
    time.sleep(0.2)
    yield "http://0.0.0.0:8000"
    api.kill()
