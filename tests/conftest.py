"""
Test configuration
"""

from datetime import datetime, timezone
import time
from multiprocessing import Process

from freezegun import freeze_time
import pytest
import uvicorn
from trekkers import database

from authapi.api.app import create_app
from authapi.settings import Settings, get_settings


@pytest.fixture(autouse=True, scope="session")
def setup():
    """Setup environment and database"""
    settings = get_settings()
    setenv(settings)
    database(settings.db_settings, "upgrade", "head")


def setenv(settings: Settings):
    """Set the variables on the global settings object"""
    settings.db_settings.pgdatabase = "postgres"
    settings.db_settings.pgpassword = "postgres"
    settings.db_settings.pguser = "postgres"
    settings.db_settings.pghost = "localhost"
    settings.db_settings.pgport = "5431"
    settings.db_settings.db_schema = "auth"
    settings.admin_password = "password"
    settings.salt = "salt"
    settings.jwt_config.jwks_server_url = "http://0.0.0.0:8000"


def app():
    """
    Entrypoint to the test server
    1. Using this instead of test client to ensure local
    endpoints can call localhost to get public keys
    """
    uvicorn.run(create_app(), host="0.0.0.0", port=8000, log_level="info")


@pytest.fixture(scope="session")
def server():
    """Run  the API server in another process and return the URL"""
    api = Process(target=app, daemon=True)
    api.start()
    time.sleep(0.2)
    yield "http://0.0.0.0:8000"
    api.kill()
