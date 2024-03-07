import os
from fastapi.testclient import TestClient
from trekkers import database
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


@pytest.fixture(scope="session")
def client():
    return TestClient(create_app())
