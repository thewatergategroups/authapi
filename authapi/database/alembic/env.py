from logging.config import fileConfig

from authapi.database.models import BaseSql
from trekkers.config import run_migrations_online
from alembic import context


run_migrations_online(BaseSql.metadata, context.config)
