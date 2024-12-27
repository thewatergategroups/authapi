"""
Required as a placeholder for alembic migrations to occur
"""

from alembic import context
from trekkers.config import run_migrations_online

from authapi.database.models import BaseSql

run_migrations_online(BaseSql.metadata, context.config)  # pylint: disable=no-member
