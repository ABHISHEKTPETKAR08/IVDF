"""
Async database engine and session factory.
Supports SQLite (default) and PostgreSQL seamlessly via DATABASE_URL.
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.config import settings
from backend.database.models import Base
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Build engine kwargs; SQLite needs StaticPool for single-file async use
_engine_kwargs: dict = {
    "echo": settings.DEBUG,
    "future": True,
}

if settings.DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
    _engine_kwargs["poolclass"] = StaticPool

engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def init_db() -> None:
    """
    Create all tables (idempotent) and apply known additive column migrations.

    `create_all` does NOT modify existing tables. When a new column is added
    to a model after the dev DB has been created, the resulting column will
    be missing and every query referencing it raises
    `sqlite3.OperationalError: no such column: ...`.

    For the project's scope (single-file SQLite in dev, occasional schema
    additions) we ship a tiny forward-compatible helper that ALTER-adds known
    additive columns. For multi-step schema changes use Alembic instead.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_apply_minor_migrations)
    logger.info("Database initialised.")


# Known additive migrations: (table, column_name, ALTER DDL).
# Order matters — earlier entries should not depend on later ones.
_MINOR_MIGRATIONS = [
    # Phase: continuous monitoring (auto-rescan feature)
    (
        "targets",
        "auto_rescan",
        "ALTER TABLE targets ADD COLUMN auto_rescan BOOLEAN NOT NULL DEFAULT 1",
    ),
]


def _apply_minor_migrations(sync_conn) -> None:
    """
    Apply known additive column migrations to existing tables.

    Runs inside an `engine.begin()` block, so the whole batch is one
    transaction. Each migration is a no-op when the column already exists.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(sync_conn)
    existing_tables = set(inspector.get_table_names())

    for table, column, ddl in _MINOR_MIGRATIONS:
        if table not in existing_tables:
            continue  # create_all just made it with the right shape
        col_names = {c["name"] for c in inspector.get_columns(table)}
        if column in col_names:
            continue
        logger.info("DB migration: adding missing column %s.%s", table, column)
        sync_conn.execute(text(ddl))


async def drop_db() -> None:
    """Drop all tables. For testing / dev reset only."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.warning("All database tables dropped.")


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Async context manager yielding a transactional DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides a DB session per request."""
    async with get_db_session() as session:
        yield session
