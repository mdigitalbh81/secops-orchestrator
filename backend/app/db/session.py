from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings


def _engine():
    return create_async_engine(
        get_settings().database_url,
        echo=get_settings().debug,
        pool_pre_ping=True,
    )


def _session_factory():
    return async_sessionmaker(_engine(), expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with _session_factory()() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
