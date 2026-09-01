"""Async worker for processing scans.

Uses ARQ for job processing. Falls back to a simple background task
if ARQ/Redis is not available (useful for testing).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.services.orchestrator import run_scan

logger = logging.getLogger(__name__)


async def process_scan_job(ctx: dict, scan_id: str) -> None:
    """ARQ job handler."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=settings.debug)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await run_scan(scan_id, session)
    await engine.dispose()


class WorkerSettings:
    """ARQ worker settings."""

    functions = [process_scan_job]
    redis_settings = None  # Set from config at startup

    @classmethod
    def configure(cls):
        from arq.connections import RedisSettings

        settings = get_settings()
        url = settings.redis_url
        parts = url.replace("redis://", "").split("/")
        host_port = parts[0]
        db = int(parts[1]) if len(parts) > 1 else 0
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            port = int(port)
        else:
            host = host_port
            port = 6379
        cls.redis_settings = RedisSettings(host=host, port=port, database=db)


async def enqueue_scan(scan_id: str) -> bool:
    """Try to enqueue via ARQ, fall back to background task."""
    try:
        from arq import create_pool
        from arq.connections import RedisSettings

        settings = get_settings()
        url = settings.redis_url.replace("redis://", "").split("/")
        host_port = url[0]
        db = int(url[1]) if len(url) > 1 else 0
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            port_int = int(port)
        else:
            host = host_port
            port_int = 6379

        pool = await create_pool(RedisSettings(host=host, port=port_int, database=db))
        await pool.enqueue_job("process_scan_job", scan_id)
        await pool.close()
        logger.info("Enqueued scan %s via ARQ", scan_id)
        return True
    except Exception:
        logger.warning("ARQ not available, running scan in background task")
        asyncio.create_task(_background_scan(scan_id))
        return False


async def _background_scan(scan_id: str) -> None:
    """Fallback: run scan directly in an asyncio task."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url, echo=settings.debug)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            await run_scan(scan_id, session)
    except Exception:
        logger.exception("Background scan %s failed", scan_id)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    from arq import run_worker

    WorkerSettings.configure()
    run_worker(WorkerSettings)
