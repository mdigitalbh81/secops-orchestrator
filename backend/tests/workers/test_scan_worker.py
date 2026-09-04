from pathlib import Path
from unittest.mock import AsyncMock, patch

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.project import Project
from app.models.scan import Scan
from app.workers.scan_worker import WorkerSettings, enqueue_scan, process_scan_job


def test_worker_settings_configure():
    WorkerSettings.configure()
    assert WorkerSettings.redis_settings is not None
    assert WorkerSettings.max_jobs >= 1
    assert WorkerSettings.retry_jobs is False


async def test_process_scan_job(db_session: AsyncSession, tmp_path: Path):
    project = Project(name="Worker Test Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(tmp_path))
    db_session.add(scan)
    await db_session.commit()

    with patch("app.workers.scan_worker.run_scan") as mock_run:
        mock_run.return_value = None
        await process_scan_job({}, scan.id)
        mock_run.assert_called_once()


async def test_enqueue_scan_arq_available():
    mock_pool = AsyncMock()
    mock_pool.enqueue_job = AsyncMock()
    mock_pool.close = AsyncMock()

    with patch("arq.create_pool", return_value=mock_pool):
        result = await enqueue_scan("test-scan-id")
        assert result is True
        mock_pool.enqueue_job.assert_called_once_with("process_scan_job", "test-scan-id")


async def test_enqueue_scan_fallback_background(db_session: AsyncSession, tmp_path: Path):
    project = Project(name="Fallback Project")
    db_session.add(project)
    await db_session.flush()

    scan = Scan(project_id=project.id, source_path=str(tmp_path))
    db_session.add(scan)
    await db_session.commit()

    with (
        patch("arq.create_pool", side_effect=Exception("Redis connection error")),
        patch("app.workers.scan_worker.run_scan") as mock_run,
    ):
        mock_run.return_value = None
        result = await enqueue_scan(scan.id)
        assert result is False
