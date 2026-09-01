from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings, override_settings
from app.db.base import Base
from app.db.session import get_db
from app.main import create_app

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def test_settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspaces"
    workspace.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        database_url=f"sqlite+aiosqlite:///{tmp_path}/test.db",
        database_url_sync=f"sqlite:///{tmp_path}/test.db",
        redis_url="redis://localhost:6379/0",
        workspace_base=workspace,
        allowed_workspace_root=tmp_path,
        scanner_timeout=10,
        scanner_max_output_bytes=1024 * 1024,
    )
    override_settings(settings)
    return settings


@pytest.fixture
async def db_session(test_settings: Settings):
    engine = create_async_engine(test_settings.database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def client(db_session: AsyncSession):
    app = create_app()

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def semgrep_json() -> str:
    return (FIXTURES_DIR / "semgrep_output.json").read_text()


@pytest.fixture
def npm_audit_json() -> str:
    return (FIXTURES_DIR / "npm_audit_output.json").read_text()


@pytest.fixture
def pip_audit_json() -> str:
    return (FIXTURES_DIR / "pip_audit_output.json").read_text()


@pytest.fixture
def trivy_json() -> str:
    return (FIXTURES_DIR / "trivy_output.json").read_text()
