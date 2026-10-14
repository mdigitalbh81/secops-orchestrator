"""Regression test for published API version metadata."""

from importlib.metadata import version

from app.main import create_app


def test_openapi_version_matches_package_release() -> None:
    app = create_app()
    assert app.version == version("secops-orchestrator")
    assert app.openapi()["info"]["version"] == app.version
