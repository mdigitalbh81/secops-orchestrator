"""FastAPI application entry point."""
from __future__ import annotations

import logging

from fastapi import FastAPI

from app.api.routes import router

logging.basicConfig(level=logging.INFO)


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecOps Orchestrator",
        description="Automated DevSecOps security orchestration platform",
        version="0.1.0",
    )

    app.include_router(router)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    return app


app = create_app()
