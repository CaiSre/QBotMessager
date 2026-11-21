"""存活与就绪探针。"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from server import __version__
from server.db.session import get_session_factory

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "version": __version__}


@router.get("/readyz")
async def readyz() -> JSONResponse:
    try:
        async with get_session_factory()() as db:
            await db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - 探针只关心可用性
        return JSONResponse({"status": "error", "detail": "database unavailable"}, status_code=503)
    return JSONResponse({"status": "ok", "version": __version__})
