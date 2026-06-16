from __future__ import annotations

from fastapi import APIRouter, Request


router = APIRouter(prefix="/api")


@router.get("/health")
async def health(request: Request) -> dict[str, object]:
    state = request.app.state.telemetry_state
    backend = getattr(request.app.state, "telemetry_backend", None)
    snapshot = await state.get_snapshot()
    return {
        "status": "ok",
        "uart_connected": snapshot["uart_connected"],
        "uart_port": getattr(backend, "uart_port", None),
        "encryption_enabled": getattr(backend, "encryption_enabled", None),
        "counters": snapshot["counters"],
    }


@router.get("/telemetry/latest")
async def latest_telemetry(request: Request) -> dict[str, object]:
    return await request.app.state.telemetry_state.get_snapshot()
