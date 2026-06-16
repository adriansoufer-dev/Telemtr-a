from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
import websockets


router = APIRouter()


@router.websocket("/ws/telemetry")
async def telemetry_websocket(websocket: WebSocket) -> None:
    await websocket.accept()
    state = websocket.app.state.telemetry_state
    last_version = -1

    try:
        await websocket.send_json(
            {
                "type": "hello",
                "websockets_version": getattr(websockets, "__version__", "unknown"),
            }
        )
        while True:
            snapshot, version = await state.wait_for_update(last_version, timeout_s=2.0)
            if websocket.application_state != WebSocketState.CONNECTED:
                break
            await websocket.send_json(
                {
                    "type": "telemetry",
                    "version": version,
                    "snapshot": snapshot,
                }
            )
            last_version = version
    except WebSocketDisconnect:
        return
