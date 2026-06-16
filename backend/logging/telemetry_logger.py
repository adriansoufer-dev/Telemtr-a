from __future__ import annotations

import asyncio
import json
import logging
from datetime import date, datetime
from pathlib import Path
from typing import Any

from fastapi.encoders import jsonable_encoder


def configure_python_logging(log_dir: str | Path = "logs", level: str = "INFO") -> None:
    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(path / "backend.log", encoding="utf-8"),
        ],
        force=True,
    )


class TelemetryJSONLogger:
    """JSONL logger for parsed telemetry and processing errors."""

    def __init__(self, log_dir: str | Path = "logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.telemetry_path = self.log_dir / "telemetry.jsonl"
        self.error_path = self.log_dir / "errors.jsonl"
        self._lock = asyncio.Lock()

    async def log_packet(self, packet_type: str, payload: Any) -> None:
        record = {
            "time": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "type": packet_type,
            "payload": jsonable_encoder(payload),
        }
        await self._append_json(self.telemetry_path, record)

    async def log_error(
        self,
        code: str,
        message: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "time": datetime.utcnow().isoformat(timespec="milliseconds") + "Z",
            "code": code,
            "message": message,
            "context": context or {},
        }
        await self._append_json(self.error_path, record)

    async def _append_json(self, path: Path, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=True, default=_json_default) + "\n"
        async with self._lock:
            await asyncio.to_thread(_append_text, path, line)


def _append_text(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)
