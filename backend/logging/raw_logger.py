from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path


class RawByteLogger:
    """Append-only binary logger for raw UART bytes before processing."""

    def __init__(self, log_dir: str | Path = "logs") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = self.log_dir / f"raw_uart_{stamp}.bin"
        self._lock = asyncio.Lock()
        self._fh = self.path.open("ab", buffering=0)

    async def write_bytes(self, data: bytes) -> None:
        if not data:
            return
        async with self._lock:
            await asyncio.to_thread(self._fh.write, data)

    async def close(self) -> None:
        async with self._lock:
            await asyncio.to_thread(self._fh.close)
