from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from backend.api.rest import router as rest_router
from backend.api.websocket import router as websocket_router
from backend.comms.aes_gcm import AESGCMCodec
from backend.comms.packet_buffer import BufferErrorEvent, EncryptedPacketBuffer, PacketBuffer
from backend.comms.uart import UARTConfig, UARTReader
from backend.logging.raw_logger import RawByteLogger
from backend.logging.telemetry_logger import TelemetryJSONLogger, configure_python_logging
from backend.telemetry.router import TelemetryRouter, TelemetryRoutingError
from backend.telemetry.state import TelemetryState


DEFAULT_DEV_AES_KEY_HEX = "00112233445566778899aabbccddeeff"


class TelemetryBackend:
    def __init__(
        self,
        *,
        state: TelemetryState,
        raw_logger: RawByteLogger,
        telemetry_logger: TelemetryJSONLogger,
        router: TelemetryRouter,
        uart: UARTReader,
        packet_buffer: PacketBuffer | EncryptedPacketBuffer,
        encryption_enabled: bool,
    ) -> None:
        self.state = state
        self.raw_logger = raw_logger
        self.telemetry_logger = telemetry_logger
        self.router = router
        self.uart = uart
        self.packet_buffer = packet_buffer
        self.encryption_enabled = encryption_enabled
        self.uart_port = uart.config.port
        self._task: asyncio.Task[None] | None = None
        self._logger = logging.getLogger(__name__)

    async def start(self) -> None:
        self._task = asyncio.create_task(self.uart.run(self.handle_uart_bytes))

    async def stop(self) -> None:
        await self.uart.stop()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self.raw_logger.close()

    async def handle_uart_bytes(self, data: bytes) -> None:
        await self.raw_logger.write_bytes(data)
        result = self.packet_buffer.feed(data)

        for error in result.errors:
            await self._handle_buffer_error(error)

        for packet in result.packets:
            try:
                await self.router.route(packet)
            except TelemetryRoutingError as exc:
                code = "telemetry_route_error"
                await self.state.record_error(code, str(exc))
                await self.telemetry_logger.log_error(
                    code,
                    str(exc),
                    context={"packet": packet.to_dict()},
                )
                self._logger.warning("Telemetry route error: %s", exc)
            except Exception as exc:
                code = "telemetry_unhandled_error"
                await self.state.record_error(code, str(exc))
                await self.telemetry_logger.log_error(
                    code,
                    str(exc),
                    context={"packet": packet.to_dict()},
                )
                self._logger.exception("Unhandled telemetry processing error")

    async def _handle_buffer_error(self, error: BufferErrorEvent) -> None:
        await self.state.record_error(error.code, error.message)
        await self.telemetry_logger.log_error(error.code, error.message, context=error.to_dict())


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _build_backend(state: TelemetryState) -> TelemetryBackend:
    log_dir = os.getenv("TELEMETRY_LOG_DIR", "logs")
    raw_logger = RawByteLogger(log_dir)
    telemetry_logger = TelemetryJSONLogger(log_dir)

    encryption_enabled = _bool_env("TELEMETRY_ENCRYPTION_ENABLED", True)
    if encryption_enabled:
        key_hex = os.getenv("TELEMETRY_AES_KEY_HEX", DEFAULT_DEV_AES_KEY_HEX)
        if key_hex == DEFAULT_DEV_AES_KEY_HEX:
            logging.getLogger(__name__).warning(
                "Using default development AES key. Set TELEMETRY_AES_KEY_HEX in production."
            )
        codec = AESGCMCodec.from_hex_key(key_hex)
        packet_buffer: PacketBuffer | EncryptedPacketBuffer = EncryptedPacketBuffer(codec)
    else:
        packet_buffer = PacketBuffer()

    async def on_uart_status(connected: bool, reason: str | None) -> None:
        await state.set_uart_connected(connected, reason)
        if reason:
            await telemetry_logger.log_error("uart_status", reason)

    default_port = "COM3" if sys.platform.startswith("win") else "/dev/ttyUSB0"
    uart = UARTReader(
        UARTConfig(
            port=os.getenv("UART_PORT", default_port),
            baudrate=int(os.getenv("UART_BAUDRATE", "115200")),
            read_size=int(os.getenv("UART_READ_SIZE", "4096")),
            timeout_s=float(os.getenv("UART_TIMEOUT_S", "0.05")),
            reconnect_delay_s=float(os.getenv("UART_RECONNECT_DELAY_S", "1.0")),
            max_reconnect_delay_s=float(os.getenv("UART_MAX_RECONNECT_DELAY_S", "10.0")),
        ),
        on_status=on_uart_status,
    )

    router = TelemetryRouter(state, telemetry_logger)
    return TelemetryBackend(
        state=state,
        raw_logger=raw_logger,
        telemetry_logger=telemetry_logger,
        router=router,
        uart=uart,
        packet_buffer=packet_buffer,
        encryption_enabled=encryption_enabled,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> Any:
    log_dir = os.getenv("TELEMETRY_LOG_DIR", "logs")
    configure_python_logging(log_dir, os.getenv("LOG_LEVEL", "INFO"))
    state = TelemetryState()
    backend = _build_backend(state)
    app.state.telemetry_state = state
    app.state.telemetry_backend = backend
    await backend.start()
    try:
        yield
    finally:
        await backend.stop()


app = FastAPI(
    title="Solaris Live Telemetry Backend",
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(rest_router)
app.include_router(websocket_router)
