from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

import serial
from serial import SerialException


BytesCallback = Callable[[bytes], Awaitable[None]]
StatusCallback = Callable[[bool, str | None], Awaitable[None]]


@dataclass(frozen=True)
class UARTConfig:
    port: str
    baudrate: int = 115200
    read_size: int = 4096
    timeout_s: float = 0.05
    reconnect_delay_s: float = 1.0
    max_reconnect_delay_s: float = 10.0


class UARTReader:
    """Async UART stream reader using pyserial behind asyncio.to_thread."""

    def __init__(
        self,
        config: UARTConfig,
        *,
        logger: logging.Logger | None = None,
        on_status: StatusCallback | None = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.on_status = on_status
        self._serial: serial.Serial | None = None
        self._stop_event = asyncio.Event()
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def run(self, on_bytes: BytesCallback) -> None:
        delay = self.config.reconnect_delay_s
        while not self._stop_event.is_set():
            try:
                await self._ensure_open()
                data = await asyncio.to_thread(self._read_sync)
                if data:
                    await on_bytes(data)
                delay = self.config.reconnect_delay_s
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await self._mark_connected(False, str(exc))
                self.logger.exception("UART read loop error")
                await self._close_serial()
                await asyncio.sleep(delay)
                delay = min(delay * 2.0, self.config.max_reconnect_delay_s)

        await self._close_serial()

    async def stop(self) -> None:
        self._stop_event.set()
        await self._close_serial()

    async def _ensure_open(self) -> None:
        if self._serial is not None and self._serial.is_open:
            return
        self._serial = await asyncio.to_thread(self._open_sync)
        await self._mark_connected(True, None)
        self.logger.info("UART connected on %s at %d baud", self.config.port, self.config.baudrate)

    def _open_sync(self) -> serial.Serial:
        return serial.Serial(
            port=self.config.port,
            baudrate=self.config.baudrate,
            timeout=self.config.timeout_s,
            write_timeout=self.config.timeout_s,
        )

    def _read_sync(self) -> bytes:
        if self._serial is None:
            raise SerialException("serial port is not open")
        return self._serial.read(self.config.read_size)

    async def _close_serial(self) -> None:
        serial_port = self._serial
        self._serial = None
        if serial_port is None:
            return
        await asyncio.to_thread(self._close_sync, serial_port)

    @staticmethod
    def _close_sync(serial_port: serial.Serial) -> None:
        if serial_port.is_open:
            serial_port.close()

    async def _mark_connected(self, connected: bool, reason: str | None) -> None:
        if self._connected == connected:
            return
        self._connected = connected
        if self.on_status is not None:
            await self.on_status(connected, reason)
