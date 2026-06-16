from __future__ import annotations

import asyncio
from copy import deepcopy

from fastapi.encoders import jsonable_encoder

from backend.comms.spp_parser import SPPPacket
from backend.telemetry.models import GPSData, IMUData, SystemData, TelemetrySnapshot, utc_now


class TelemetryState:
    """In-memory latest-value store with update notifications for WebSockets."""

    def __init__(self) -> None:
        self._snapshot = TelemetrySnapshot()
        self._condition = asyncio.Condition()
        self._version = 0

    @property
    def version(self) -> int:
        return self._version

    async def set_uart_connected(self, connected: bool, reason: str | None = None) -> None:
        async with self._condition:
            self._snapshot.uart_connected = connected
            if reason:
                self._snapshot.last_error = reason
                self._snapshot.counters.uart_errors += 1
            self._touch_locked()

    async def apply_gps(self, packet: SPPPacket, gps: GPSData) -> None:
        async with self._condition:
            self._record_packet_locked(packet)
            self._snapshot.gps = gps
            self._touch_locked()

    async def apply_imu(self, packet: SPPPacket, imu: IMUData) -> None:
        async with self._condition:
            self._record_packet_locked(packet)
            self._snapshot.imu = imu
            self._touch_locked()

    async def apply_system(self, packet: SPPPacket, system: SystemData) -> None:
        async with self._condition:
            self._record_packet_locked(packet)
            self._snapshot.system = system
            self._touch_locked()

    async def record_unknown_packet(self, packet: SPPPacket) -> None:
        async with self._condition:
            self._record_packet_locked(packet)
            self._snapshot.counters.unknown_packets += 1
            self._touch_locked()

    async def record_error(self, code: str, message: str) -> None:
        async with self._condition:
            lowered = code.lower()
            if "crc" in lowered:
                self._snapshot.counters.crc_errors += 1
            elif "decrypt" in lowered or "auth" in lowered:
                self._snapshot.counters.decrypt_errors += 1
            elif "uart" in lowered:
                self._snapshot.counters.uart_errors += 1
            elif "resync" in lowered or "overflow" in lowered:
                self._snapshot.counters.resync_events += 1
            else:
                self._snapshot.counters.parse_errors += 1
            self._snapshot.last_error = f"{code}: {message}"
            self._touch_locked()

    async def get_snapshot(self) -> dict[str, object]:
        async with self._condition:
            return self._snapshot_dict_locked()

    async def wait_for_update(
        self,
        last_seen_version: int,
        *,
        timeout_s: float = 5.0,
    ) -> tuple[dict[str, object], int]:
        async with self._condition:
            if self._version <= last_seen_version:
                try:
                    await asyncio.wait_for(
                        self._condition.wait_for(lambda: self._version > last_seen_version),
                        timeout=timeout_s,
                    )
                except asyncio.TimeoutError:
                    pass
            return self._snapshot_dict_locked(), self._version

    def _record_packet_locked(self, packet: SPPPacket) -> None:
        counters = self._snapshot.counters
        counters.total_packets += 1
        key = str(packet.apid)
        previous = counters.last_seq_by_apid.get(key)
        if previous is not None:
            expected = (previous + 1) & 0xFFFF
            if packet.seq != expected:
                lost = (packet.seq - expected) & 0xFFFF
                if 0 < lost < 0x8000:
                    counters.lost_packets += lost
        counters.last_seq_by_apid[key] = packet.seq

    def _touch_locked(self) -> None:
        now = utc_now()
        self._snapshot.server_time = now
        self._snapshot.updated_at = now
        self._version += 1
        self._condition.notify_all()

    def _snapshot_dict_locked(self) -> dict[str, object]:
        return jsonable_encoder(deepcopy(self._snapshot))
