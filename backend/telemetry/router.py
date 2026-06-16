from __future__ import annotations

import struct
from typing import Any

import numpy as np

from backend.comms.spp_parser import SPPPacket
from backend.logging.telemetry_logger import TelemetryJSONLogger
from backend.telemetry.models import (
    GPS_APID,
    IMU_APID,
    SYSTEM_APID,
    GPSData,
    IMUData,
    PacketMeta,
    SystemData,
)
from backend.telemetry.state import TelemetryState


GPS_PAYLOAD_FORMAT = "<ddffBB"
IMU_PAYLOAD_FORMAT = "<fffffff"
SYSTEM_PAYLOAD_FORMAT = "<fffBI"


class TelemetryRoutingError(ValueError):
    """Raised when an APID payload cannot be decoded."""


class TelemetryRouter:
    def __init__(
        self,
        state: TelemetryState,
        telemetry_logger: TelemetryJSONLogger,
    ) -> None:
        self.state = state
        self.telemetry_logger = telemetry_logger

    async def route(self, packet: SPPPacket) -> None:
        if packet.apid == GPS_APID:
            gps = self._parse_gps(packet)
            await self.state.apply_gps(packet, gps)
            await self.telemetry_logger.log_packet("gps", gps)
        elif packet.apid == IMU_APID:
            imu = self._parse_imu(packet)
            await self.state.apply_imu(packet, imu)
            await self.telemetry_logger.log_packet("imu", imu)
        elif packet.apid == SYSTEM_APID:
            system = self._parse_system(packet)
            await self.state.apply_system(packet, system)
            await self.telemetry_logger.log_packet("system", system)
        else:
            await self.state.record_unknown_packet(packet)
            await self.telemetry_logger.log_packet("unknown", packet.to_dict())

    def _meta(self, packet: SPPPacket) -> PacketMeta:
        return PacketMeta(
            apid=packet.apid,
            seq=packet.seq,
            timestamp_ms=packet.timestamp_ms,
            drop_counter=packet.drop_counter,
            received_at=packet.received_at,
            payload_hex=packet.payload.hex(),
        )

    def _parse_gps(self, packet: SPPPacket) -> GPSData:
        self._require_payload_size(packet, GPS_PAYLOAD_FORMAT)
        lat, lon, alt, speed, satellites, fix_type = struct.unpack_from(
            GPS_PAYLOAD_FORMAT,
            packet.payload,
            0,
        )
        return GPSData(
            meta=self._meta(packet),
            latitude_deg=lat,
            longitude_deg=lon,
            altitude_m=alt,
            ground_speed_mps=speed,
            satellites=satellites,
            fix_type=fix_type,
        )

    def _parse_imu(self, packet: SPPPacket) -> IMUData:
        self._require_payload_size(packet, IMU_PAYLOAD_FORMAT)
        ax, ay, az, gx, gy, gz, temp = struct.unpack_from(IMU_PAYLOAD_FORMAT, packet.payload, 0)
        accel = np.array([ax, ay, az], dtype=np.float64)
        gyro = np.array([gx, gy, gz], dtype=np.float64)
        return IMUData(
            meta=self._meta(packet),
            accel_mps2=(ax, ay, az),
            gyro_dps=(gx, gy, gz),
            temperature_c=temp,
            acceleration_norm_mps2=float(np.linalg.norm(accel)),
            angular_rate_norm_dps=float(np.linalg.norm(gyro)),
        )

    def _parse_system(self, packet: SPPPacket) -> SystemData:
        self._require_payload_size(packet, SYSTEM_PAYLOAD_FORMAT)
        voltage, current, cpu_temp, status_flags, uptime_ms = struct.unpack_from(
            SYSTEM_PAYLOAD_FORMAT,
            packet.payload,
            0,
        )
        return SystemData(
            meta=self._meta(packet),
            voltage_v=voltage,
            current_a=current,
            cpu_temp_c=cpu_temp,
            status_flags=status_flags,
            uptime_ms=uptime_ms,
        )

    @staticmethod
    def _require_payload_size(packet: SPPPacket, fmt: str) -> None:
        required = struct.calcsize(fmt)
        if len(packet.payload) < required:
            raise TelemetryRoutingError(
                f"APID 0x{packet.apid:04x} payload too short: "
                f"{len(packet.payload)} bytes, expected at least {required}"
            )
