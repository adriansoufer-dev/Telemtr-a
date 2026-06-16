from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from pydantic import BaseModel, Field


GPS_APID = 0x0101
IMU_APID = 0x0102
SYSTEM_APID = 0x0103


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    class Config:
        extra = "forbid"


class PacketMeta(StrictModel):
    apid: int
    seq: int
    timestamp_ms: int
    drop_counter: int
    received_at: datetime
    payload_hex: str


class GPSData(StrictModel):
    meta: PacketMeta
    latitude_deg: float
    longitude_deg: float
    altitude_m: float
    ground_speed_mps: float
    satellites: int
    fix_type: int


class IMUData(StrictModel):
    meta: PacketMeta
    accel_mps2: Tuple[float, float, float]
    gyro_dps: Tuple[float, float, float]
    temperature_c: float
    acceleration_norm_mps2: float
    angular_rate_norm_dps: float


class SystemData(StrictModel):
    meta: PacketMeta
    voltage_v: float
    current_a: float
    cpu_temp_c: float
    status_flags: int
    uptime_ms: int


class TelemetryCounters(StrictModel):
    total_packets: int = 0
    unknown_packets: int = 0
    lost_packets: int = 0
    crc_errors: int = 0
    decrypt_errors: int = 0
    parse_errors: int = 0
    resync_events: int = 0
    uart_errors: int = 0
    last_seq_by_apid: Dict[str, int] = Field(default_factory=dict)


class TelemetrySnapshot(StrictModel):
    server_time: datetime = Field(default_factory=utc_now)
    updated_at: Optional[datetime] = None
    uart_connected: bool = False
    last_error: Optional[str] = None
    gps: Optional[GPSData] = None
    imu: Optional[IMUData] = None
    system: Optional[SystemData] = None
    counters: TelemetryCounters = Field(default_factory=TelemetryCounters)
