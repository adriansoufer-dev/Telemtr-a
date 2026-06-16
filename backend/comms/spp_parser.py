from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone


K_SPP_PKT_VERSION = 0x01
MAX_PAYLOAD_LEN = 48

# Little Endian by default. The field widths supplied in the protocol add up
# to 7 primary-header bytes, so this implementation follows the field widths.
ENDIANNESS = "<"
PRIMARY_HEADER_FORMAT = f"{ENDIANNESS}BHHH"
SECONDARY_HEADER_FORMAT = f"{ENDIANNESS}IB"
CRC_FORMAT = f"{ENDIANNESS}H"

PRIMARY_HEADER_LEN = struct.calcsize(PRIMARY_HEADER_FORMAT)
SECONDARY_HEADER_LEN = struct.calcsize(SECONDARY_HEADER_FORMAT)
CRC_LEN = struct.calcsize(CRC_FORMAT)
MIN_PACKET_LEN = PRIMARY_HEADER_LEN + SECONDARY_HEADER_LEN + CRC_LEN
MAX_PACKET_LEN = MIN_PACKET_LEN + MAX_PAYLOAD_LEN

CRC16_POLY = 0x1021
CRC16_INIT = 0xFFFF


class SPPParseError(ValueError):
    """Base exception for invalid SPP packets."""


class SPPIncompletePacketError(SPPParseError):
    """Raised when a byte buffer does not contain a full packet yet."""


class SPPVersionError(SPPParseError):
    """Raised when the packet version does not match K_SPP_PKT_VERSION."""


class SPPPayloadLengthError(SPPParseError):
    """Raised when payloadLen is invalid or unsupported."""


class SPPCRCError(SPPParseError):
    """Raised when CRC16 validation fails."""


@dataclass(frozen=True)
class SPPPrimaryHeader:
    version: int
    apid: int
    seq: int
    payload_len: int


@dataclass(frozen=True)
class SPPSecondaryHeader:
    timestamp_ms: int
    drop_counter: int


@dataclass(frozen=True)
class SPPPacket:
    primary: SPPPrimaryHeader
    secondary: SPPSecondaryHeader
    payload: bytes
    crc: int
    raw: bytes
    received_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def version(self) -> int:
        return self.primary.version

    @property
    def apid(self) -> int:
        return self.primary.apid

    @property
    def seq(self) -> int:
        return self.primary.seq

    @property
    def timestamp_ms(self) -> int:
        return self.secondary.timestamp_ms

    @property
    def drop_counter(self) -> int:
        return self.secondary.drop_counter

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "apid": self.apid,
            "seq": self.seq,
            "timestamp_ms": self.timestamp_ms,
            "drop_counter": self.drop_counter,
            "payload_len": self.primary.payload_len,
            "payload_hex": self.payload.hex(),
            "crc": self.crc,
            "received_at": self.received_at.isoformat(),
        }


def crc16_ccitt(data: bytes, init: int = CRC16_INIT) -> int:
    """CRC16-CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection."""
    crc = init & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ CRC16_POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def peek_payload_len(buffer: bytes | bytearray) -> int:
    if len(buffer) < PRIMARY_HEADER_LEN:
        raise SPPIncompletePacketError("not enough bytes for SPP primary header")
    version, _apid, _seq, payload_len = struct.unpack_from(PRIMARY_HEADER_FORMAT, buffer, 0)
    if version != K_SPP_PKT_VERSION:
        raise SPPVersionError(f"invalid SPP version 0x{version:02x}")
    if payload_len > MAX_PAYLOAD_LEN:
        raise SPPPayloadLengthError(
            f"payloadLen={payload_len} exceeds MAX_PAYLOAD_LEN={MAX_PAYLOAD_LEN}"
        )
    return payload_len


def expected_packet_len(buffer: bytes | bytearray) -> int:
    payload_len = peek_payload_len(buffer)
    return PRIMARY_HEADER_LEN + SECONDARY_HEADER_LEN + payload_len + CRC_LEN


def parse_spp_packet(packet_bytes: bytes) -> SPPPacket:
    if len(packet_bytes) < MIN_PACKET_LEN:
        raise SPPIncompletePacketError(
            f"packet has {len(packet_bytes)} bytes; minimum is {MIN_PACKET_LEN}"
        )

    version, apid, seq, payload_len = struct.unpack_from(PRIMARY_HEADER_FORMAT, packet_bytes, 0)
    if version != K_SPP_PKT_VERSION:
        raise SPPVersionError(f"invalid SPP version 0x{version:02x}")
    if payload_len > MAX_PAYLOAD_LEN:
        raise SPPPayloadLengthError(
            f"payloadLen={payload_len} exceeds MAX_PAYLOAD_LEN={MAX_PAYLOAD_LEN}"
        )

    total_len = PRIMARY_HEADER_LEN + SECONDARY_HEADER_LEN + payload_len + CRC_LEN
    if len(packet_bytes) < total_len:
        raise SPPIncompletePacketError(
            f"packet has {len(packet_bytes)} bytes; expected {total_len}"
        )
    if len(packet_bytes) != total_len:
        raise SPPParseError(f"packet has trailing bytes: {len(packet_bytes)} != {total_len}")

    timestamp_ms, drop_counter = struct.unpack_from(
        SECONDARY_HEADER_FORMAT, packet_bytes, PRIMARY_HEADER_LEN
    )
    payload_start = PRIMARY_HEADER_LEN + SECONDARY_HEADER_LEN
    payload_end = payload_start + payload_len
    payload = packet_bytes[payload_start:payload_end]

    (expected_crc,) = struct.unpack_from(CRC_FORMAT, packet_bytes, payload_end)
    actual_crc = crc16_ccitt(packet_bytes[:payload_end])
    if actual_crc != expected_crc:
        raise SPPCRCError(
            f"CRC mismatch: expected 0x{expected_crc:04x}, calculated 0x{actual_crc:04x}"
        )

    return SPPPacket(
        primary=SPPPrimaryHeader(
            version=version,
            apid=apid,
            seq=seq,
            payload_len=payload_len,
        ),
        secondary=SPPSecondaryHeader(
            timestamp_ms=timestamp_ms,
            drop_counter=drop_counter,
        ),
        payload=payload,
        crc=expected_crc,
        raw=packet_bytes,
    )
