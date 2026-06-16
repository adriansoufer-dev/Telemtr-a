from __future__ import annotations

from dataclasses import dataclass, field

from backend.comms.aes_gcm import AESGCMAuthError, AESGCMCodec
from backend.comms.spp_parser import (
    K_SPP_PKT_VERSION,
    MAX_PACKET_LEN,
    MIN_PACKET_LEN,
    SPPCRCError,
    SPPParseError,
    SPPPacket,
    SPPPayloadLengthError,
    SPPVersionError,
    expected_packet_len,
    parse_spp_packet,
)


@dataclass(frozen=True)
class BufferErrorEvent:
    code: str
    message: str
    discarded: bytes = b""
    buffered_bytes: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "discarded_hex": self.discarded.hex(),
            "buffered_bytes": self.buffered_bytes,
        }


@dataclass
class BufferResult:
    packets: list[SPPPacket] = field(default_factory=list)
    errors: list[BufferErrorEvent] = field(default_factory=list)


class PacketBuffer:
    """Continuous plaintext SPP packet buffer.

    The buffer never assumes that one UART read is one packet. It accumulates
    bytes, reads payloadLen from the SPP header, waits for missing bytes,
    extracts concatenated packets, and drops one byte at a time on CRC/version
    errors to recover synchronization.
    """

    def __init__(self, *, max_buffer_size: int = 4096) -> None:
        self._buffer = bytearray()
        self.max_buffer_size = max_buffer_size

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> BufferResult:
        result = BufferResult()
        if data:
            self._buffer.extend(data)

        while True:
            if len(self._buffer) < MIN_PACKET_LEN:
                break

            if self._buffer[0] != K_SPP_PKT_VERSION:
                discarded = self._discard_until_next_version_byte()
                result.errors.append(
                    BufferErrorEvent(
                        code="resync_garbage",
                        message="discarded bytes before next candidate SPP version",
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )
                continue

            try:
                packet_len = expected_packet_len(self._buffer)
            except SPPPayloadLengthError as exc:
                discarded = bytes([self._buffer.pop(0)])
                result.errors.append(
                    BufferErrorEvent(
                        code="payload_len_invalid",
                        message=str(exc),
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )
                continue
            except SPPVersionError as exc:
                discarded = bytes([self._buffer.pop(0)])
                result.errors.append(
                    BufferErrorEvent(
                        code="version_invalid",
                        message=str(exc),
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )
                continue
            except SPPParseError:
                break

            if len(self._buffer) < packet_len:
                break

            packet_bytes = bytes(self._buffer[:packet_len])
            try:
                result.packets.append(parse_spp_packet(packet_bytes))
                del self._buffer[:packet_len]
            except SPPCRCError as exc:
                discarded = bytes([self._buffer.pop(0)])
                result.errors.append(
                    BufferErrorEvent(
                        code="crc_invalid",
                        message=str(exc),
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )
            except SPPParseError as exc:
                discarded = bytes([self._buffer.pop(0)])
                result.errors.append(
                    BufferErrorEvent(
                        code="parse_invalid",
                        message=str(exc),
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )

        self._trim_if_needed(result)
        return result

    def _discard_until_next_version_byte(self) -> bytes:
        next_index = self._buffer.find(bytes([K_SPP_PKT_VERSION]), 1)
        if next_index == -1:
            discarded = bytes(self._buffer)
            self._buffer.clear()
            return discarded
        discarded = bytes(self._buffer[:next_index])
        del self._buffer[:next_index]
        return discarded

    def _trim_if_needed(self, result: BufferResult) -> None:
        overflow = len(self._buffer) - self.max_buffer_size
        if overflow <= 0:
            return
        discarded = bytes(self._buffer[:overflow])
        del self._buffer[:overflow]
        result.errors.append(
            BufferErrorEvent(
                code="buffer_overflow",
                message=f"packet buffer exceeded {self.max_buffer_size} bytes",
                discarded=discarded,
                buffered_bytes=len(self._buffer),
            )
        )


class EncryptedPacketBuffer:
    """Continuous AES-GCM frame buffer for encrypted SPP packets.

    Because the SPP header is encrypted, there is no cleartext payloadLen to
    read before authentication. The valid SPP packet size is tightly bounded,
    so this buffer tries all legal encrypted frame lengths and accepts only a
    frame that authenticates and parses as SPP. Wrong candidates fail at the
    GCM tag check and are not logged individually.
    """

    def __init__(
        self,
        codec: AESGCMCodec,
        *,
        min_plaintext_len: int = MIN_PACKET_LEN,
        max_plaintext_len: int = MAX_PACKET_LEN,
        max_buffer_size: int = 8192,
    ) -> None:
        self.codec = codec
        self.min_plaintext_len = min_plaintext_len
        self.max_plaintext_len = max_plaintext_len
        self.min_frame_len = codec.overhead_len + min_plaintext_len
        self.max_frame_len = codec.overhead_len + max_plaintext_len
        self.max_buffer_size = max_buffer_size
        self._buffer = bytearray()

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> BufferResult:
        result = BufferResult()
        if data:
            self._buffer.extend(data)

        while len(self._buffer) >= self.min_frame_len:
            extraction = self._try_extract_frame_at_start()
            if extraction is None:
                if len(self._buffer) < self.max_frame_len:
                    break
                discarded = bytes([self._buffer.pop(0)])
                result.errors.append(
                    BufferErrorEvent(
                        code="decrypt_resync",
                        message="discarded one byte while searching for AES-GCM frame boundary",
                        discarded=discarded,
                        buffered_bytes=len(self._buffer),
                    )
                )
                continue

            frame_len, packet, error = extraction
            del self._buffer[:frame_len]
            if packet is not None:
                result.packets.append(packet)
            if error is not None:
                result.errors.append(error)

        self._trim_if_needed(result)
        return result

    def _try_extract_frame_at_start(
        self,
    ) -> tuple[int, SPPPacket | None, BufferErrorEvent | None] | None:
        available = len(self._buffer)
        max_plaintext = min(self.max_plaintext_len, available - self.codec.overhead_len)

        for plaintext_len in range(self.min_plaintext_len, max_plaintext + 1):
            frame_len = plaintext_len + self.codec.overhead_len
            frame = bytes(self._buffer[:frame_len])
            try:
                plaintext = self.codec.decrypt_frame(frame)
            except AESGCMAuthError:
                continue

            try:
                packet = parse_spp_packet(plaintext)
                return frame_len, packet, None
            except SPPParseError as exc:
                return (
                    frame_len,
                    None,
                    BufferErrorEvent(
                        code="parse_after_decrypt_invalid",
                        message=str(exc),
                        discarded=frame,
                        buffered_bytes=len(self._buffer),
                    ),
                )

        return None

    def _trim_if_needed(self, result: BufferResult) -> None:
        overflow = len(self._buffer) - self.max_buffer_size
        if overflow <= 0:
            return
        discarded = bytes(self._buffer[:overflow])
        del self._buffer[:overflow]
        result.errors.append(
            BufferErrorEvent(
                code="encrypted_buffer_overflow",
                message=f"encrypted packet buffer exceeded {self.max_buffer_size} bytes",
                discarded=discarded,
                buffered_bytes=len(self._buffer),
            )
        )
