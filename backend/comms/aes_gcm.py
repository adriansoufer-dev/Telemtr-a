from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


AES_128_KEY_LEN = 16
AES_GCM_NONCE_LEN = 12
AES_GCM_TAG_LEN = 16


class AESGCMError(ValueError):
    """Base exception for AES-GCM framing/decryption errors."""


class AESGCMAuthError(AESGCMError):
    """Raised when the GCM authentication tag is invalid."""


@dataclass(frozen=True)
class AESGCMFrame:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


class AESGCMCodec:
    """AES-128-GCM codec for UART packets.

    Wire frame format:
        nonce(12 bytes) || ciphertext(N bytes) || tag(16 bytes)

    AES-GCM does not pad, so ciphertext length equals plaintext SPP packet
    length. The packet buffer is responsible for identifying candidate frame
    boundaries in the continuous UART stream.
    """

    def __init__(
        self,
        key: bytes,
        *,
        nonce_len: int = AES_GCM_NONCE_LEN,
        tag_len: int = AES_GCM_TAG_LEN,
        associated_data: bytes | None = None,
    ) -> None:
        if len(key) != AES_128_KEY_LEN:
            raise AESGCMError(f"AES-128-GCM key must be {AES_128_KEY_LEN} bytes")
        self._aesgcm = AESGCM(key)
        self.nonce_len = nonce_len
        self.tag_len = tag_len
        self.associated_data = associated_data

    @classmethod
    def from_hex_key(
        cls,
        key_hex: str,
        *,
        associated_data: bytes | None = None,
    ) -> "AESGCMCodec":
        try:
            key = bytes.fromhex(key_hex)
        except ValueError as exc:
            raise AESGCMError("TELEMETRY_AES_KEY_HEX is not valid hex") from exc
        return cls(key, associated_data=associated_data)

    @property
    def overhead_len(self) -> int:
        return self.nonce_len + self.tag_len

    def split_frame(self, frame: bytes) -> AESGCMFrame:
        min_len = self.nonce_len + self.tag_len + 1
        if len(frame) < min_len:
            raise AESGCMError(f"encrypted frame too short: {len(frame)} < {min_len}")
        nonce = frame[: self.nonce_len]
        ciphertext = frame[self.nonce_len : -self.tag_len]
        tag = frame[-self.tag_len :]
        return AESGCMFrame(nonce=nonce, ciphertext=ciphertext, tag=tag)

    def decrypt_frame(self, frame: bytes) -> bytes:
        parts = self.split_frame(frame)
        try:
            return self._aesgcm.decrypt(
                parts.nonce,
                parts.ciphertext + parts.tag,
                self.associated_data,
            )
        except InvalidTag as exc:
            raise AESGCMAuthError("AES-GCM authentication failed") from exc

    def encrypt_packet(self, packet: bytes, nonce: bytes) -> bytes:
        if len(nonce) != self.nonce_len:
            raise AESGCMError(f"nonce must be {self.nonce_len} bytes")
        encrypted = self._aesgcm.encrypt(nonce, packet, self.associated_data)
        ciphertext = encrypted[:-self.tag_len]
        tag = encrypted[-self.tag_len :]
        return nonce + ciphertext + tag
