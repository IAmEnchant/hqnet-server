"""Packet codec, constants and string helpers."""

import struct

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ENCODING = 'euc-kr'
MAX_PACKET_SIZE = 10000
MIN_PACKET_SIZE = 4
NAME_SIZE = 21        # 20 chars + null
NAME_FIELD = 20       # strncpy size for sub_type 1/2
MAP_SIZE = 9          # 8 chars + null
GAME_ENTRY_SIZE = 50
USER_DETAIL_SIZE = 27
CHANNEL_DELIMITER = '\n'  # delimiter for 0x04 channel list (may need tuning)


# ---------------------------------------------------------------------------
# String / byte helpers
# ---------------------------------------------------------------------------
def encode_fixed(s: str, size: int) -> bytes:
    """Encode string to fixed-size null-terminated field (EUC-KR)."""
    raw = s.encode(ENCODING, errors='replace')[:size - 1]
    return raw + b'\x00' * (size - len(raw))


def decode_fixed(data: bytes) -> str:
    """Decode null-terminated EUC-KR bytes."""
    idx = data.find(0)
    if idx >= 0:
        data = data[:idx]
    return data.decode(ENCODING, errors='replace')


# ---------------------------------------------------------------------------
# PacketCodec
# ---------------------------------------------------------------------------
class PacketCodec:
    """Packet framing: 3-byte header (LE uint16 length + XOR checksum) + payload."""

    @staticmethod
    def xor_checksum(data: bytes) -> int:
        c = 0
        for b in data:
            c ^= b
        return c

    @staticmethod
    def build_packet(payload: bytes) -> bytearray:
        total = len(payload) + 3
        chk = PacketCodec.xor_checksum(payload)
        packet = bytearray(total)
        struct.pack_into('<H', packet, 0, total)
        packet[2] = chk
        packet[3:] = payload
        return packet

    @staticmethod
    def parse_stream(buf: bytearray) -> tuple[bytes | None, int]:
        """Try to extract one packet from *buf*.  Returns (payload, consumed)."""
        if len(buf) < 4:
            return None, 0
        total = struct.unpack_from('<H', buf, 0)[0]
        if total < MIN_PACKET_SIZE or total > MAX_PACKET_SIZE:
            return None, len(buf)          # corrupt → flush
        if len(buf) < total:
            return None, 0                 # incomplete
        payload_view = memoryview(buf)[3:total]
        if buf[2] != PacketCodec.xor_checksum(payload_view):
            return None, total             # bad checksum → skip
        return payload_view.tobytes(), total
