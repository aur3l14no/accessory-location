"""iAP2 framing. Protocol details and references are in docs/protocol.md."""

import struct
from dataclasses import dataclass

SYN, ACK, EAK, RST = 0x80, 0x40, 0x20, 0x10
DETECT = bytes.fromhex("ff550200ee10")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    flags: int
    sequence: int
    acknowledgement: int
    session: int = 0
    payload: bytes = b""

    def encode(self) -> bytes:
        size = 9 + len(self.payload) + bool(self.payload)
        header = struct.pack(
            ">2sHBBBB",
            b"\xffZ",
            size,
            self.flags,
            self.sequence,
            self.acknowledgement,
            self.session,
        )
        frame = header + bytes([-sum(header) & 255])
        if self.payload:
            frame += self.payload + bytes([-sum(self.payload) & 255])
        return frame

    @classmethod
    def decode(cls, raw: bytes) -> "Packet":
        if len(raw) < 9 or raw[:2] != b"\xffZ":
            raise ProtocolError("Bad link marker or truncated header")
        if int.from_bytes(raw[2:4], "big") != len(raw) or sum(raw[:9]) & 255:
            raise ProtocolError("Bad link length or header checksum")
        if len(raw) == 10 or (len(raw) > 9 and sum(raw[9:]) & 255):
            raise ProtocolError("Bad link payload or checksum")
        return cls(*raw[4:8], raw[9:-1] if len(raw) > 9 else b"")


def parameter(identifier: int, data: bytes = b"") -> bytes:
    return struct.pack(">HH", len(data) + 4, identifier) + data


def parameters(raw: bytes) -> list[tuple[int, bytes]]:
    result = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 4:
            raise ProtocolError("Truncated parameter header")
        size, identifier = struct.unpack_from(">HH", raw, offset)
        if size < 4 or offset + size > len(raw):
            raise ProtocolError("Invalid parameter length")
        result.append((identifier, raw[offset + 4 : offset + size]))
        offset += size
    return result


def text_parameter(identifier: int, value: str) -> bytes:
    if "\0" in value:
        raise ValueError("Embedded NUL in protocol string")
    return parameter(identifier, value.encode("utf-8") + b"\0")


@dataclass(frozen=True)
class Message:
    identifier: int
    body: bytes = b""

    def encode(self) -> bytes:
        return struct.pack(">2sHH", b"@@", len(self.body) + 6, self.identifier) + self.body


class MessageBuffer:
    """Control messages may cross link packets or share one packet."""

    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data: bytes) -> list[Message]:
        self.buffer.extend(data)
        result = []
        while len(self.buffer) >= 6:
            marker, size, identifier = struct.unpack_from(">2sHH", self.buffer)
            if marker != b"@@" or size < 6:
                raise ProtocolError("Invalid control message header")
            if len(self.buffer) < size:
                break
            result.append(Message(identifier, bytes(self.buffer[6:size])))
            del self.buffer[:size]
        return result
