import asyncio
import struct
from datetime import UTC, datetime

import pytest

from accessory_location.link import Link
from accessory_location.profile import coordinate, identity, location_sentences, sentence
from accessory_location.wire import (
    ACK,
    SYN,
    Message,
    MessageBuffer,
    Packet,
    ProtocolError,
    parameters,
)


def test_synack_reference_vector():
    payload = bytes.fromhex("017fffff07d000161e03010002")
    packet = Packet(0xC0, 176, 71, 0, payload)
    # Fixed protocol values exercise an independently calculated header checksum.
    assert packet.encode()[:9] == bytes.fromhex("ff5a0017c0b04700d9")
    assert Packet.decode(packet.encode()) == packet


@pytest.mark.parametrize("offset", [0, 3, 6, 8, 10, 13])
def test_corruption_is_rejected(offset):
    raw = bytearray(Packet(ACK, 2, 3, 1, b"hello").encode())
    raw[offset] ^= 1
    with pytest.raises(ProtocolError):
        Packet.decode(bytes(raw))


def test_control_messages_survive_arbitrary_fragmentation():
    expected = [Message(0x1D00), Message(0x1D01, b"abcdef"), Message(0xFFFC)]
    wire = b"".join(m.encode() for m in expected)
    for width in range(1, len(wire) + 1):
        buffer = MessageBuffer()
        found = []
        for offset in range(0, len(wire), width):
            found.extend(buffer.feed(wire[offset : offset + width]))
        assert found == expected


@pytest.mark.parametrize("raw", [b"\x00", b"\x00\x03\x00\x01", b"\x00\x08\x00\x01x"])
def test_invalid_parameters_fail(raw):
    with pytest.raises(ProtocolError):
        parameters(raw)


def test_identification_only_advertises_implemented_gps_features():
    fields = dict(parameters(identity().body))
    assert fields[6] == bytes.fromhex("fffb")
    assert fields[7] == bytes.fromhex("fffafffc")
    assert set(dict(parameters(fields[22]))) == {0, 1, 17, 18}
    assert 24 not in fields  # No wireless CarPlay service is implemented.


def test_nmea_known_reference_and_rounding():
    body = "GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,"
    assert sentence(body) == f"${body}*47\r\n"
    assert coordinate(89.999999999, True) == ("9000.0000", "N")
    assert coordinate(-122.009, False) == ("12200.5400", "W")
    sentences = location_sentences(37.3349, -122.009, datetime(2000, 1, 1, tzinfo=UTC))
    assert ",3720.0940,N,12200.5400,W," in sentences[1]
    assert ",010100,,,A*" in sentences[2]


@pytest.mark.parametrize("value,latitude", [(91, True), (-181, False), (float("nan"), True)])
def test_invalid_location_is_rejected(value, latitude):
    with pytest.raises(ValueError):
        coordinate(value, latitude)


class Stream:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer

    async def recvall(self, size):
        return await self.reader.readexactly(size)

    async def sendall(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def close(self):
        self.writer.close()
        await self.writer.wait_closed()


async def read_frame(reader):
    header = await reader.readexactly(9)
    tail = await reader.readexactly(int.from_bytes(header[2:4], "big") - 9)
    return Packet.decode(header + tail)


async def test_link_retry_duplicate_delivery_sequence_wrap_and_partial_read():
    errors = []
    finished = asyncio.Event()

    async def peer(reader, writer):
        try:
            syn = await read_frame(reader)
            assert syn.flags == SYN
            body = struct.pack(">BBHHHBB", 1, 1, 4096, 40, 22, 5, 1) + bytes([1, 0, 2])
            writer.write(Packet(SYN | ACK, 254, syn.sequence, payload=body).encode())
            await writer.drain()
            assert (await read_frame(reader)).acknowledgement == 254
            start = Packet(ACK, 255, syn.sequence, 1, Message(0x1D00).encode()).encode()
            writer.write(start[:5])
            await writer.drain()
            await asyncio.sleep(0.04)  # Survive caller timeout with half a header buffered.
            writer.write(start[5:])
            await writer.drain()
            assert (await read_frame(reader)).acknowledgement == 255
            first = await read_frame(reader)
            assert first.sequence == 0  # Host sequence wraps from 255.
            retry = await read_frame(reader)  # Intentionally drop its first ACK.
            assert retry == first
            writer.write(Packet(ACK, 255, first.sequence, 1, Message(0x1D00).encode()).encode())
            await writer.drain()
            assert (await read_frame(reader)).acknowledgement == 255
            writer.write(Packet(ACK, 0, first.sequence, 1, Message(0x1D02).encode()).encode())
            await writer.drain()
            assert (await read_frame(reader)).acknowledgement == 0
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
            finished.set()

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    address = server.sockets[0].getsockname()
    reader, writer = await asyncio.open_connection(*address)
    link = Link(Stream(reader, writer))
    link.sequence = 255
    try:
        await link.handshake()
        with pytest.raises(TimeoutError):
            await link.receive(0.01)
        assert (await link.receive()).identifier == 0x1D00
        await link.send(identity())
        assert (await link.receive()).identifier == 0x1D02  # No duplicate StartIdentification.
        await asyncio.wait_for(finished.wait(), 2)
        assert not errors
    finally:
        await link.close()
        server.close()
        await server.wait_closed()
