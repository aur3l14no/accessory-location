"""A small stop-and-wait iAP2 link over an asynchronous byte stream."""

import asyncio
import secrets
import struct
from collections import deque

from .wire import ACK, EAK, RST, SYN, Message, MessageBuffer, Packet, ProtocolError


class Link:
    def __init__(self, stream, emit=lambda **event: None):
        self.stream = stream
        self.emit = emit
        self.sequence = secrets.randbelow(256)
        self.peer_sequence = 0
        self.session = 1
        self.maximum_packet = 4096
        self.retransmit_seconds = 2.0
        self.messages = deque()
        self.assembler = MessageBuffer()
        self.reader_task = None

    async def _read(self):
        header = await self.stream.recvall(9)
        if len(header) != 9:
            raise EOFError("iAP2 stream closed")
        size = int.from_bytes(header[2:4], "big")
        if header[:2] != b"\xffZ" or sum(header) & 255 or not 9 <= size <= 4096:
            raise ProtocolError("Malformed or oversized incoming packet")
        return Packet.decode(header + (await self.stream.recvall(size - 9) if size > 9 else b""))

    async def read(self, timeout):
        # A timeout must not discard a partially received packet.
        if self.reader_task is None:
            self.reader_task = asyncio.create_task(self._read())
        try:
            packet = await asyncio.wait_for(asyncio.shield(self.reader_task), timeout)
        except TimeoutError:
            raise
        else:
            self.reader_task = None
            return packet

    async def write(self, packet):
        await self.stream.sendall(packet.encode())

    async def handshake(self):
        offer = struct.pack(">BBHHHBB", 1, 1, 4096, 2000, 22, 5, 1) + bytes([1, 0, 2])
        syn = Packet(SYN, self.sequence, 0, payload=offer)
        for _ in range(3):
            await self.write(syn)
            try:
                response = await self.read(2.0)
            except TimeoutError:
                continue
            if response.flags & (SYN | ACK) != SYN | ACK:
                raise ProtocolError("Expected SYN+ACK")
            if response.acknowledgement != self.sequence or len(response.payload) < 13:
                raise ProtocolError("Invalid handshake acknowledgement or parameters")
            version, window, size, retry, _, _, _ = struct.unpack(">BBHHHBB", response.payload[:10])
            sessions = response.payload[10:]
            if version != 1 or window < 1 or size < 10 or len(sessions) % 3:
                raise ProtocolError("Unsupported link parameters")
            if bytes([1, 0, 2]) not in [sessions[i : i + 3] for i in range(0, len(sessions), 3)]:
                raise ProtocolError("Peer did not accept control session 1 version 2")
            self.maximum_packet = min(size, 4096)
            self.retransmit_seconds = max(retry / 1000, 0.1)
            self.peer_sequence = response.sequence
            await self.acknowledge()
            self.emit(event="link_ready", control_session=self.session)
            return
        raise TimeoutError("No iAP2 SYN acknowledgement")

    async def acknowledge(self):
        await self.write(Packet(ACK, self.sequence, self.peer_sequence))

    async def accept(self, packet):
        if packet.flags & RST:
            raise ConnectionError("Peer reset the iAP2 link")
        if packet.flags & SYN:
            # A retransmitted SYN+ACK can arrive if our final handshake ACK was lost.
            if packet.sequence != self.peer_sequence:
                raise ProtocolError("Unexpected new SYN during established link")
            await self.acknowledge()
            return
        if packet.payload and not packet.flags & EAK:
            if packet.sequence == (self.peer_sequence + 1) & 255:
                self.peer_sequence = packet.sequence
                if packet.session != self.session:
                    raise ProtocolError("Data on an unnegotiated session")
                self.messages.extend(self.assembler.feed(packet.payload))
            # Duplicate or out-of-order: acknowledge last contiguous sequence, never deliver twice.
            await self.acknowledge()

    async def send(self, message: Message):
        raw = message.encode()
        for offset in range(0, len(raw), self.maximum_packet - 10):
            self.sequence = (self.sequence + 1) & 255
            payload = raw[offset : offset + self.maximum_packet - 10]
            acknowledged = False
            for attempt in range(4):
                await self.write(
                    Packet(ACK, self.sequence, self.peer_sequence, self.session, payload)
                )
                deadline = asyncio.get_running_loop().time() + self.retransmit_seconds
                while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
                    try:
                        packet = await self.read(remaining)
                    except TimeoutError:
                        break
                    await self.accept(packet)
                    if packet.flags & ACK and packet.acknowledgement == self.sequence:
                        acknowledged = True
                        break
                if acknowledged:
                    break
                self.emit(event="retransmit", attempt=attempt + 1)
            if not acknowledged:
                raise TimeoutError("Peer did not acknowledge data")

    async def receive(self, timeout=10):
        deadline = asyncio.get_running_loop().time() + timeout
        while not self.messages:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("No control message before deadline")
            await self.accept(await self.read(remaining))
        return self.messages.popleft()

    async def close(self):
        if self.reader_task is not None:
            self.reader_task.cancel()
            await asyncio.gather(self.reader_task, return_exceptions=True)
        await self.stream.close()
