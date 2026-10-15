import asyncio
import re

from .wire import DETECT, ProtocolError


def bluetooth_address(text):
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", text):
        raise ValueError("Expected a six-byte Bluetooth address")
    return bytes.fromhex(text.replace(":", "").replace("-", ""))


class BluetoothStream:
    def __init__(self, process):
        self.process = process

    @classmethod
    async def open(cls, executable, address):
        bluetooth_address(address)
        process = await asyncio.create_subprocess_exec(
            executable,
            address,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        return cls(process)

    async def detect(self):
        await self.sendall(DETECT)
        response = await asyncio.wait_for(self.recvall(6), 20)
        if response != DETECT:
            raise ProtocolError(f"Unexpected iAP2 detection response: {response.hex()}")

    async def recvall(self, size):
        return await self.process.stdout.readexactly(size)

    async def sendall(self, data):
        self.process.stdin.write(data)
        await self.process.stdin.drain()

    async def close(self):
        self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), 2)
        except TimeoutError:
            self.process.terminate()
            await self.process.wait()


async def controller_address(executable):
    process = await asyncio.create_subprocess_exec(
        executable,
        "--controller",
        stdout=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), 10)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise
    if process.returncode:
        raise RuntimeError("Unable to read the local Bluetooth controller address")
    return bluetooth_address(stdout.decode().strip())
