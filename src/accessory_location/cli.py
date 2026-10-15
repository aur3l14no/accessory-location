import argparse
import asyncio
import json
import math

from pymobiledevice3.lockdown import create_using_usbmux

from .auth import AuthenticationProvider
from .link import Link
from .profile import coordinate, identity, location_message, location_sentences
from .transport import BluetoothStream, controller_address
from .wire import parameters


def emit(**event):
    print(json.dumps(event, ensure_ascii=False), flush=True)


async def run(args):
    phone = None
    link = None
    auth = AuthenticationProvider(args.auth_helper) if args.auth_helper else None
    try:
        local_address = None
        if args.transport == "usb":
            phone = await create_using_usbmux(connection_type="USB", autopair=False)
            emit(event="device_connected", transport="usb")
            stream = await phone.start_lockdown_service("com.apple.carkit.service")
        else:
            local_address = await controller_address(args.bluetooth_helper)
            stream = await BluetoothStream.open(args.bluetooth_helper, args.device)
        link = Link(stream, emit)
        if args.transport == "bluetooth":
            await stream.detect()
        await link.handshake()
        deadline = asyncio.get_running_loop().time() + args.duration
        active, last_sent, intervals = set(), {}, {}
        identified = False
        authenticated = False
        sent_count = 0
        while (remaining := deadline - asyncio.get_running_loop().time()) > 0:
            try:
                message = await link.receive(min(0.25, remaining))
            except TimeoutError:
                message = None
            if message is not None:
                fields = parameters(message.body)
                emit(
                    event="message",
                    identifier=f"0x{message.identifier:04x}",
                    parameters=[{"id": i, "bytes": len(b)} for i, b in fields],
                )
                if message.identifier == 0x1D00:
                    await link.send(identity(args.transport, local_address))
                elif message.identifier == 0x1D02:
                    identified = True
                    emit(event="identification_accepted")
                elif message.identifier == 0x1D03:
                    raise RuntimeError(f"Identification rejected: {[i for i, _ in fields]}")
                elif message.identifier == 0xAA00:
                    if auth is None:
                        raise RuntimeError(
                            "Accessory authentication required; no credential configured"
                        )
                    await link.send(await auth.certificate())
                elif message.identifier == 0xAA02:
                    if auth is None:
                        raise RuntimeError(
                            "Accessory authentication required; no credential configured"
                        )
                    challenges = [b for i, b in fields if i == 0]
                    if len(challenges) != 1:
                        raise RuntimeError("Invalid authentication challenge parameters")
                    await link.send(await auth.sign(challenges[0]))
                elif message.identifier == 0xAA05:
                    authenticated = True
                    emit(event="authentication_succeeded")
                elif message.identifier == 0xAA04:
                    raise RuntimeError("Accessory authentication failed")
                elif message.identifier == 0xFFFA:
                    active = {i for i, b in fields if i in (1, 2) and not b}
                    intervals = {
                        i - 0x8000: max(1.0, int.from_bytes(b, "big") / 1000)
                        for i, b in fields
                        if i in (0x8001, 0x8002) and len(b) == 4
                    }
                    last_sent.clear()
                    emit(event="location_requested", sentences=sorted(active))
                elif message.identifier == 0xFFFC:
                    active.clear()
                    emit(event="location_stopped")
            if args.command == "send" and identified and authenticated and active:
                now = asyncio.get_running_loop().time()
                due = sorted(
                    i
                    for i in active
                    if now - last_sent.get(i, -math.inf) >= max(args.interval, intervals.get(i, 1))
                )
                if due:
                    sentences = location_sentences(args.latitude, args.longitude)
                    await link.send(location_message([sentences[i] for i in due]))
                    last_sent.update({i: now for i in due})
                    sent_count += 1
                    if sent_count == 1 or sent_count % 10 == 0:
                        emit(event="location_link_acknowledged", count=sent_count)
        emit(
            event="finished",
            identified=identified,
            authenticated=authenticated,
            location_packets_acknowledged=sent_count,
            phone_location_verified=False,
        )
    finally:
        if link is not None:
            await link.close()
        if phone is not None:
            await phone.close()
        if auth is not None:
            await auth.close()


def main():
    parser = argparse.ArgumentParser(description="Experimental iAP2 accessory-location client")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("probe", "send"):
        command = commands.add_parser(name)
        command.add_argument("--transport", choices=["usb", "bluetooth"], default="usb")
        command.add_argument("--device", help="Previously paired iPhone Bluetooth address")
        command.add_argument("--bluetooth-helper", default="build/bluetooth-bridge")
        command.add_argument(
            "--auth-helper", help="Path to a local JSON-lines certificate/signing provider"
        )
        command.add_argument("--duration", type=float, default=20 if name == "probe" else 60)
        if name == "send":
            command.add_argument("--latitude", type=float, required=True)
            command.add_argument("--longitude", type=float, required=True)
            command.add_argument("--interval", type=float, default=1)
    args = parser.parse_args()
    if args.transport == "bluetooth" and not args.device:
        parser.error("Bluetooth transport requires --device with the paired iPhone address")
    if not math.isfinite(args.duration) or not 0 < args.duration <= 3600:
        parser.error("duration must be between 0 and 3600 seconds")
    if args.command == "send":
        try:
            coordinate(args.latitude, True)
            coordinate(args.longitude, False)
            if not math.isfinite(args.interval) or args.interval < 1:
                raise ValueError("interval must be at least 1 second")
        except ValueError as error:
            parser.error(str(error))
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        emit(event="interrupted")
    except Exception as error:
        emit(event="error", type=type(error).__name__, detail=str(error))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
