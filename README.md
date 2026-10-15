# Accessory Location

A local iAP2 accessory-location client for macOS. It connects to an iPhone over
USB, authenticates through a local helper, and sends GGA/RMC coordinates when the
phone requests them.

**Experimental · GPL-3.0-only.** You must supply an accessory certificate and
matching private key accepted by the device. This project does not include or
generate those credentials. USB is the primary transport; the Bluetooth bridge
is experimental.

## TL;DR — let an agent help

Copy either prompt into a coding agent with access to your Mac. The first builds
an independent implementation; the second uses this repository. Neither approach
removes the need to inspect the code and verify what happens on the phone.

### 1. Build from scratch

```text
Build a local macOS USB iAP2 accessory-location tool from scratch, without using
the accessory-location repository. Use pymobiledevice3's com.apple.carkit.service
and study youcci/playport on GitHub for MFi-v3 authentication. A public experimental
identity source is shihabal3amri/DiPlay v0.2.7: its APK contains
assets/offline-mfi/certificate.p7b and identity.pk8. Review its provenance before
using it; keep credentials local and out of Git. Sign the 32-byte challenge using
prehashed ECDSA P-256 and return raw r||s. After identification and authentication,
wait for a location subscription before sending GGA/RMC. Ask me for target
coordinates and run a bounded session with IP networking blocked. Guide me to
open Maps; if a fix is ignored, toggle Location Services off for about 10 seconds
and back on while sending. Verify the map actually moves, then stop and confirm
the real position returns. Test with synthetic credentials before device use.
```

### 2. Use this project with step-by-step guidance

```text
Help me run https://github.com/aur3l14no/accessory-location on my Mac, guiding me
one step at a time. Read its README and authentication documentation, inspect the
code, and set up dependencies with uv. Help me prepare a matching MFi-v3 identity
using the documented sources; do not assume credentials are bundled. Keep them
outside the checkout and never upload them. Ask for my target coordinates, then
help me connect, unlock, and trust the iPhone over USB. Run the sender through
tools/local-only.sb for a bounded session. Guide me to open Maps and, if needed,
toggle Location Services off for about 10 seconds and back on. Distinguish
authentication, subscription, packet acknowledgement, and actual map movement.
Finish by stopping the sender and confirming the real position returns. Do not
change unrelated device settings or include device identifiers in shared logs.
```

## Usage

From the repository directory, after [setup](#setup):

```sh
export ACCESSORY_MFI_CERT_FILE=/absolute/path/to/certificate.p7b
export ACCESSORY_MFI_KEY_FILE=/absolute/path/to/identity.pk8

uv run accessory-location send --transport usb \
  --auth-helper tools/local_mfi_v3_helper.py \
  --latitude 48.1173 --longitude 11.5167 --duration 180
```

The coordinates above are an example. Replace them with your intended test
location. Open a location consumer such as Maps on the phone to trigger a
subscription. The sender waits for identification, authentication, and a
location request before transmitting coordinates.

Look for these JSON events:

```json
{"event":"authentication_succeeded"}
{"event":"location_requested","sentences":[1,2]}
{"event":"location_link_acknowledged","count":1}
```

An acknowledgement confirms delivery, not adoption. Check the phone's map to
verify that its reported position actually changed. Stop with Ctrl-C or let the
session expire, disconnect USB, and confirm the real position returns. The phone
may retain its last fix temporarily.

## Setup

Requires macOS, Python 3.11 or later, [uv](https://docs.astral.sh/uv/), and an
unlocked iPhone that already trusts the Mac. A developer disk image is not used.

```sh
git clone https://github.com/aur3l14no/accessory-location.git
cd accessory-location
uv sync --locked
```

Keep identity files outside the checkout. The included helper expects a DER
PKCS#7 certificate container and an unencrypted DER PKCS#8 P-256 private key.
See [authentication](docs/authentication.md) for validation rules, the helper
interface, and upstream identity documentation. A self-signed test certificate
does not establish device trust.

To observe the handshake without sending coordinates:

```sh
uv run accessory-location probe --transport usb \
  --auth-helper tools/local_mfi_v3_helper.py --duration 20
```

To deny IP networking for the sender and its helper, install dependencies first,
then use the included macOS sandbox profile:

```sh
/usr/bin/sandbox-exec -f tools/local-only.sb \
  uv run --no-sync accessory-location send --transport usb \
  --auth-helper tools/local_mfi_v3_helper.py \
  --latitude 48.1173 --longitude 11.5167 --duration 180
```

The profile preserves local Unix sockets used for USB transport. It also denies
access to the background URL-session service.

## Troubleshooting

| Observation | Next step |
| --- | --- |
| No device or a trust error | Unlock the phone, reconnect USB, and complete its Trust prompt. |
| Authentication fails | Check the certificate/key format and match; device acceptance is separate from local validation. |
| Authentication succeeds, but no location request | Open Maps and request the current position. |
| Packets are acknowledged, but the position does not move | Keep the sender running, turn Location Services off for about 10 seconds, turn it on, then request the current position again. iOS may still reject the fix. |
| Position persists after stopping | Disconnect the accessory and toggle Location Services, then verify the map again. |

The tool does not read back the phone's selected coordinates or location-source
flags. Device and OS changes can affect authentication, subscription, and
coordinate adoption independently.

## Experimental Bluetooth transport

Requires Apple Command Line Tools and an already paired phone:

```sh
make native
build/bluetooth-bridge --list
uv run accessory-location probe --transport bluetooth \
  --device AA:BB:CC:DD:EE:FF \
  --auth-helper tools/local_mfi_v3_helper.py
```

The bridge discovers an outgoing iAP2 RFCOMM channel through SDP. It does not
provide pairing, an incoming service, wireless CarPlay, or automatic reconnect.
The listing command prints paired-device names and addresses locally.

## Development

```sh
uv run ruff check src tests tools
uv run pytest -q
make native
```

Tests use local loopback peers and temporary synthetic identities, without
connecting to a phone. See [contributing](CONTRIBUTING.md), the
[protocol reference](docs/protocol.md), and [sources](docs/sources.md).

## License

[GNU GPL version 3](LICENSE), `GPL-3.0-only`. Third-party identity material is not
part of this project or its license.
