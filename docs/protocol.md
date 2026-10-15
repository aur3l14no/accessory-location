# Protocol reference

This document describes the subset implemented by the client. It is not a
complete iAP2 specification. Research references are listed in [sources](sources.md).

## Transport and framing

USB opens `com.apple.carkit.service` through an already trusted lockdown
connection using `pymobiledevice3`, with USB selected explicitly.

Classic Bluetooth uses IOBluetooth RFCOMM and the accessory-to-phone service
UUID `00000000-deca-fade-deca-deafdecacafe`. SDP supplies the channel number.
Bluetooth begins with the six-byte detection sequence `ff 55 02 00 ee 10`;
USB begins directly with SYN negotiation.

| Offset | Link packet field |
| --- | --- |
| 0–1 | Marker `FF 5A` |
| 2–3 | Total length, big endian |
| 4 | Flags: SYN `80`, ACK `40`, EAK `20`, RST `10` |
| 5 | Sequence number, modulo 256 |
| 6 | Cumulative acknowledgement |
| 7 | Session identifier |
| 8 | Header checksum: the first nine bytes sum to zero modulo 256 |
| 9 onward | Optional payload followed by its additive checksum |

An empty packet is nine bytes. SYN carries a ten-byte link-parameter block and
session triplets `(id, type, version)`. The client offers control session
`(1, 0, 2)` with a 4096-byte receive limit.

The link keeps one outgoing packet outstanding, retransmits within bounded
attempt counts, acknowledges received packets, and suppresses duplicate
messages. A persistent asynchronous reader preserves partial packets across
caller timeouts. Selective-retransmit windows and file-transfer sessions are not
implemented.

## Control messages

A message contains marker `40 40`, a big-endian 16-bit total length, a 16-bit
identifier, and parameters. Each parameter has a 16-bit length including its
four-byte header, a 16-bit identifier, and data. Text is UTF-8 terminated by NUL.
Nested groups use the same parameter encoding.

| Identifier | Direction | Meaning |
| --- | --- | --- |
| `1D00` | phone → accessory | Start identification |
| `1D01` | accessory → phone | Identity and capabilities |
| `1D02` / `1D03` | phone → accessory | Identification accepted / rejected |
| `AA00` | phone → accessory | Request certificate |
| `AA01` | accessory → phone | Certificate response |
| `AA02` | phone → accessory | Challenge |
| `AA03` | accessory → phone | Signature response |
| `AA04` / `AA05` | phone → accessory | Authentication failed / succeeded |
| `FFFA` | phone → accessory | Start location information |
| `FFFB` | accessory → phone | Location information |
| `FFFC` | phone → accessory | Stop location information |

The identity includes fields 0–9, languages 12/13, transport group 16 for USB or
17 for Bluetooth, and location group 22. The location group declares component
ID 0, name 1, and capabilities 17/18 for GGA/RMC. Wireless CarPlay is not advertised.

A location subscription selects GGA with empty parameter 1 and RMC with empty
parameter 2. Optional parameters `8001` / `8002` specify minimum intervals as
32-bit milliseconds. The sender respects these intervals and its own interval,
with a minimum of one second.

Each NMEA sentence occupies a separate parameter 0 in `FFFB`, with CRLF and NUL
termination. Checksums XOR the characters between `$` and `*`. The client sends
stationary GGA/RMC fixes, with UTC timestamps generated at send time. `FFFC`
clears the active subscription immediately.

## Authentication boundary

The client delegates certificate delivery and challenge signing to a local
JSON-lines subprocess. See the [helper contract](authentication.md#helper-contract).
No credential material is part of the package.
