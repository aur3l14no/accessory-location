# Contributing

Use Python 3.11 or later and uv:

```sh
uv sync --locked
uv run ruff check src tests tools
uv run pytest -q
make native
```

The native build requires macOS and Apple Command Line Tools. Protocol tests use
local loopback sockets. Authentication tests generate temporary synthetic keys
and certificates; no phone or real accessory identity is needed.

Keep protocol changes covered by interoperability-focused tests: malformed
frames, fragmentation, retransmission, sequence wrap, subscription handling,
and cryptographic encoding. Do not add captured sessions or real credentials as
fixtures. Use artificial data and remove device identifiers from issue reports.

Keep user instructions in the README, protocol details in `docs/protocol.md`,
and helper integration details in `docs/authentication.md`.
