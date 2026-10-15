.PHONY: native test check

native: build/bluetooth-bridge

build:
	mkdir -p build

build/bluetooth-bridge: native/bluetooth_bridge.m | build
	xcrun clang -fobjc-arc -framework Foundation -framework IOBluetooth $< -o $@

test:
	uv run pytest -q

check:
	uv run ruff check src tests tools
