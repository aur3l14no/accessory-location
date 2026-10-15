import base64

import pytest

from accessory_location.auth import AuthenticationProvider
from accessory_location.wire import ProtocolError, parameters


class Provider(AuthenticationProvider):
    def __init__(self, response):
        super().__init__("unused-test-helper")
        self.response = response
        self.requests = []

    async def request(self, operation, **fields):
        self.requests.append((operation, fields))
        return self.response


async def test_baa_certificate_is_three_distinct_parameters():
    auth = Provider({"type": "baa", "certificate": "bGVhZg==", "intermediate": "Y2E="})
    message = await auth.certificate()
    assert message.identifier == 0xAA01
    assert parameters(message.body) == [(0, b"leaf"), (1, b"\x01"), (2, b"ca")]


async def test_challenge_passed_unchanged_to_provider():
    auth = Provider({"signature": base64.b64encode(b"signed-result").decode()})
    challenge = bytes(range(32))
    message = await auth.sign(challenge)
    assert message.identifier == 0xAA03
    assert parameters(message.body) == [(0, b"signed-result")]
    assert base64.b64decode(auth.requests[0][1]["challenge"]) == challenge


@pytest.mark.parametrize(
    "response",
    [
        {"type": "mfi", "certificate": ""},
        {"type": "baa", "certificate": "bGVhZg==", "intermediate": ""},
        {"type": "unknown", "certificate": "bGVhZg=="},
    ],
)
async def test_incomplete_identity_rejected(response):
    with pytest.raises(ProtocolError):
        await Provider(response).certificate()
