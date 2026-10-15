#!/usr/bin/env python3
"""Local MFi-v3 JSONL authentication helper; supplies no accessory identity.

Requires cryptography in the interpreter environment. Configure caller-provided files:
  ACCESSORY_MFI_CERT_FILE=/path/to/certificate.p7b
  ACCESSORY_MFI_KEY_FILE=/path/to/identity.pk8

The certificate must be a DER PKCS#7 container with one matching non-CA leaf.
The matching private key must be unencrypted DER PKCS#8 P-256. This helper checks
structure and key consistency, NOT Apple trust, authorization, or revocation.
It has no network, Apple API, USB, Bluetooth, or device operation.
"""

import base64
import binascii
import json
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import pkcs7

MAX_IDENTITY_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 128 * 1024


class ProviderError(Exception):
    pass


def is_pkcs8(data):
    """Distinguish plaintext PKCS#8 from SEC1; cryptography validates key contents."""

    def field(offset):
        if offset + 2 > len(data):
            raise ValueError
        tag, size = data[offset : offset + 2]
        offset += 2
        if size & 0x80:
            count = size & 0x7F
            if not 1 <= count <= 4 or offset + count > len(data):
                raise ValueError
            size = int.from_bytes(data[offset : offset + count], "big")
            offset += count
        end = offset + size
        if end > len(data):
            raise ValueError
        return tag, offset, end

    try:
        tag, start, end = field(0)
        if tag != 0x30 or end != len(data):
            return False
        version_tag, _, after_version = field(start)
        algorithm_tag, _, after_algorithm = field(after_version)
        key_tag, _, _ = field(after_algorithm)
        return version_tag == 0x02 and algorithm_tag == 0x30 and key_tag == 0x04
    except (ValueError, IndexError):
        return False


def read_identity_file(variable):
    path = os.environ.get(variable)
    if not path:
        raise ProviderError(f"Set {variable} to a caller-supplied identity file")
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_IDENTITY_BYTES + 1)
    except OSError:
        raise ProviderError(f"Cannot read {variable}") from None
    if not data or len(data) > MAX_IDENTITY_BYTES:
        raise ProviderError(f"{variable} must contain 1..{MAX_IDENTITY_BYTES} bytes")
    return data


def validate_identity(certificate, encoded_key):
    """Check bounded DER containers and a unique matching P-256 leaf; return the key."""
    for data in (certificate, encoded_key):
        if not data or len(data) > MAX_IDENTITY_BYTES:
            raise ProviderError(f"Identity files must contain 1..{MAX_IDENTITY_BYTES} bytes")
    try:
        certificates = pkcs7.load_der_pkcs7_certificates(certificate)
    except (ValueError, TypeError):
        raise ProviderError("Certificate must be a DER PKCS#7 container") from None
    if not certificates:
        raise ProviderError("PKCS#7 container has no certificates")
    if not is_pkcs8(encoded_key):
        raise ProviderError("Private key must be unencrypted DER PKCS#8")
    try:
        key = serialization.load_der_private_key(encoded_key, password=None)
    except (ValueError, TypeError):
        raise ProviderError("Private key must be unencrypted DER PKCS#8") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ProviderError("Private key must use P-256")
    matching_leaves = 0
    for cert in certificates:
        try:
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                continue
        except x509.ExtensionNotFound:
            pass
        public_key = cert.public_key()
        if (
            isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP256R1)
            and public_key.public_numbers() == key.public_key().public_numbers()
        ):
            matching_leaves += 1
    if matching_leaves != 1:
        raise ProviderError("Private key must match exactly one non-CA leaf certificate")
    return key


class LocalMfiV3:
    def __init__(self):
        self.key = None
        self.certificate = None

    def load(self):
        if self.key is not None:
            return
        certificate = read_identity_file("ACCESSORY_MFI_CERT_FILE")
        encoded_key = read_identity_file("ACCESSORY_MFI_KEY_FILE")
        key = validate_identity(certificate, encoded_key)
        self.key = key
        self.certificate = certificate

    def handle(self, request):
        if not isinstance(request, dict):
            raise ProviderError("Request must be a JSON object")
        operation = request.get("op")
        if operation == "certificate":
            self.load()
            return {
                "type": "mfi",
                "certificate": base64.b64encode(self.certificate).decode("ascii"),
            }
        if operation != "sign":
            raise ProviderError("Operation must be certificate or sign")
        if self.key is None:
            raise ProviderError("Request a certificate first")
        encoded = request.get("challenge")
        if not isinstance(encoded, str):
            raise ProviderError("Challenge must be base64 text")
        try:
            digest = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ProviderError("Challenge must be valid base64") from None
        if len(digest) != 32:
            raise ProviderError("MFi v3 requires exactly 32 challenge bytes")
        signature_der = self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature_der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return {"signature": base64.b64encode(raw).decode("ascii")}


def main():
    provider = LocalMfiV3()
    while True:
        line = sys.stdin.buffer.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            break
        too_large = len(line) > MAX_REQUEST_BYTES
        try:
            if too_large:
                raise ProviderError("Request exceeds size limit")
            try:
                request = json.loads(line)
            except (ValueError, UnicodeError):
                raise ProviderError("Request must be valid JSON") from None
            response = provider.handle(request)
        except ProviderError as error:
            response = {"error": str(error)}
        except Exception:
            # No raw input, key, certificate, path, or traceback enters diagnostics.
            response = {"error": "Local identity operation failed"}
        print(json.dumps(response, separators=(",", ":")), flush=True)
        if too_large:
            break


if __name__ == "__main__":
    main()
