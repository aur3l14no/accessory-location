"""Offline integration test; all generated private-key files are temporary."""

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from accessory_location.auth import AuthenticationProvider
from accessory_location.wire import parameters

HELPER = Path(__file__).resolve().parents[1] / "tools" / "local_mfi_v3_helper.py"


def make_certificate(key, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UNTRUSTED TEST ONLY")])
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def encode_key(key, format=serialization.PrivateFormat.PKCS8):
    return key.private_bytes(serialization.Encoding.DER, format, serialization.NoEncryption())


async def expect_error(cert_bytes, key_bytes, cert_file, key_file, phrase):
    cert_file.write_bytes(cert_bytes)
    key_file.write_bytes(key_bytes)
    provider = AuthenticationProvider(str(HELPER))
    try:
        try:
            await provider.certificate()
        except RuntimeError as error:
            assert phrase in str(error), str(error)
        else:
            raise AssertionError("Malformed/mismatched identity accepted")
    finally:
        await provider.close()


async def run_in_directory(directory):
    cert_file = directory / "untrusted-test.p7b"
    key_file = directory / "untrusted-test.pk8"
    os.environ["ACCESSORY_MFI_CERT_FILE"] = str(cert_file)
    os.environ["ACCESSORY_MFI_KEY_FILE"] = str(key_file)
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = make_certificate(key)
    cert_bytes = pkcs7.serialize_certificates([certificate], serialization.Encoding.DER)
    key_bytes = encode_key(key)
    cert_file.write_bytes(cert_bytes)
    key_file.write_bytes(key_bytes)
    key_file.chmod(0o600)

    provider = AuthenticationProvider(str(HELPER))
    try:
        response = await provider.certificate()
        assert response.identifier == 0xAA01
        assert parameters(response.body) == [(0, cert_bytes)]
        verification_key = pkcs7.load_der_pkcs7_certificates(parameters(response.body)[0][1])[
            0
        ].public_key()
        for number in range(32):
            digest = hashlib.sha256(f"ephemeral test {number}".encode()).digest()
            response = await provider.sign(digest)
            assert response.identifier == 0xAA03
            signature_fields = parameters(response.body)
            assert len(signature_fields) == 1 and signature_fields[0][0] == 0
            raw = signature_fields[0][1]
            assert len(raw) == 64
            der = utils.encode_dss_signature(
                int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
            )
            verification_key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            try:
                verification_key.verify(der, digest, ec.ECDSA(hashes.SHA256()))
            except InvalidSignature:
                pass
            else:
                raise AssertionError("Double-hashing was not detected")
        for length in (1, 31, 33, 64):
            try:
                await provider.sign(bytes(length))
            except RuntimeError as error:
                assert "exactly 32" in str(error)
            else:
                raise AssertionError("Wrong challenge length accepted")
        try:
            await provider.request("sign", challenge="%not-base64%")
        except RuntimeError as error:
            assert "valid base64" in str(error)
        else:
            raise AssertionError("Malformed base64 accepted")
    finally:
        await provider.close()

    other_key = ec.generate_private_key(ec.SECP256R1())
    await expect_error(cert_bytes, encode_key(other_key), cert_file, key_file, "exactly one non-CA")
    multi = pkcs7.serialize_certificates(
        [certificate, make_certificate(key)], serialization.Encoding.DER
    )
    await expect_error(multi, key_bytes, cert_file, key_file, "exactly one non-CA")
    only_ca = pkcs7.serialize_certificates(
        [make_certificate(key, ca=True)], serialization.Encoding.DER
    )
    await expect_error(only_ca, key_bytes, cert_file, key_file, "exactly one non-CA")
    p384 = ec.generate_private_key(ec.SECP384R1())
    non_p256 = pkcs7.serialize_certificates([make_certificate(p384)], serialization.Encoding.DER)
    await expect_error(non_p256, encode_key(p384), cert_file, key_file, "P-256")
    await expect_error(b"bad DER", key_bytes, cert_file, key_file, "DER PKCS#7")
    await expect_error(cert_bytes, b"bad DER", cert_file, key_file, "DER PKCS#8")
    await expect_error(
        cert_bytes,
        encode_key(key, serialization.PrivateFormat.TraditionalOpenSSL),
        cert_file,
        key_file,
        "unencrypted DER PKCS#8",
    )
    await expect_error(cert_bytes, b"x" * (16 * 1024 + 1), cert_file, key_file, "1..16384")

    # A bundle may contain CA certificates using another curve; preserve it verbatim.
    chain_bundle = pkcs7.serialize_certificates(
        [certificate, make_certificate(p384, ca=True)], serialization.Encoding.DER
    )
    cert_file.write_bytes(chain_bundle)
    key_file.write_bytes(key_bytes)
    provider = AuthenticationProvider(str(HELPER))
    try:
        response = await provider.certificate()
        assert parameters(response.body) == [(0, chain_bundle)]
    finally:
        await provider.close()


async def test_ephemeral_local_mfi_v3_helper(tmp_path, monkeypatch):
    # Replace both inherited paths before starting any helper subprocess.
    with TemporaryDirectory(prefix="ephemeral-mfi-check-", dir=tmp_path) as temp:
        directory = Path(temp)
        monkeypatch.setenv("ACCESSORY_MFI_CERT_FILE", str(directory / "untrusted-test.p7b"))
        monkeypatch.setenv("ACCESSORY_MFI_KEY_FILE", str(directory / "untrusted-test.pk8"))
        await run_in_directory(directory)
    assert not directory.exists()
