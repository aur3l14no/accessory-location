#!/usr/bin/env python3
"""Opt-in local import from the pinned DiPlay preview APK; never runs the APK."""

import argparse
import hashlib
import io
import os
import shlex
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from local_mfi_v3_helper import MAX_IDENTITY_BYTES, ProviderError, validate_identity

APK_URL = "https://github.com/shihabal3amri/DiPlay/releases/download/v0.2.7/DiPlay-0.2.7.apk"
APK_SHA256 = "27b434462da7e78b1ff0987d129ed0a4b0a0e56beceaf8ec221d47150d4675bd"
MAX_APK_BYTES = 64 * 1024 * 1024
CHECKOUT = Path(__file__).resolve().parents[1]
ASSETS = {
    "certificate.p7b": "assets/offline-mfi/certificate.p7b",
    "identity.pk8": "assets/offline-mfi/identity.pk8",
}
NOTICE_URL = (
    "https://github.com/shihabal3amri/DiPlay/blob/main/"
    "docs/THIRD_PARTY_NOTICES.md#experimental-authentication-data"
)


class IdentityImportError(Exception):
    pass


def destination_path(path):
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise IdentityImportError("Output directory must not be a symbolic link")
    destination = expanded.resolve()
    if destination.is_relative_to(CHECKOUT):
        raise IdentityImportError("Keep the output directory outside the repository")
    if destination.exists():
        raise IdentityImportError("Output directory already exists; choose a new directory")
    return destination


def download_apk(stream):
    request = urllib.request.Request(APK_URL, headers={"User-Agent": "accessory-location"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.geturl().startswith("https://"):
            raise IdentityImportError("Download redirected outside HTTPS")
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_APK_BYTES:
                raise IdentityImportError("APK exceeds the download size limit")
            stream.write(chunk)
    stream.seek(0)


def read_identity(stream, expected_digest=None):
    """Verify the full archive before reading only the two named, bounded assets."""
    stream.seek(0)
    archive_bytes = stream.read(MAX_APK_BYTES + 1)
    if len(archive_bytes) > MAX_APK_BYTES:
        raise IdentityImportError("APK exceeds the size limit")
    if hashlib.sha256(archive_bytes).hexdigest() != (expected_digest or APK_SHA256):
        raise IdentityImportError("APK SHA-256 mismatch; expected the pinned DiPlay v0.2.7 release")
    identity = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        names = archive.namelist()
        for filename, asset in ASSETS.items():
            if names.count(asset) != 1:
                raise IdentityImportError(f"APK must contain exactly one {asset}")
            info = archive.getinfo(asset)
            if not 1 <= info.file_size <= MAX_IDENTITY_BYTES:
                raise IdentityImportError("Identity asset exceeds size limits")
            with archive.open(info) as entry:
                data = entry.read(MAX_IDENTITY_BYTES + 1)
            if not data or len(data) > MAX_IDENTITY_BYTES:
                raise IdentityImportError("Identity asset exceeds size limits")
            identity[filename] = data
    validate_identity(identity["certificate.p7b"], identity["identity.pk8"])
    return identity


def write_identity(identity, destination):
    destination = destination_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    created = []
    try:
        for filename in ASSETS:
            path = destination / filename
            # Create each file with owner-only permissions, independent of umask.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(identity[filename])
    except BaseException:
        for path in created:
            path.unlink()
        destination.rmdir()
        raise
    return destination


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--download", action="store_true", help="download the pinned preview APK")
    source.add_argument("--apk", type=Path, help="read an existing DiPlay v0.2.7 APK")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home() / "Library/Application Support/accessory-location/identity",
        help="new directory outside the checkout (existing directories are never overwritten)",
    )
    args = parser.parse_args(argv)
    try:
        destination = destination_path(args.output_dir)
        if args.download:
            with tempfile.TemporaryFile() as stream:
                download_apk(stream)
                identity = read_identity(stream)
        else:
            with args.apk.open("rb") as stream:
                identity = read_identity(stream)
        destination = write_identity(identity, destination)
    except (IdentityImportError, ProviderError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1
    except (OSError, urllib.error.URLError, zipfile.BadZipFile, RuntimeError):
        print("Import failed: could not download, read, or save the identity", file=sys.stderr)
        return 1
    print("Imported DiPlay v0.2.7's shared experimental accessory identity.")
    print(f"Provenance and distribution notes: {NOTICE_URL}")
    print("Local validation passed; device acceptance is not guaranteed.")
    print("Set these variables in the shell that will run the client:")
    for variable, filename in (
        ("ACCESSORY_MFI_CERT_FILE", "certificate.p7b"),
        ("ACCESSORY_MFI_KEY_FILE", "identity.pk8"),
    ):
        print(f"export {variable}={shlex.quote(str(destination / filename))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
