# Local authentication

The device requests a certificate and then sends a challenge. Successful local
key validation is not proof that the device accepts that identity; the device's
`AA05` response is the authentication result.

## Included MFi-v3 helper

Configure these environment variables before running the client:

| Variable | Required file |
| --- | --- |
| `ACCESSORY_MFI_CERT_FILE` | DER PKCS#7 certificate container |
| `ACCESSORY_MFI_KEY_FILE` | Unencrypted DER PKCS#8 P-256 private key |

`tools/local_mfi_v3_helper.py` preserves the complete certificate container and
requires exactly one non-CA P-256 leaf matching the key. It limits input sizes
and rejects malformed or ambiguous identities. These checks do not validate
Apple trust, revocation, or permission to use a credential.

The MFi-v3 challenge must be exactly 32 bytes and is already a SHA-256 digest.
The helper uses prehashed ECDSA, then converts its DER signature to the 64-byte
`r || s` form required by the peer. Hashing the challenge again or returning a
DER signature instead changes the result.

The helper reads local files only. It does not obtain an identity automatically.
Use your own matching identity or the separate, optional importer below. Keep
credentials outside the checkout. Generated test identities are short-lived,
self-signed fixtures and are removed after tests.

## Import from DiPlay

[DiPlay's provenance notes](https://github.com/shihabal3amri/DiPlay/blob/main/docs/THIRD_PARTY_NOTICES.md#experimental-authentication-data)
describe a shared accessory certificate and key recovered from public Carlinkit
firmware and included in its preview APK. The pair is already public in that APK;
it is not a personal Apple account key or a key created by pairing your phone.
Anyone with the pair can present the same accessory identity. Device acceptance
and further protocol permissions are separate questions.

DiPlay states that this material is not relicensed as project source code and
that continued acceptance and suitability for general distribution are unresolved.
This repository distributes the importer, not the identity files. Local import
keeps that third-party material separate from the GPL source; it does not make
an already shared key secret. See also [PlayPort's identity documentation](https://github.com/youcci/playport#accessory-identity-required).

After installing dependencies, choose one source:

```sh
uv run python tools/import_diplay_identity.py --download
# Or use a copy you already downloaded:
uv run python tools/import_diplay_identity.py --apk /path/to/DiPlay-0.2.7.apk
```

Both modes require the exact [DiPlay v0.2.7 release APK](https://github.com/shihabal3amri/DiPlay/releases/tag/v0.2.7)
with SHA-256:

```text
27b434462da7e78b1ff0987d129ed0a4b0a0e56beceaf8ec221d47150d4675bd
```

The importer checks the full archive before reading the two named assets,
`assets/offline-mfi/certificate.p7b` and `assets/offline-mfi/identity.pk8`.
It bounds archive and asset sizes and applies the helper's format and key-match
checks. It never installs or executes the APK, connects to a phone, or sends
coordinates. Downloaded APK data is temporary; an APK supplied with `--apk` is
left untouched.

The default destination is
`~/Library/Application Support/accessory-location/identity`. Use `--output-dir`
to choose another new directory outside the checkout. The directory has mode
`0700` and both files have mode `0600`. Existing destinations are never overwritten;
a failed write removes the partial identity. The importer prints paths and shell
commands, not key or certificate contents. Copy its two `export` commands into
the shell used to run the client.

Run import before applying `tools/local-only.sb`: `--download` needs HTTPS access,
while the sender and authentication helper need only the resulting local files.

## Helper contract

The helper is a persistent child process. Standard input and output contain one
JSON object per line. Standard output is reserved for protocol responses.

Certificate request:

```json
{"op":"certificate"}
```

Conventional MFi response:

```json
{"type":"mfi","certificate":"BASE64_PKCS7_CONTAINER"}
```

Signing request and response:

```json
{"op":"sign","challenge":"BASE64_CHALLENGE"}
{"signature":"BASE64_SIGNATURE"}
```

A provider can reject a request with `{"error":"description"}`. The bundled
helper avoids including raw inputs, credential paths, or key material in errors.

The generic client also accepts an external BAA provider returning
`{"type":"baa","certificate":"BASE64_LEAF_DER","intermediate":"BASE64_CA_DER"}`.
For BAA, `AA01` contains parameters `(0, leaf)`, `(1, byte 1)`, `(2, intermediate)`.
For conventional MFi, `AA01` contains `(0, certificate container)` only. In both
cases `AA03` carries signature bytes in parameter 0. No BAA credential-issuance
implementation is included.

## Diagnostics

Normal client events report message identifiers, parameter sizes, and state
transitions. They do not dump certificates, challenges, signatures, or private
keys. The separate Bluetooth listing command intentionally prints local paired
device names and addresses; review diagnostic output before sharing it.
