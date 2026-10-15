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

Identity provisioning is external to the tool. For public background on local
accessory identities, see [PlayPort's identity documentation](https://github.com/youcci/playport#accessory-identity-required)
and [DiPlay's provenance notes](https://github.com/shihabal3amri/DiPlay/blob/main/docs/THIRD_PARTY_NOTICES.md).
The project does not download, generate, or bundle device-trusted credentials.

Keep real credentials outside the checkout. Generated test identities are
short-lived, self-signed fixtures and are removed after tests.

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
