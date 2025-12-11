
# C3 = Compact Crypto Certs

Compact Crypto Certs (C3) is a Python mini-PKI library and command-line tool for creating, signing, and verifying cryptographic certificates with full chain
  functionality. 

(Note: a libsodium DLL/so/dylib is needed for the private key password encryption)

## Installation

```bash
pip install c3sign
````

# Python API examples

## Make Root Certificate (self-signed)

```python
import c3
c3m = c3.SignVerify()

root = c3m.make_csr(
    name="myroot",
    expiry="2030-01-01",
    cert_type="rootcert",      # optional metadata
    key_type="nacl"            # "nacl" (default), "prime256v1", or "secp256k1"
)

# Must set private key handling before saving
root.private_key_encrypt("mypassword")   # password-protected
# OR
root.private_key_set_nopassword()        # unencrypted (for testing)

c3m.sign(root, root)  # self-sign
```

## Intermediate Certificate

```python
# Load the signing cert
signer = c3m.load(filename="myroot.b64.txt")
signer.private_key_decrypt("mypassword")

# Create and sign intermediate
inter = c3m.make_csr(name="intermediate", expiry="2028-01-01")
inter.private_key_encrypt("interpass")
c3m.sign(inter, signer)

# link_by_name=True stores only the signer's ID 
#                   (smaller output, signer needs to be in verifiers trust store already)
# link_by_name=False appends signer's full chain (self-contained)
c3m.sign(inter, signer, link_by_name=True)
```

## Signing Payloads
Sign arbitrary binary data (licenses, configs, manifests):

```python
# Load signing cert
signer = c3m.load(filename="intermediate.b64.txt")
signer.private_key_decrypt("interpass")

# Create and sign payload
payload_bytes = b'{"user": "alice", "tier": "pro"}'
pce = c3m.make_payload(payload_bytes)
c3m.sign(pce, signer)

# Export signed payload
signed_text = pce.pub.as_text()
# or
pce.pub.write_text_file("license")  # writes license.public.b64.txt
```

## Verification

```python
c3m = SignVerify()

# Load trusted root(s) into trust store
c3m.load_trusted_cert(filename="myroot.b64.txt")

# Load and verify
ce = c3m.load(filename="license.public.b64.txt")

try:
    c3m.verify(ce)
    print("Valid!")
    print("Chain:", ce.vnames())   # e.g. "/myroot/intermediate"
    print("Payload:", ce.payload)
except VerifyError as e:
    print("Invalid:", e)
```

## Input (loading/reading) 

Three input methods (mutually exclusive):
```python
# From file (auto-detects text vs binary by extension)
ce = c3m.load(filename="cert.b64.txt")
ce = c3m.load(filename="cert.*")  # loads split .public. and .PRIVATE. files

# From text string
ce = c3m.load(text=certificate_text)

# From binary bytes
ce = c3m.load(block=certificate_bytes)
```


## Output 

Each CertEntry has three output accessors:
```python 
# Public only (safe to distribute)
ce.pub.as_binary()
ce.pub.as_text()
ce.pub.write_text_file("name")  # writes name.public.b64.txt

# Private only (keep secret)
ce.priv.as_binary()
ce.priv.as_text()
ce.priv.write_text_file("name")  # writes name.PRIVATE.b64.txt

# Combined (for convenience, protect like private)
ce.both.as_binary()
ce.both.as_text()
ce.both.write_text_file("name")  # writes name.b64.txt
```

## Private key password Handling
```python
# Setting passwords (when creating)
ce.private_key_encrypt("password")      # programmatic
ce.private_key_encrypt_user()           # interactive prompt
ce.private_key_set_nopassword()         # no encryption

# Using passwords (when loading)
ce.private_key_decrypt("password")      # programmatic
ce.private_key_decrypt_user()           # uses C3_PASSWORD env var, or prompts

# Environment variable
export C3_PASSWORD="mypassword"
```

## Error Handling

```python
from c3.errors import *

# Verification errors
InvalidSignatureError   # cryptographic signature mismatch
CertNotFoundError       # referenced cert not in chain or trust store
ShortChainError         # chain ends before reaching trusted cert
UntrustedChainError     # chain valid but root not in trust store

# Other errors
CertExpired             # tried to sign with expired cert
StructureError          # malformed binary/text data
IntegrityError          # CRC check failed (corruption)
TamperError             # visible fields don't match binary
SignError               # signing operation failed
OutputError             # can't export (e.g. private key not set)
NoPassword              # user cancelled password entry
```

# Complete Example: License System

### Issuer side
```python
from c3.signverify import SignVerify
import b3, json

c3m = SignVerify()

# One-time: create root cert
root = c3m.make_csr(name="acme-root", expiry="2035-01-01", cert_type="root")
root.private_key_encrypt("rootpass")
c3m.sign(root, root)
root.both.write_text_file("acme-root")

# Create license payload
LICENSE_SCHEMA = (
    (b3.UTF8,    "org",   1, True),   # True/False is 'is field Mandatory'
    (b3.UTF8,    "tier",  2, True),
    (b3.SVARINT, "seats", 3, False),
)
license_data = b3.schema_pack(LICENSE_SCHEMA, {"org": "Acme Corp", "tier": "enterprise", "seats": 50})

# (Alternative JSON payload)
license_data = json.dumps(dict(org="Acme", tier="enterprise", seats=50)).encode("utf-8")

# Sign license
signer = c3m.load(filename="acme-root.b64.txt")
signer.private_key_decrypt("rootpass")
license_ce = c3m.make_payload(license_data)
c3m.sign(license_ce, signer)

# Write license file
license_ce.pub.write_text_file("acme-license")
```

### Application (product) side 

```python
from c3.signverify import SignVerify
import b3, json

c3m = SignVerify()

# Embed root public cert in app (or load from file)
c3m.load_trusted_cert(filename="acme-root.public.b64.txt")

# Verify license at runtime
license_ce = c3m.load(filename="acme-license.public.b64.txt")
c3m.verify(license_ce)  # raises on failure

# Get the payload, and unpack to get license data
license_info = b3.schema_unpack(LICENSE_SCHEMA, license_ce.payload)
print(f"Licensed to: {license_info['org']}, tier: {license_info['tier']}")
```


## Text File Format

```
C3 text files are human-readable with base64-encoded binary blocks:

---[ Certificate: myroot ]---
[ Subject Name ]  myroot
[ Expiry Date  ]  01 January 2030
[ Cert Type    ]  rootcert

2Q7uAukZsAEJAGUJAAVpbnRlchkBBWludGVyOQIBAQkDQJqwMvo4wnp9Auz93zKr
scBlbu8mihvzRARudJyYDumHVutovutOUEaPiJuQjMpI/vOG+hxn6uhZv7/aTM+B
...

---[ PRIVATE ]---
6Q8zOQABATkBAQEJAiDVJDmswBXrxa4PIuqHpl1H38C5Q1QdssQSxPhUh1ZAIS0D
...

```


The visible fields are optional and tamper-checked against the binary data on load.



## Purpose

The library provides a lightweight certificate infrastructure for:
- Software licensing - sign licenses, verify at runtime
- Build authentication - sign manifests, verify builds
- Self-hosted mini-PKI - create certificate hierarchies without external CAs
- Embedded systems - compact formats, multiple key types

## Core Capabilities

| Feature                | Description                                             |
|------------------------|---------------------------------------------------------|
| Certificate Generation | Create CSRs with Ed25519, NIST P-256, or secp256k1 keys |
| Certificate Signing    | Self-sign or sign with issuer certificates              |
| Chain Building         | Multi-level certificate hierarchies                     |
| Payload Signing        | Sign arbitrary binary data                              |
| Chain Verification     | Validate chains against trusted roots                   |
| Dual Formats           | Human-readable text (.b64.txt) and compact binary       |
| Password Protection    | Argon2i + NaCl encryption for private keys              |

## Dependencies

- b3buf - Binary encoding/decoding
- ecdsa - ECDSA cryptographic operations
- PyNaCl - Ed25519 signatures and password encryption

## Key Source Files

| File            | Purpose                                                 |
|-----------------|---------------------------------------------------------|
| signverify.py   | Core signing/verification engine and trust store        |
| certentry.py    | Certificate data container with pub/priv output methods |
| structure.py    | Binary format parsing with CRC32 integrity checks       |
| textfiles.py    | Text format I/O with base64 encoding and visible fields |
| keypairs.py     | Cryptographic operations (keygen, sign, verify)         |
| pass_protect.py | Password encryption using PyNaCl                        |
| commandline.py  | CLI interface (make, signcert, signpayload, verify)     |

## Tests

- tests/test_all.py - Comprehensive pytest suite covering binary/text roundtrips, signing, verification, chain validation, expiry checking,
and Windows CRLF handling
- tests/fuzz_glitch.py - Fuzzing tests for binary structure robustness

## Command line tool

```
Usage:
    c3 make        --name=root1  --expiry="24 oct 2024"
    c3 signcert    --name=root1  --using=self  --link=[name|append]
    c3 make        --name=inter1 --expiry="24 oct 2024"
    c3 signcert    --name=inter1 --using=root1
    c3 signpayload --payload=payload.txt --using=inter1
    c3 verify      --name=payload.txt    --trusted=root1  --trusted=inter1
    make options   --type=rootcert --parts=split/combine --nopassword=y
    Note: if multiple --trusted specified for verify, ensure root is first.
```


