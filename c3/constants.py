
# C3 data schema for the binary blocks, tag constants, and API enums

import b3

# --- API Actions ---

# Make/Sign actions:
MAKE_SELFSIGNED = 1
MAKE_INTERMEDIATE = 2
SIGN_PAYLOAD = 3
LINK_APPEND = 1
LINK_NAME = 2

# --- environment variables for priv key crypting ---
PASS_VAR = "C3_PASSWORD"
SHOW_VAR = "C3_SHOW_PASS"


# --- Top-level tag values ---
PUB_CSR = 10
DUALBLOCK = 11
PUB_PAYLOAD = 12      # cert chain with a payload as the first entry
BARE_PAYLOAD = 13     # literally just payload bytes but tagged with a header tag.
PUB_CERTCHAIN = 14    # cert chain with a cert as the first entry
PRIV_CRCWRAPPED = 15  # "priv data with a crc32 integrity check"

# Public-part chain-level
HDR_DAS = 0x19            # "data_part and sig_part structure"


# Private-part field types
PRIVTYPE_BARE = 1
PRIVTYPE_PASS_PROTECT = 2
KT_ECDSA_PRIME256V1 = 1
KT_ECDSA_SECP256K1 = 2      # the bitcoin one, for which fast implementations exist
KNOWN_PRIVTYPES = [1, 2]
KNOWN_KEYTYPES = [1]


# --- Public-Part data structures ---

CERT_SCHEMA = (
    (b3.BYTES,     "cert_id",       0, True),
    (b3.UTF8,      "subject_name",  1, True),
    (b3.UVARINT,   "key_type",      2, True),
    (b3.BYTES,     "public_key",    3, True),
    (b3.BASICDATE, "expiry_date",   4, True),
    (b3.BASICDATE, "issued_date",   5, True),
    (b3.UTF8,      "cert_type",     6, False),
)

SIG_SCHEMA = (
    (b3.BYTES, "signature", 0,  True),
    (b3.BYTES, "signing_cert_id", 1, False),  # value can be empty.
)

DATASIG_SCHEMA = (
    (b3.BYTES, "data_part", 0, True),  # a cert (CERT_SCHEMA) or a payload (BYTES)
    (b3.BYTES, "sig_part", 1, True),   # a SIG_SCHEMA
    # (We could put a sig_list item here later if we want to go chain multi sig.)
)


# --- Private block top level data structures ---

PRIV_CRCWRAP_SCHEMA = (
    (b3.UVARINT, "priv_type", 0, True),      # protection method (e.g. bare/none, or pass_protect)
    (b3.UVARINT, "key_type",  1, True),      # actual type of private key (e.g. ecdsa 256p)
    (b3.BYTES,   "priv_data", 2, True),
    (b3.UVARINT, "crc32",     3, True),       # crc of privdata for integrity check
)

# --- Both-parts binary data structures ---

DUALBLOCK_SCHEMA = (
    (b3.BYTES, "public", 0, True),
    (b3.BYTES, "private", 1, True),
)



KEY2NAME = {55 : "PUB_PAYLOAD", 66 : "PUB_CERTCHAIN", 77 : "HDR_DAS", 88 : "PRIV_CRCWRAPPED"}
