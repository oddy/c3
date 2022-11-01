
# C3 data schema for the binary blocks, tag constants, and API enums

import b3
b3.composite_schema.strict_mode = True

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


# --- Schemas and header tag values ---

# Tag/Key values
# Public-part top level
KEY_LIST_PAYLOAD = 55  # cert chain with a payload as the first entry
KEY_LIST_CERTS = 66   # cert chain with a cert as the first entry

# Public-part chain-level
KEY_DAS = 77            # "data_part and sig_part structure"

# Private-part top level
KEY_PRIV_CRCWRAPPED = 88       # "priv data with a crc32 integrity check"

# Private-part field types
PRIVTYPE_BARE = 1
PRIVTYPE_PASS_PROTECT = 2
KEYTYPE_ECDSA_256P = 1      # this may include hashers (tho may include hashtype later?)
KNOWN_PRIVTYPES = [1, 2]
KNOWN_KEYTYPES = [1]

# --- Data structures ---

CERT_SCHEMA = (
    (b3.BYTES,     "cert_id",       0, True),
    (b3.UTF8,      "subject_name",  1, True),
    (b3.UVARINT,   "key_type",      2, True),
    (b3.BYTES,     "public_key",    3, True),
    (b3.BASICDATE, "expiry_date",   4, True),
    (b3.BASICDATE, "issued_date",   5, True),
)

SIG_SCHEMA = (
    (b3.BYTES, "signature", 0,  True),
    (b3.BYTES, "signing_cert_id", 1, False),  # value can be empty.
)

DATA_AND_SIG = (
    (b3.BYTES, "data_part", 0, True),  # a cert (CERT_SCHEMA) or a payload (BYTES)
    (b3.BYTES, "sig_part", 1, True),   # a SIG_SCHEMA
    # (We could put a sig_list item here later if we want to go chain multi sig.)
)

# --- Private structure stuff ---

PRIV_CRCWRAPPED = (
    (b3.UVARINT, "priv_type", 0, True),      # protection method (e.g. bare/none, or pass_protect)
    (b3.UVARINT, "key_type",  1, True),      # actual type of private key (e.g. ecdsa 256p)
    (b3.BYTES,   "priv_data", 2, True),
    (b3.UVARINT, "crc32",     3, True),       # crc of privdata for integrity check
)


KEY2NAME = {55 : "KEY_LIST_PAYLOAD", 66 : "KEY_LIST_CERTS", 77 : "KEY_DAS", 88 : "KEY_PRIV_CRCWRAPPED"}
