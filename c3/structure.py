
import copy, binascii

import b3

from constants import *
from errors import StructureError, IntegrityError


class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]
    def __deepcopy__(self, memo):
        return self.__class__({k: copy.deepcopy(v, memo) for k, v in self.items()})

# --- Public part loader ---

def load(public_part):
    # The public part should have an initial header that indicates whether the first das is a payload or a cert
    ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, public_part, 0)
    public_part = public_part[index:]               # chop off the header

    # Should be a list of DAS structures, so pythonize the list
    chain = list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)

    # unpack the certs & sigs in chain
    for i, das in enumerate(chain):
        # dont unpack cert if this is the first das and ppkey is PAYLOAD
        if i > 0 or ppkey == KEY_LIST_CERTS:
            das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_part))
            schema_ensure_mandatory_fields(CERT_SCHEMA, das.cert)

        das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_part))
        schema_ensure_mandatory_fields(SIG_SCHEMA, das.sig)

    return chain

# --- Private part loader ---

# in: block bytes from e.g. LoadFiles
# out: private key + metadata dict
# sanity & crc32 check the priv block, then shuck it and return the inner data.
# caller goes ok if privtype is pass_protect use pass_protect to decrypt the block etc.

def load_priv_block(block_bytes):
    _, index = expect_key_header([KEY_PRIV_CRCWRAPPED], b3.DICT, block_bytes, 0)
    privd = AttrDict(b3.schema_unpack(PRIV_CRCWRAPPED, block_bytes[index:]))
    # --- Sanity checks ---
    schema_ensure_mandatory_fields(PRIV_CRCWRAPPED, privd)
    if privd.priv_type not in KNOWN_PRIVTYPES:
        raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
    if privd.key_type not in KNOWN_KEYTYPES:
        raise StructureError("Unknown keytype %d in priv block (wanted %r)" % (privd.key_type, KNOWN_KEYTYPES))
    # --- Integrity check ---
    data_crc = binascii.crc32(privd.priv_data, 0) % (1 << 32)
    if data_crc != privd.crc32:
        raise IntegrityError("Private key block failed data integrity check (crc32)")
    return privd


# --- Structure helper functions ---

# Expects a list items which are the same schema object. This should eventually be part of b3.

def list_of_schema_unpack(schema, want_keys, buf):
    end = len(buf)
    index = 0
    out = []
    while index < end:
        try:
            key, data_type, has_data, is_null, data_len, index = b3.item.decode_header(buf, index)
        except (IndexError, UnicodeDecodeError):
            raise StructureError("List item header structure is invalid")
        if key not in want_keys:
            raise StructureError \
                ("List item header key invalid - wanted %r got %r" % (want_keys, key))
        if data_type != b3.DICT:
            raise StructureError("List item header type invalid - wanted DICT got %r" % data_type)
        if not has_data or data_len == 0:
            raise StructureError("List item header invalid - no data")

        das_bytes = b3.decode_value(data_type, has_data, is_null, data_len, buf, index)

        if len(das_bytes) == 0:
            raise StructureError("List item data is missing")

        # Now unpack the actual dict too
        dx = b3.schema_unpack(schema, das_bytes)
        schema_ensure_mandatory_fields(schema, dx)
        out.append(AttrDict(dx))
        index += data_len
    return out


def schema_ensure_mandatory_fields(schema, dx):
    for field_def in schema:                    # by name
        # only check if mandatory bool flag is both present AND true.
        if len(field_def) > 3 and field_def[3] is True:
            field_name = field_def[1]
            if field_name not in dx:
                raise StructureError("Required schema field '%s' is missing" % field_name)
            if not dx[field_name]:
                raise StructureError("Mandatory field '%s' is %r" % (field_name, dx[field_name]))



# Index and Unicode are the only two unhandled exception types that b3's decode_header code produces when fuzzed.
# IndexError trying to decode a bad varint for ext_type, datalen or number key.
# Unicode for when b3 thinks there's a utf8 key but the utf8 is bad.
def expect_key_header(want_keys, want_type, buf, index):
    if not buf:
        raise StructureError("No data - buffer is empty or None")
    try:
        key, data_type, has_data, is_null, data_len, index = b3.decode_header(buf, index)
    except (IndexError, UnicodeDecodeError):
        raise StructureError("Header structure is invalid")  # from None
        # raise .. from None disables py3's chaining (cleaner unhandled prints) but isnt legal py2
    if key not in want_keys:
        raise StructureError \
            ("Incorrect key in header - wanted %r got %s" % (want_keys, repr(key)[:32]))
    if data_type != want_type:
        raise StructureError \
            ("Incorrect type in header - wanted %r got %s" % (want_type, repr(data_type)[:32]))
    if not has_data:
        raise StructureError("Invalid header - no has_data")
    if index == len(buf):
        raise StructureError("No data after header - buffer is empty")
    return key, index


# This does not ensure mandatory fields are present like load() does, so it can be used for
# more things e.g. friendly_fields and check_expiry.

def extract_first_dict(part_block, schema):
    if schema == CERT_SCHEMA:       # public part block
        ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, part_block, 0)
        public_part = part_block[index:]
        das0 = list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)[0]
        dx0 = AttrDict(b3.schema_unpack(schema, das0.data_part))
    elif schema == PRIV_CRCWRAPPED:    # private part block
        ppkey, index = expect_key_header([KEY_PRIV_CRCWRAPPED,], b3.DICT, part_block, 0)
        private_part = part_block[index:]
        dx0 = AttrDict(b3.schema_unpack(schema, private_part))
    else:
        raise TypeError("Unknown schema for first-dict extract")
    return dx0


# For error message readability

def ctnm(das):
    if not das:
        return ""
    if "cert" in das:
        return " (cert %r) " % das.cert.cert_id
    else:
        return " (payload) "

# Output/Results fetchers

# In: chain from load()
# Out: payload bytes

def get_payload(chain):
    first_das = chain[0]
    if "cert" not in first_das:         # first data_and_sig element's data_part is a payload
        return first_das.data_part
    return b""      # first data_and_sig element's data_part is a cert


# Delivering a cut-down Chain for meta:
# chain is list of:
#   data_part,  ->  cert (or payload)   ->  cert fields
#   sig_part,   ->  sig                 ->  signature & signing_cert_id

# In: chain from load()
# Out: trimmed-down metadata-only chain

def get_meta(chain):
    st = 0
    first_das = chain[0]
    if "cert" not in first_das:     # skip the first data_and_sig if it's a payload one
        st = 1
    chain2 = copy.deepcopy(chain[st:])
    for i in chain2:
        del i["data_part"]
        del i["sig_part"]
        del i["cert"]["public_key"]
        del i["sig"]["signature"]
    return chain2

