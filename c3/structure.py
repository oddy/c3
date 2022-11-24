
# C3 private & public binary block structure saving, loading & validation

import copy, binascii, time, struct, os

from c3.constants import *
from c3.errors import StructureError, IntegrityError, CertExpired


class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]
    def __deepcopy__(self, memo):
        return self.__class__({k: copy.deepcopy(v, memo) for k, v in self.items()})


# --- Private part/block save & load ---

# in:  private key bytes, and if they are unencrypted (bare) or not
# out: block bytes with header.

def make_priv_block(priv_bytes, bare=False):
    privd = AttrDict()
    privd["key_type"] = KT_ECDSA_PRIME256V1
    privd["priv_type"] = PRIVTYPE_BARE if bare else PRIVTYPE_PASS_PROTECT
    privd["priv_data"] = priv_bytes
    privd["crc32"] = binascii.crc32(privd.priv_data, 0) % (1 << 32)
    out_bytes = b3.schema_pack(PRIV_CRCWRAP_SCHEMA, privd)
    out_bytes_with_hdr = b3.encode_item_joined(PRIV_CRCWRAPPED, b3.DICT, out_bytes)
    return out_bytes_with_hdr


# in: block bytes from e.g. LoadFiles
# out: DICT with private key + metadata
# sanity & crc32 check the priv block, then shuck it and return the inner data.
# Caller must then decrypt the private key if needed.

def load_priv_block(block_bytes):
    _, index = expect_key_header([PRIV_CRCWRAPPED], b3.DICT, block_bytes, 0)
    privd = AttrDict(b3.schema_unpack(PRIV_CRCWRAP_SCHEMA, block_bytes[index:]))
    # --- Sanity checks ---
    schema_ensure_mandatory_fields(PRIV_CRCWRAP_SCHEMA, privd)
    if privd.priv_type not in KNOWN_PRIVTYPES:
        raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
    if privd.key_type not in KNOWN_KEYTYPES:
        raise StructureError("Unknown keytype %d in priv block (wanted %r)" % (privd.key_type, KNOWN_KEYTYPES))
    # --- Integrity check ---
    data_crc = binascii.crc32(privd.priv_data, 0) % (1 << 32)
    if data_crc != privd.crc32:
        raise IntegrityError("Private key block failed data integrity check (crc32)")
    return privd


# --- Public part loader ---

# In: public_part bytes
# Out: data-and-sig list cert chain structure
# Note: the inverse of this function is part of sign

def load_pub_block(public_part):
    # The public part should have an initial header that indicates whether the first das is a payload or a cert
    ppkey, index = expect_key_header([PUB_CSR, PUB_PAYLOAD, PUB_CERTCHAIN], None, public_part, 0)
    public_part = public_part[index:]               # chop off the header

    # PUB_CSR is just a cert by itself
    if ppkey == PUB_CSR:
        cert = AttrDict(b3.schema_unpack(CERT_SCHEMA, public_part))
        return ppkey, cert
    # PUB_PAYLOAD and PUB_CERTCHAIN are chains.
    # Should be a list of DAS structures, so pythonize the list

    chain = list_of_schema_unpack(DATASIG_SCHEMA, [HDR_DAS], public_part)

    # unpack the certs & sigs in chain
    for i, das in enumerate(chain):
        # dont unpack cert dif this is the first das and ppkey is PAYLOAD
        if i > 0 or ppkey == PUB_CERTCHAIN:
            das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_part))
            schema_ensure_mandatory_fields(CERT_SCHEMA, das.cert)

        das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_part))
        schema_ensure_mandatory_fields(SIG_SCHEMA, das.sig)

    return ppkey, chain


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
    if want_type is not None and want_type != data_type:   # note often we dont want type checking
        raise StructureError \
            ("Incorrect type in header - wanted %r got %s" % (want_type, repr(data_type)[:32]))
    if not has_data:
        raise StructureError("Invalid header - no has_data")
    if index == len(buf):
        raise StructureError("No data after header - buffer is empty")
    return key, index

# Used by the uniloader when someone passes a binary block directly.

def split_binary_pub_priv(block_in):
    want_keys = [PUB_CSR, PUB_PAYLOAD, PUB_CERTCHAIN, PRIV_CRCWRAPPED, DUALBLOCK]
    key, index = expect_key_header(want_keys, None, block_in, 0)
    if key == PRIV_CRCWRAPPED:
        return b"", block_in
    if key in (PUB_CSR, PUB_PAYLOAD, PUB_CERTCHAIN):
        return block_in, b""
    if key == DUALBLOCK:
        dual = b3.schema_unpack(DUALBLOCK_SCHEMA, block_in[index:])
        return dual["public"], dual["private"]

def combine_binary_pub_priv(pub_block, priv_block):
    dbx = dict(public=pub_block, private=priv_block)
    dual_bytes = b3.schema_pack(DUALBLOCK_SCHEMA, dbx)
    return b3.encode_item_joined(DUALBLOCK, b3.DICT, dual_bytes)


# --- Output/Results fetchers ---

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


# For error message readability
def ctnm(das):
    if not das:
        return ""
    if "cert" in das:
        return " (cert %r) " % das.cert.subject_name
    else:
        return " (payload) "

# --------------------------------------------------------------------------------------------------

# ULID generator that doesn't care about trying to be sub-millisecond monotonic.
def gen_ulid():
    stamp_bytes = struct.pack(">Q", int(time.time() * 1000.0))[2:]
    rand_bytes = os.urandom(10)
    return stamp_bytes + rand_bytes


# Note: a better approach here is to use micro or nanosecond timers.
# This guy has a number of good strategies:  https://github.com/RobThree/NUlid/tree/master/NUlid/Rng
# random vs monotonic is a tradeoff-spectrum, with cryptographically-secure RNG at one and and
# "just use DB autoincrement fields instead" at the other.


# ULID gen using super basic "keep trying random numbers" monotonic-increase tekneeq
# Dont want it sucking systems dry of urandom though.
# prev_rand = None
# prev_stamp = None
# def gen_ulid():
#     global prev_rand, prev_stamp
#     nn = 0
#     stamp = int(time.time() * 1000.0)
#     stamp_bytes = struct.pack(">Q", stamp)[2:]
#     rand_bytes = os.urandom(10)
#     if stamp == prev_stamp and prev_rand is not None:
#         while rand_bytes < prev_rand:
#             nn += 1
#             rand_bytes = os.urandom(10)
#     prev_rand = rand_bytes
#     prev_stamp = stamp
#     return stamp, nn, stamp_bytes + rand_bytes

# Courtesy of https://github.com/valohai/ulid2/blob/master/ulid2/__init__.py
