
from __future__ import print_function

import sys, re, base64, os, traceback, random, binascii, textwrap, functools, datetime, copy

from pprint import pprint

import ecdsa
import six

import b3
b3.composite_schema.strict_mode = True  # helpful errors when packing wrong

import getpassword
import pass_protect


# TODO TOMORROW:


# Be as janky with this stuff as we want, we're not doing a public release, just making the UX not suck too bad for us.
# this means click is out, --nopassword=yes is ok.

# Policy: For simplicity for now, the subject names and cert_ids are the same. Later there should be ULIDs.

# [NOT DOING] DNF Flags
# [DONE] * fix the new field names in the code.
# [DONE]  - rebuild the test data with the new field names.
# [DONE] * get expiry dates and expiry handling in.
# [DONE] * have verify return a nice chain along with the payload if any.
# [DONE] * the update b3 fixmes
# [DONE] * cross check priv key with pub key on using load


# * integrate check_friendly's vertical validation with load_files loader.
#   - make sure binary blocks is still the gateway point.
#   - integrate it with the private part loader too (already happens via load_files i think)


# * integrate make_friendly at commandline level or save_files level
#   - its a files thing not a bytes thing so.
#   - so e.g. licensing can have its own friendly fields.   [DO THIS DURING LICENSING]


# * Break the code up into bytes operations (c3main.C3) and files stuff (load/save & friendlies)
#   - password soliciting might be in the middle, that's ok.
#   - It would be nice to very briefly document the bytes API so we have a solid lock on the gateway boundary.

# Clean up password prompts and commandline UX

# * improve expiry date parsing

# * fix up commandline handling - do this in conjunction with the Licensing use case.
#   - this is about the API functions too.
#   - which we need the Licensing use case for anyway.


# -------------------------------
# release as beta.
# dont distribute verify seperately, and dont distribute a libsodium dll yet.



# --- Public structure stuff ---

# Tag/Key values
# Public-part top level
KEY_LIST_PAYLOAD = 55  # cert chain with a payload as the first entry
KEY_LIST_CERTS = 66   # cert chain with a cert as the first entry
# Public-part chain-level
KEY_DAS = 77
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
    (b3.UVARINT, "crc32",    3, True),       # crc of privdata for integrity check
)


KEY2NAME = {55 : "KEY_LIST_PAYLOAD", 66 : "KEY_LIST_CERTS", 77 : "KEY_DAS", 88 : "KEY_PRIV_CRCWRAPPED"}

# --- Errors ---
class C3Error(ValueError):
    pass
class StructureError(C3Error):  # something wrong with the data/binary structure; misparse, corrupt
    pass
class IntegrityError(StructureError):  # the crc32 in the privkey block doesn't match block contents
    pass
class VerifyError(C3Error):     # parent error for failures in the verification process
    pass
class InvalidSignatureError(VerifyError):   # cryptographic signature failed verification
    pass
class CertNotFoundError(VerifyError):   # chain points to a cert name we dont have in Trusted
    pass
class ShortChainError(VerifyError):  # the next cert for verifying is missing off the end
    pass
class UntrustedChainError(VerifyError):  # the chain ends with a self-sign we dont have in Trusted
    pass
class TamperError(VerifyError):     # Friendly Fields are present in the textual file,
    pass                             #   but don't match up with the secure fields
class SignError(C3Error):
    pass
class CertExpired(SignError):       # can't sign, --using's cert has expired.
    pass



# ============ Command line ========================================================================



def UsageBail(msg=""):
    help_txt = """
    %s
    Usage:    
    TBD 

    """ % (msg+"\n",)
    print(help_txt)
    sys.exit(1)


def ArgvArgs():
    args = AttrDict()
    for arg in sys.argv:
        z = re.match(r"^--(\w+)=(.+)$", arg)
        if z:
            k, v = z.groups()
            args[k] = v
    return args


#               |     no payload             payload
#  -------------+-------------------------------------------------
#  using cert   |     make chain signer      sign payload
#               |
#  using self   |     make self signer       ERROR invalid state

def ParseExpiryDate(exp_str):
    exp_d = datetime.datetime.strptime(exp_str, "%Y-%m-%d").date()
    # Put some intelligent regex matches here so we can decode a few of the most common date formats
    # yes we need this.
    return exp_d

def CommandlineMain():
    if len(sys.argv) < 2:
        UsageBail()
    cmd = sys.argv[1].lower()
    args = ArgvArgs()

    c3m = C3()

    # python c3main.py  make --name=root1 --using=self  --parts=split
    # python c3main.py  make --name=inter1 --using=root1 --link=name --parts=combine

    if cmd == "make":
        if "using" not in args:
            print("'make' needs --using=<name> or --using=self, please supply")
            return

        expiry = ParseExpiryDate(args.expiry)
        if args.using == "self":
            pub, priv = c3m.MakeSign(action=c3m.MAKE_SELFSIGNED, name=args.name, expiry=expiry)
        else:
            if "link" not in args:
                print("'make' needs --link=append or --link=name, please supply")
                return

            upub, uepriv = c3m.load_files(args.using)         # uses files
            upriv = c3m.decrypt_private_key(c3m.load_priv_block(uepriv))  # (might) ask user for password
            link = {"append" : c3m.LINK_APPEND, "name" : c3m.LINK_NAME}[args.link]

            pub, priv = c3m.MakeSign(action=c3m.MAKE_INTERMEDIATE, name=args.name, expiry=expiry,
                                     using_priv=upriv, using_pub=upub, using_name=args.using, link=link)

        bare = "nopassword" in args  # has to be --nopassword=blah for now.
        if not bare:
            print("Setting password on private key-")
        epriv = c3m.make_encrypt_private_key_block(priv, bare=bare)
        combine = True
        if "parts" in args and args.parts == "split":
            combine = False

        pub_ff_names = ["subject_name", "expiry_date", "issued_date"]
        pub_ffields = c3m.make_friendly_fields(pub, CERT_SCHEMA, pub_ff_names)
        c3m.write_files(args.name, pub, epriv, combine, pub_ff_lines=pub_ffields)
        return

    # python c3main.py  sign --payload=payload.txt --link=append  --using=inter1

    if cmd == "sign":
        if "payload" not in args:
            print("please supply --payload=<filename>")
            return
        payload_bytes = open(args.payload, "rb").read()

        upub, uepriv = c3m.load_files(args.using)  # uses files
        upriv = c3m.decrypt_private_key(c3m.load_priv_block(uepriv))  # (might) ask user for password
        link = {"append": c3m.LINK_APPEND, "name": c3m.LINK_NAME}[args.link]

        pub, priv = c3m.MakeSign(action=c3m.SIGN_PAYLOAD, name=args.name, payload=payload_bytes,
                                 using_priv=upriv, using_pub=upub, link=link)

        # pub_ff_names = ["whatever", "app_specific", "fields_app_schema_has"]
        # pub_ffields = c3m.make_friendly_fields(pub, APP_SCHEMA, pub_ff_names)
        c3m.write_files(args.payload, pub, b"", combine=False)   #, pub_ff_lines=pub_ffields))
        # Note: ^^ no private part, so no combine.         ^^^ how to friendly-fields for app
        return

    # python c3main.py  verify --name=payload.txt --trusted=root1

    if cmd == "verify":
        if "trusted" in args:
            print("Loading trusted cert ",args.trusted)
            tr_pub, _ = c3m.load_files(args.trusted)
            print("tr_pub is ",repr(tr_pub))
            c3m.add_trusted_certs(tr_pub)
        else:
            print("Please specify a trusted cert with --trusted=")
            return

        public_part, _ = c3m.load_files(args.name)
        ret = c3m.verify(c3m.load(public_part))
        print("\n\nverify returns", repr(ret))
        return

    UsageBail("Unknown command")


# Delivering a cut-down Chain out of verify:
# chain is list of:
#   data_part,  ->  cert (or payload)   ->  cert fields
#   sig_part,   ->  sig                 ->  signature & signing_cert_id



# ===================== MAIN CLASS =================================================================


class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]
    def __deepcopy__(self, memo):
        return self.__class__(
            {k: copy.deepcopy(v, memo) for k, v in self.items()}
            )


# Policy: verify() only reads from self.trusted_certs, it doesnt write anything into there.
#         That's the caller's (user's) remit.

class C3(object):

    # Make/Sign actions:
    MAKE_SELFSIGNED = 1
    MAKE_INTERMEDIATE = 2
    SIGN_PAYLOAD = 3

    LINK_APPEND = 1
    LINK_NAME = 2

    def __init__(self):
        self.trusted_certs = {}   # by name. For e.g. root certs etc.
        self.pass_protect = pass_protect.PassProtect()      # todo: c3sign only
        return

    def add_trusted_certs(self, certs_bytes, force=False):
        cert_chain = self.load(certs_bytes)
        if not force:
            try:
                self.verify(cert_chain)
            except UntrustedChainError:   # ignore this one failure mode because we havent installed
                pass                      # this/these certs yet!
        for das in cert_chain:
            if "cert" not in das:         # skip payload if there is one
                continue
            self.trusted_certs[das.cert.cert_id] = das.cert
        return


    # ============ Private key decryption  =========================================================

    # in: block bytes from e.g. LoadFiles
    # out: private key + metadata dict
    # sanity & crc32 check the priv block, then shuck it and return the inner data.
    # caller goes ok if privtype is pass_protect use pass_protect to decrypt the block etc.

    def load_priv_block(self, block_bytes):
        _, index = self.expect_key_header([KEY_PRIV_CRCWRAPPED], b3.DICT, block_bytes, 0)
        privd = AttrDict(b3.schema_unpack(PRIV_CRCWRAPPED, block_bytes[index:]))
        # --- Sanity checks ---
        self.schema_ensure_mandatory_fields(PRIV_CRCWRAPPED, privd)
        if privd.priv_type not in KNOWN_PRIVTYPES:
            raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
        if privd.key_type not in KNOWN_KEYTYPES:
            raise StructureError("Unknown keytype %d in priv block (wanted %r)" % (privd.key_type, KNOWN_KEYTYPES))
        # --- Integrity check ---
        data_crc = binascii.crc32(privd.priv_data, 0) % (1 << 32)
        if data_crc != privd.crc32:
            raise IntegrityError("Private key block failed data integrity check (crc32)")
        return privd

    # Has a "get password from user" loop
    # here is where we would demux different private protection methods also.
    # - currently we just have Bare and pass_protect

    def decrypt_private_key(self, privd):
        if privd.priv_type == PRIVTYPE_BARE:
            return privd.priv_data
        if privd.priv_type != PRIVTYPE_PASS_PROTECT:
            raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
        if self.pass_protect.DualPasswordsNeeded(privd.priv_data):  # todo: we dont support this here yet
            raise NotImplementedError("Private key wants dual passwords")

        # --- Try password from environment variables ---
        passw = getpassword.get_env_password()
        if passw:
            priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            # Note exceptions are propagated right out here, its an exit if this decrypt fails.
            return priv_ret

        # --- Try password from user ---
        prompt = "Password to unlock private key: "
        priv_ret = b""
        while not priv_ret:
            passw = getpassword.get_enter_password(prompt)
            if not passw:
                raise ValueError("No password supplied, exiting")

            try:
                priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            except Exception as e:
                print("Failed decrypting private key: ", str(e))
                continue        # let user try again
        return priv_ret

    # ============ Private key encryption  =========================================================

    # given private key bytes
    # encrypt em, getting a password from the user, if that is wanted.

    def make_encrypt_private_key_block(self, bare_priv_bytes, bare=False):
        if bare:                    # no encryption needed
            priv_bytes = bare_priv_bytes
        else:
            prompt1 = "Private  key encryption password: "
            prompt2 = "Re-enter key encryption password: "
            passw = getpassword.get_double_enter_setting_password(prompt1, prompt2)
            if not passw:
                print("not passw for some reason")
                return b""
            priv_bytes = self.pass_protect.SinglePassEncrypt(bare_priv_bytes, passw)

        privd = AttrDict()
        privd["key_type"] = KEYTYPE_ECDSA_256P
        privd["priv_type"] = PRIVTYPE_BARE if bare else PRIVTYPE_PASS_PROTECT
        privd["priv_data"] = priv_bytes
        privd["crc32"] = binascii.crc32(privd.priv_data, 0) % (1 << 32)
        out_bytes = b3.schema_pack(PRIV_CRCWRAPPED, privd)
        out_bytes_with_hdr = b3.encode_item_joined(KEY_PRIV_CRCWRAPPED, b3.DICT, out_bytes)
        return out_bytes_with_hdr



    # ============ Load and Verify =================================================================

    # load() = public_part bytes -> list of Data-And-Sigs items.

    def load(self, public_part):
        # The public part should have an initial header that indicates whether the first das is a payload or a cert
        ppkey, index = self.expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, public_part, 0)
        public_part = public_part[index:]               # chop off the header

        # Should be a list of DAS structures, so pythonize the list
        chain = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)

        # unpack the certs & sigs in chain
        for i, das in enumerate(chain):
            # dont unpack cert if this is the first das and ppkey is PAYLOAD
            if i > 0 or ppkey == KEY_LIST_CERTS:
                das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_part))
                self.schema_ensure_mandatory_fields(CERT_SCHEMA, das.cert)

            das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_part))
            self.schema_ensure_mandatory_fields(SIG_SCHEMA, das.sig)

        return chain

    def ctnm(self, das):
        if not das:
            return ""
        if "cert" in das:
            return " (cert %r) " % das.cert.cert_id
        else:
            return " (payload) "

    # Apart from actual signature fails, there are 3 other ways for this to fail:
    # 1) unnamed issuer cert and no next cert in line aka "fell off the end" (ShortChainError)
    # 2) Named cert not found - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verifies OK but isn't in the trust store. (Untrusted Chain)

    # In: Data-And-Sigs items list
    # Out: payload bytes or an Exception

    def verify(self, chain):
        certs_by_id = {das.cert.cert_id : das.cert for das in chain if "cert" in das}
        found_in_trusted = False         # whether we have established a link to the trusted_certs

        for i, das in enumerate(chain):
            signing_cert_id = das.sig.signing_cert_id
            # --- Find the 'next cert' ie the one which verifies our signature ---
            if not signing_cert_id:
                # --- no signing-id means "next cert in the chain" ---
                if i + 1 >= len(chain):      # have we fallen off the end?
                    raise ShortChainError(self.ctnm(das)+"Next issuer cert is missing")
                next_cert = chain[i + 1].cert
            else:
                # --- got a name, look in trusted for it, then in ourself (self-signed) ---
                if signing_cert_id in self.trusted_certs:
                    next_cert = self.trusted_certs[signing_cert_id]
                    found_in_trusted = True
                elif signing_cert_id in certs_by_id:
                    next_cert = certs_by_id[signing_cert_id]
                else:
                    raise CertNotFoundError(self.ctnm(das)+"wanted cert %r not found" % signing_cert_id)

            # --- Actually verify the signature ---
            try:
                VK = ecdsa.VerifyingKey.from_string(next_cert.public_key, ecdsa.NIST256p)
                VK.verify(das.sig.signature, das.data_part)  # returns True or raises exception
            except Exception:       # wrap theirs with our own error class
                raise InvalidSignatureError(self.ctnm(das)+"Signature failed to verify")
            # --- Now do next das in line ---

        # Chain verifies completed without problems. Make sure we got to a trust store cert.
        # If there is a payload, return it otherwise return True. (So bool-ness works.)
        # Even tho all errors are exceptions.
        if found_in_trusted:
            return True
        raise UntrustedChainError("Chain does not link to trusted certs")

    # In: chain from load()
    # Out: payload bytes

    def get_payload(self, chain):
        first_das = chain[0]
        if "cert" not in first_das:         # first data_and_sig element's data_part is a payload
            return first_das.data_part
        return b""      # first data_and_sig element's data_part is a cert

    # In: chain from load()
    # Out: trimmed-down metadata-only chain

    def get_meta(self, chain):
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

    # ============================== Internal Functions ============================================

    # Expects a list items which are the same schema object. This should eventually be part of b3.

    def list_of_schema_unpack(self, schema, want_keys, buf):
        end = len(buf)
        index = 0
        out = []
        while index < end:
            try:
                key, data_type, has_data, is_null, data_len, index = b3.item.decode_header(buf, index)
            except (IndexError, UnicodeDecodeError):
                raise StructureError("List item header structure is invalid")
            if key not in want_keys:
                raise StructureError("List item header key invalid - wanted %r got %r" % (want_keys, key))
            if data_type != b3.DICT:
                raise StructureError("List item header type invalid - wanted DICT got %r" % data_type)
            if not has_data or data_len == 0:
                raise StructureError("List item header invalid - no data")

            das_bytes = b3.decode_value(data_type, has_data, is_null, data_len, buf, index)

            if len(das_bytes) == 0:
                raise StructureError("List item data is missing")

            # Now unpack the actual dict too
            dx = b3.schema_unpack(schema, das_bytes)
            self.schema_ensure_mandatory_fields(schema, dx)
            out.append(AttrDict(dx))
            index += data_len
        return out


    def schema_ensure_mandatory_fields(self, schema, dx):
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
    def expect_key_header(self, want_keys, want_type, buf, index):
        if not buf:
            raise StructureError("No data - buffer is empty or None")
        try:
            key, data_type, has_data, is_null, data_len, index = b3.decode_header(buf, index)
        except (IndexError, UnicodeDecodeError):
            raise StructureError("Header structure is invalid")  # from None
            # raise .. from None disables py3's chaining (cleaner unhandled prints) but isnt legal py2
        if key not in want_keys:
            raise StructureError("Incorrect key in header - wanted %r got %s" % (want_keys, repr(key)[:32]))
        if data_type != want_type:
            raise StructureError("Incorrect type in header - wanted %r got %s" % (want_type, repr(data_type)[:32]))
        if not has_data:
            raise StructureError("Invalid header - no has_data")
        if index == len(buf):
            raise StructureError("No data after header - buffer is empty")
        return key, index


    # ============================== File Saving/Loading ===========================================

    # Policy: look for name.PRIVATE and name.PUBLIC (.b64.txt)
    # Policy: split trumps combined.
    # Policy: Return "" for private_part if there is none, callers can validate

    def asc_header(self, msg):
        m2 = "[ %s ]" % msg
        offs = 37 - len(m2)//2
        line = "-"*offs
        line += m2
        line += "-"*(76-len(line))
        return line


    def write_files(self, name, public_part, private_part=b"", combine=True, desc="", pub_ff_lines="", priv_ff_lines=""):
        pub_desc = desc if desc else (name + " - Payload & Public Certs")
        priv_desc = (desc or name) + " - PRIVATE Key"
        if pub_ff_lines:
            pub_ff_lines += "\n"
        pub_str = self.asc_header(pub_desc) + "\n" + pub_ff_lines + base64.encodebytes(public_part).decode()
        if priv_ff_lines:
            priv_ff_lines += "\n"
        priv_str = self.asc_header(priv_desc) + "\n" + priv_ff_lines + base64.encodebytes(private_part).decode()

        print()
        print(pub_str)
        print()
        print(priv_str)
        if combine:
            fname = name + ".b64.txt"
            with open(fname, "w") as f:
                f.write("\n"+pub_str)
                f.write("\n")
                f.write(priv_str+"\n")
            print("Wrote combined file: ",fname)
        else:
            fname = name + ".public.b64.txt"
            with open(fname, "w") as f:
                f.write("\n"+pub_str+"\n")
            print("Wrote public file:  ", fname)

            if not private_part:
                return

            fname = name + ".PRIVATE.b64.txt"
            with open(fname, "w") as f:
                f.write("\n"+priv_str+"\n")
            print("Wrote PRIVATE file: ", fname)



    def load_files(self, name):
        header_rex = r"^-+\[ (.*?) \]-+$"
        pub_text_block = ""
        priv_text_block = ""

        combine_name = name + ".b64.txt"
        if os.path.isfile(combine_name):
            print("Loading combined file ", combine_name)
            both_strs = open(combine_name, "r").read()

            # regex cap the header lines

            hdrs = list(re.finditer(header_rex, both_strs, re.MULTILINE))
            if len(hdrs) != 2:
                print(" Warning: number of headers in combined file is not 2")

            # Structure: first header, first data, second header, second data, end of file
            # data offsets are start-of-first-header : start-of-second-header,
            # because check_friendly_fields wants to see the headers too if they are there.
            block0_text = both_strs[hdrs[0].start() : hdrs[1].start()]
            block1_text = both_strs[hdrs[1].start( ):]

            # normally the second block is the private block, but if a user has shuffled things around
            # we cater for that by checking which block has 'PRIVATE' in its header description
            if "PRIVATE" in hdrs[0].group(1):       # Private block comes first (not the normal case)
                pub_text_block, priv_text_block = block1_text, block0_text
            else:   # Otherwise assume the public block comes first.
                pub_text_block, priv_text_block = block0_text, block1_text

        # Enable more-specific files to override the combined file, if both exist

        pub_only_name = name + ".public.b64.txt"
        if os.path.isfile(pub_only_name):
            print("Loading public file ", pub_only_name)
            pub_text_block = open(pub_only_name, "r").read()
            hdrs = list(re.finditer(header_rex, pub_text_block, re.MULTILINE))
            if len(hdrs) != 1:
                print(" Warning: too %s headers in public file" % ("many" if len(hdrs)>1 else "few"))

        priv_only_name = name + ".PRIVATE.b64.txt"
        if os.path.isfile(priv_only_name):
            print("Loading private file ", priv_only_name)
            priv_text_block = open(priv_only_name, "r").read()
            hdrs = list(re.finditer(header_rex, priv_text_block, re.MULTILINE))
            if len(hdrs) != 1:
                print(" Warning: too %s headers in public file" % ("many" if len(hdrs) > 1 else "few"))

        # Ensure friendly (visible) text-fields (if any) match the secure binary info.
        # This also extracts and converts the base64 secure block parts.
        pub_block = self.check_friendly_fields(pub_text_block, CERT_SCHEMA)
        priv_block = self.check_friendly_fields(priv_text_block, PRIV_CRCWRAPPED)


        return pub_block, priv_block


    # Include the headers, don't base64 decode the base64 parts of the blocks,
    # so pub_text_block and priv_text_block.


    # ============================== Friendly Fields ===============================================


    # In: block_part bytes, schema for first dict, field names to output in friendly format
    # Out: field names & values as text lines (or exceptions)

    def make_friendly_fields(self, block_part, schema, friendly_field_names):
        # --- get to that first dict ---
        # Assume standard pub_bytes structure (chain with header)
        # We can't use load() here because load() does mandatory schema checks and we
        dx0 = self.extract_first_dict(block_part, schema)

        # --- Cross-check whether wanted fields exist (and map names to types) ---
        # This is because we're doing this with payloads as well as certs
        # The rest of the C3 system is fully payload-agnostic but we aren't.
        types_by_name = {}
        for typ, name in [i[:2] for i in schema]:
            if name in dx0 and name in friendly_field_names:
                types_by_name[name] = typ
        if not types_by_name:
            raise ValueError("No wanted friendly fields found in the secure block")
            # note: should this just be a warning & continue?

        # --- Convert wanted fields to a textual representation where possible ---
        # order by the friendly_field_names parameter
        line_items = []
        for name in friendly_field_names:
            if name not in types_by_name:
                continue
            fname = name.title().replace("_"," ")
            typ = types_by_name[name]
            val = dx0[name]     # in
            fval = ""   # out
            # --- Value converters ---
            if typ in (b3.BYTES, b3.LIST, b3.DICT, 11, 12):  # cant be str-converted
                raise TypeError("Visible field '%s' cannot be text-converted (type %s), skipping" % (name, b3.b3_type_name(typ)))
            elif typ == b3.SCHED:
                fval = "%s, %s" % (val.strftime("%-I:%M%p").lower(), val.strftime("%-d %B %Y"))
            elif typ == b3.BASICDATE:
                fval = val.strftime("%-d %B %Y")
            else:
                fval = str(val)
            line_items.append((fname, fval))

        # --- Make stuff line up nicely ---
        longest_name_len = functools.reduce(max, [len(i[0]) for i in line_items], 0)
        lines = ["[ %s ]  %s" % (str.ljust(fname, longest_name_len), fval) for fname,fval in line_items]
        return '\n'.join(lines)


    # Note: unlike make_friendly_fields, we raise exceptions when something is wrong
    # In: text with header line, friendly-fields lines, followed by the base64 of the secure public or private block.
    # Out: exceptions or True.
    # We're pretty strict compared to make, any deviations at all will raise an exception.
    # This includes spurious fields, etc.

    # We expect there to be an empty line (or end of file) after the base64 block, and NOT more stuff.
    # This means EOF immediately after the base64 block is an error.

    # This does not ensure mandatory fields are present like load() does, so it can be used for
    # more things e.g. friendly_fields and check_expiry.  (and by user code for payloads).

    def extract_first_dict(self, part_block, schema):
        if schema == CERT_SCHEMA:       # public part block
            ppkey, index = self.expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, part_block, 0)
            public_part = part_block[index:]
            das0 = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)[0]
            dx0 = AttrDict(b3.schema_unpack(schema, das0.data_part))
        elif schema == PRIV_CRCWRAPPED:    # private part block
            ppkey, index = self.expect_key_header([KEY_PRIV_CRCWRAPPED,], b3.DICT, part_block, 0)
            private_part = part_block[index:]
            dx0 = AttrDict(b3.schema_unpack(schema, private_part))
        else:
            raise TypeError("Unknown schema for first-dict extract")
        return dx0


    def check_friendly_fields(self, text_part, schema):
        types_by_name = {i[1]: i[0] for i in schema}
        # --- Ensure vertical structure is legit ---
        # 1 or no header line (-), immediately followed by 0 or more FF lines ([),
        # immediately followd by base64 then a mandatory whitespace (e.g empty line).
        lines = text_part.splitlines()
        c0s = ''.join([line[0] if line else ' ' for line in lines])+' '
        X = re.match(r"^\s*(-?)(\[*)([a-zA-Z0-9/=+]+) ", c0s)
        if not X:
            raise StructureError("File text vertical structure is invalid")
        ff_lines = lines[X.start(2) : X.end(2)]    # extract FF lines
        b64_lines = lines[X.start(3) : X.end(3)]   # extract base64 lines
        b64_block = ''.join(b64_lines)
        bytes_part = base64.b64decode(b64_block)

        # --- get to that first dict in the secure block ---
        # Assume standard pub_bytes structure (chain with header)
        # Let these just exception out.
        dx0 = self.extract_first_dict(bytes_part, schema)

        # --- Cross-check each Friendy Field line ---
        for ff in ff_lines:
            # --- Extract friendly name & value ---
            fX = re.match(r"^\[ (.*) ]  (.*)$",ff)
            if not fX:
                raise TamperError("Invalid format for visible field line %r" % ff[:32])
            fname, fval = fX.groups()

            # --- convert name ---
            # spaces aren't allowed in code schema field names because AttrDict, only underscores so
            # 1:1 conversion back is easy.
            name = fname.strip().lower().replace(" ","_")
            fval = fval.strip()     # some converters are finicky about trailing spaces

            # --- Check name presence ---
            if name not in types_by_name:
                raise TamperError("Visible field '%s' is not present in the secure area" % (name,))
            typ = types_by_name[name]

            # --- convert value ---
            if typ == b3.UTF8:
                val = str(fval)              # actually the incoming text should already be utf8 anyway
            elif typ == b3.UVARINT:
                val = int(fval)
            elif typ == b3.BOOL:
                val = bool(fval.lower().strip() == "True")
            # elif typ == b3.SCHED:   # todo: this is the wrong way around
            #    val = "%s, %s" % (fval.strftime("%-I:%M%p").lower(), fval.strftime("%-d %B %Y"))
            elif typ == b3.BASICDATE:
                val = datetime.datetime.strptime(fval, "%d %B %Y").date()
            else:
                raise TamperError("Visible field '%s' cannot be type-converted" % (name,))

            # --- Compare value ---
            if name not in dx0:         # could happen if field is optional in the schema
                raise TamperError("Visible field '%s' is not present in the secure area" % (name,))
            secure_val = dx0[name]
            if secure_val != val:
                raise TamperError("Field '%s' visible value %r does not match secure value %r" % (name, val, secure_val))

        return bytes_part  # success


    # ============================== Signing =======================================================

    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state

    # The way sign combines things, we get bytes out.
    # Cannot be seperated like load and verify are, nor do we want to.


    def GenKeysECDSANist256p(self):
        curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
        priv = ecdsa.SigningKey.generate(curve=curve)
        pub = priv.get_verifying_key()
        return priv.to_string(), pub.to_string()


    # In: priv key bytes, pub chain block
    # Out: true or exception

    def check_privpub_match_ecdsanist256p(self, priv_key_bytes, using_pub_block):
        using_pub_key = self.extract_first_dict(using_pub_block, CERT_SCHEMA).public_key
        priv = ecdsa.SigningKey.from_string(priv_key_bytes, ecdsa.NIST256p)
        pub = priv.get_verifying_key()
        if pub.to_string() != using_pub_key:
            raise SignError("private key and public key do not match")
        return True


    # name = name to give selfsigned cert, name to give inter cert.  (payload doesnt get a name)
    # payload  = the payload bytes, if signing a payload
    # using_priv, using_pub/using_name = the parts of the Using keypair, if not making selfsigned
    # Note: incoming using_priv comes in bare, caller must decrypt.
    #       return var new_key_priv goes out bare, caller must encrypt.

    def MakeSign(self, action, name="", payload=b"", using_priv=b"", using_pub=b"", using_name="", expiry=None, link=LINK_APPEND):
        # using_pub must now always be present unless MAKE_SELFSIGNED
        if action != self.MAKE_SELFSIGNED:
            if not using_pub:
                raise ValueError("please supply public part of --using")
            # Make sure the signing cert hasn't expired!
            self.ensure_not_expired(using_pub)
            # Make sure the keypair really is a keypair
            self.check_privpub_match_ecdsanist256p(using_priv, using_pub)

        # sanity check expiry, needed for selfsign and intermediate
        if action in (self.MAKE_INTERMEDIATE, self.MAKE_SELFSIGNED):
            if not expiry:
                raise ValueError("creating cert: please provide expiry date")

        # Policy: for now, cert_id and subject name are the same.  Consider ULID in future.
        cert_id = name.encode("ascii")
        using_id = using_name.encode("ascii")
        new_key_priv = None

        # --- Key gen if applicable ---
        if action in (self.MAKE_SELFSIGNED, self.MAKE_INTERMEDIATE):
            # make keys
            new_key_priv, new_key_pub = self.GenKeysECDSANist256p()
            # make pub cert for pub key

            today = datetime.date.today()
            new_pub_cert = AttrDict(
                public_key=new_key_pub, subject_name=name, cert_id=cert_id, issued_date=today,
                key_type=KEYTYPE_ECDSA_256P, expiry_date=expiry
            )
            new_pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, new_pub_cert)
            payload_bytes = new_pub_cert_bytes
        # --- Load payload if not key-genning ---
        else:
            payload_bytes = payload

        # --- Make a selfsign if applicable ---
        if action == self.MAKE_SELFSIGNED:
            SK = ecdsa.SigningKey.from_string(new_key_priv, ecdsa.NIST256p)
            sig_d = AttrDict(signature=SK.sign(payload_bytes), signing_cert_id=cert_id)
        # --- Sign the thing (cert or payload) using Using, if not selfsign ----
        else:
            SK = ecdsa.SigningKey.from_string(using_priv, ecdsa.NIST256p)
            sig_d = AttrDict(signature=SK.sign(payload_bytes), signing_cert_id=using_id)
            # note  ^^^ signing_cert_id can be blank, in which case using_pub should have bytes to append

        sig_part = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Make data-and-sig structure ---
        das = AttrDict(data_part=payload_bytes, sig_part=sig_part)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # --- prepend header for das itself so straight concatenation makes a list-of-das ---
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # --- Append Using's public_part (the chain) if applicable ---
        if link == self.LINK_APPEND and action != self.MAKE_SELFSIGNED:
            # we need to:
            # 1) strip using_public_part's public_part header,
            # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)
            # (we should test this)
            _, index = self.expect_key_header([KEY_LIST_CERTS], b3.LIST, using_pub, 0)
            # 1a) ensure the signing cert hasn't expired!  (This only works with link-append mode because link-name mode has no using_pub)
            using_pub = using_pub[index:]
            # 2) concat our data + using_public_part's data
            out_public_part = das_bytes_with_hdr + using_pub
        else:
            out_public_part = das_bytes_with_hdr

        # --- Prepend a new overall public_part header & return pub & private bytes ---
        if action == self.SIGN_PAYLOAD:
            key_type = KEY_LIST_PAYLOAD
        else:
            key_type = KEY_LIST_CERTS
        out_public_with_hdr = b3.encode_item_joined(key_type, b3.LIST, out_public_part)

        return out_public_with_hdr, new_key_priv


    def ensure_not_expired(self, using_pub):
        dx0 = self.extract_first_dict(using_pub, CERT_SCHEMA)
        expiry = dx0["expiry_date"]
        if datetime.date.today() > expiry:
            raise CertExpired("cert specified by --using has expired")
        return True


if __name__ == "__main__":
    CommandlineMain()



# Making ULIDS

# Courtesy of https://github.com/valohai/ulid2/blob/master/ulid2/__init__.py
#
# import time, calendar, struct
# _last_entropy = None
# _last_timestamp = None
#
# def generate_binary_ulid(timestamp=None, monotonic=False):
#     """
#     Generate the bytes for an ULID.
#     :param timestamp: An optional timestamp override.
#                       If `None`, the current time is used.
#     :type timestamp: int|float|datetime.datetime|None
#     :param monotonic: Attempt to ensure ULIDs are monotonically increasing.
#                       Monotonic behavior is not guaranteed when used from multiple threads.
#     :type monotonic: bool
#     :return: Bytestring of length 16.
#     :rtype: bytes
#     """
#     global _last_entropy, _last_timestamp
#     if timestamp is None:
#         timestamp = time.time()
#     elif isinstance(timestamp, datetime.datetime):
#         timestamp = calendar.timegm(timestamp.utctimetuple())
#
#     ts = int(timestamp * 1000.0)
#     ts_bytes = struct.pack(b'!Q', ts)[2:]
#     entropy = os.urandom(10)
#     if monotonic and _last_timestamp == ts and _last_entropy is not None:
#         while entropy < _last_entropy:
#             entropy = os.urandom(10)
#     _last_entropy = entropy
#     _last_timestamp = ts
#     return ts_bytes + entropy
#
