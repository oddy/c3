
from __future__ import print_function

import sys, re, base64, os, traceback, random, binascii, textwrap, functools, datetime
from pprint import pprint

import ecdsa
import six

import b3
b3.composite_schema.strict_mode = True  # helpful errors when packing wrong

import getpassword
import pass_protect     # todo: packagize

# TODO TOMORROW:

# We need a diagram of how the functions flow, and the various entry points.

# Be as janky with this stuff as we want, we're not doing a public release, just making the UX not suck for us.
# this means click is out, --nopassword=yes is ok.


# * fix the new field names in the code.
# * get expiry dates and expiry handling in.
#   - rebuild the test data with the new field names.

# * integrate check_friendly's vertical validation with load_files loader.
#   - make sure binary blocks is still the gateway point.
#   - integrate it with the private part loader too (already happens via load_files i think)

# * have verify return a nice chain along with the payload if any.


# * integrate make_friendly at commandline level or save_files level
#   - its a files thing not a bytes thing so.
#   - so e.g. licensing can have its own friendly fields.

# * [DONT] integrate load_using into MakeSign
#   - tho we've been keeping them seperate so that upriv and upub can be a bytes-gateway.
#   - because MakeSign operates bytes in bytes out, which we need for e.g. acmd operation.

# * the update b3 fixmes

# * cross check priv key with pub key on using load?
#   - gonna go with requiring the public part for Using even if link=name
#   - OR skip the cross check and issue a warning.

# * Break the code up into bytes operations (c3main.C3) and files stuff (load/save & friendlies)
#   - password soliciting might be in the middle, that's ok.
#   - It would be nice to very briefly document the bytes API so we have a solid lock on the gateway boundary.

# Clean up password prompts and commandline UX

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
    # (b3.UTF8,  "name",  1, True),      # name becomes cert_id (we can still use e.g "root1" for testing.)
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
    pass             #   but don't match up with the secure fields


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
            print("'make' needs --using=<name> or '--using=self', please supply")
            return
        if args.using == "self":
            pub, priv = c3m.MakeSign(action=c3m.MAKE_SELFSIGNED, name=args.name)
        else:
            # one call to MakeSign with  using=<name> and append=true or false?
            # you have to load_using anyway, but upriv can be missing.

            # verify uses --trusted NOT --using, so we COULD integrate load_using into MakeSign.

            upub, upriv = c3m.load_using(args.using)
            if args.link == "append":
                pub, priv = c3m.MakeSign(action=c3m.MAKE_INTERMEDIATE, name=args.name,
                                         using_priv=upriv, using_pub=upub)
            elif args.link == "name":
                pub, priv = c3m.MakeSign(action=c3m.MAKE_INTERMEDIATE, name=args.name,
                                         using_priv=upriv, using_name=args.using)
            else:
                print("please supply public-using --mode=append --mode=link")
                return

        bare = "nopassword" in args  # has to be --nopassword=blah for now.
        if not bare:
            print("Setting password on private key-")
        epriv = c3m.make_encrypt_private_key_block(priv, bare=bare)
        combine = True
        if "parts" in args and args.parts == "split":
            combine = False
        c3m.write_files(args.name, pub, epriv, combine)
        return

    # python c3main.py  sign --payload=payload.txt --link=append  --using=inter1

    if cmd == "sign":
        if "payload" not in args:
            print("please supply --payload=<filename>")
            return
        payload_bytes = open(args.payload, "rb").read()

        upub, upriv = c3m.load_using(args.using)
        if args.link == "append":
            pub, priv = c3m.MakeSign(action=c3m.SIGN_PAYLOAD, name=args.payload, payload=payload_bytes,
                                     using_priv=upriv, using_pub=upub)
        elif args.link == "name":
            pub, priv = c3m.MakeSign(action=c3m.SIGN_PAYLOAD, name=args.payload, payload=payload_bytes,
                                     using_priv=upriv, using_name=args.using)
        else:
            print("please supply public-using --link=append --link=name")
            return

        print("priv from makesign is ",repr(priv))
        c3m.write_files(args.payload, pub, b"", combine=False)  # no private part, so no combine

    # python c3main.py  verify --name=payload.txt --trusted=root1

    if cmd == "verify":
        if "trusted" in args:
            print("Loading trusted cert ",args.trusted)
            tr_pub, _ = c3m.load_files(args.trusted)
            print("tr_pub is ",repr(tr_pub))
            c3m.add_trusted_certs(tr_pub)

        public_part, _ = c3m.load_files(args.name)
        ret = c3m.verify(c3m.load(public_part))
        print("\n\nverify returns", repr(ret))
        return


    UsageBail("Unknown command")



# ===================== MAIN CLASS =================================================================


class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]


# Policy: verify() only reads from self.trusted_certs, it doesnt write anything into there.
#         That's the caller's (user's) remit.

class C3(object):
    def __init__(self):
        self.trusted_certs = {}   # by name. For e.g. root certs etc.
        self.pass_protect = pass_protect.PassProtect()      # todo: c3sign only
        return

    def add_trusted_certs(self, certs_bytes, force=False):
        cert_das_list = self.load(certs_bytes)
        if not force:
            try:
                self.verify(cert_das_list)
            except UntrustedChainError:   # ignore this one failure mode because we havent installed
                pass                      # this/these certs yet!
        for das in cert_das_list:
            if "cert" not in das:         # skip payload if there is one
                continue
            self.trusted_certs[das.cert.name] = das.cert
        return

    # ============ Load-using step =====================

    def load_using(self, using_name):
        upub, uepriv = self.load_files(using_name)
        if not upub:
            raise ValueError("No public part found for --using")
        if not uepriv:
            raise ValueError("No private part found for --using")
        # todo: verify Using's pub? (would require the tool end to have a root pub cert
        #       baked in and also a trust store of its own)
        print("note: skipping verifying Using for now (requires tool root cert bake-in)")
        ueprivd = self.load_priv_block(uepriv)
        if ueprivd.privtype != PRIVTYPE_BARE:
            print("Unlocking using's private key for use-")
        upriv = self.decrypt_private_key(ueprivd)
        # todo: ensure Using's priv key and pub key match?
        return upub, upriv

    # ============ Private key decryption  =========================================================

    # in: block bytes from e.g. LoadFiles
    # out: private key + metadata dict
    # sanity & crc32 check the priv block, then shuck it and return the inner data.
    # caller goes ok if privtype is pass_protect use pass_protect to decrypt the block etc.

    def load_priv_block(self, block_bytes):
        _, index = self.expect_key_header([KEY_PRIV_CRCWRAPPED], b3.DICT, block_bytes, 0)
        privd = AttrDict(b3.schema_unpack(PRIV_CRCWRAPPED, block_bytes[index:]))
        # --- Sanity checks ---
        self.schema_assert_mandatory_fields_truthy(PRIV_CRCWRAPPED, privd)
        if privd.privtype not in KNOWN_PRIVTYPES:
            raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.privtype, KNOWN_PRIVTYPES))
        if privd.keytype not in KNOWN_KEYTYPES:
            raise StructureError("Unknown keytype %d in priv block (wanted %r)" % (privd.keytype, KNOWN_KEYTYPES))
        # --- Integrity check ---
        data_crc = binascii.crc32(privd.privdata, 0) % (1 << 32)
        if data_crc != privd.crc32:
            raise IntegrityError("Private key block failed data integrity check (crc32)")
        return privd

    # Has a "get password from user" loop
    # here is where we would demux different private protection methods also.
    # - currently we just have Bare and pass_protect

    def decrypt_private_key(self, privd):
        if privd.privtype == PRIVTYPE_BARE:
            return privd.privdata
        if privd.privtype != PRIVTYPE_PASS_PROTECT:
            raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.privtype, KNOWN_PRIVTYPES))
        if self.pass_protect.DualPasswordsNeeded(privd.privdata):  # todo: we dont support this here yet
            raise NotImplementedError("Private key wants dual passwords")

        # --- Try password from environment variables ---
        passw = getpassword.get_env_password()
        if passw:
            priv_ret = self.pass_protect.SinglePassDecrypt(privd.privdata, passw)
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
                priv_ret = self.pass_protect.SinglePassDecrypt(privd.privdata, passw)
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
        privd["keytype"] = KEYTYPE_ECDSA_256P
        privd["privtype"] = PRIVTYPE_BARE if bare else PRIVTYPE_PASS_PROTECT
        privd["privdata"] = priv_bytes
        privd["crc32"] = binascii.crc32(privd.privdata, 0) % (1 << 32)
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
        das_list = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)

        # unpack the certs & sigs in das_list
        for i, das in enumerate(das_list):
            # dont unpack cert if this is the first das and ppkey is PAYLOAD
            if i > 0 or ppkey == KEY_LIST_CERTS:
                das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_bytes))
                self.schema_assert_mandatory_fields_truthy(CERT_SCHEMA, das.cert)

            das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_bytes))
            self.schema_assert_mandatory_fields_truthy(SIG_SCHEMA, das.sig)

        return das_list

    def ctnm(self, das):
        if not das:
            return ""
        if "cert" in das:
            return " (cert %r) " % das.cert.name
        else:
            return " (payload) "

    # Apart from actual signature fails, there are 3 other ways for this to fail:
    # 1) unnamed issuer cert and no next cert in line aka "fell off the end" (ShortChainError)
    # 2) Named cert not found - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verifies OK but isn't in the trust store. (Untrusted Chain)

    # In: Data-And-Sigs items list
    # Out: payload bytes or an Exception

    def verify(self, das_list):
        certs_by_name = {das.cert.name : das.cert for das in das_list if "cert" in das}
        found_in_trusted = False         # whether we have established a link to the trusted_certs

        for i, das in enumerate(das_list):
            issuer_name = das.sig.issuer_name
            # --- Find the 'next cert' ie the one which verifies our signature ---
            if not issuer_name:
                # --- no name means "next cert in the chain" ---
                if i + 1 >= len(das_list):      # have we fallen off the end?
                    raise ShortChainError(self.ctnm(das)+"Next issuer cert is missing")
                next_cert = das_list[i + 1].cert
            else:
                # --- got a name, look in trusted for it, then in ourself (self-signed) ---
                if issuer_name in self.trusted_certs:
                    next_cert = self.trusted_certs[issuer_name]
                    found_in_trusted = True
                elif issuer_name in certs_by_name:
                    next_cert = certs_by_name[issuer_name]
                else:
                    raise CertNotFoundError(self.ctnm(das)+"wanted cert %r not found" % issuer_name)

            # --- Actually verify the signature ---
            try:
                VK = ecdsa.VerifyingKey.from_string(next_cert.public_key, ecdsa.NIST256p)
                VK.verify(das.sig.sig_val, das.data_bytes)  # returns True or raises exception
            except Exception as e:       # wrap theirs with our own error class
                raise InvalidSignatureError(self.ctnm(das)+"Signature failed to verify")
            # --- Now do next das in line ---

        # Chain verifies completed without problems. Make sure we got to a trust store cert.
        # If there is a payload, return it otherwise return True. (So bool-ness works.)
        # Even tho all errors are exceptions.
        if found_in_trusted:
            # print("SUCCESS")
            first_das = das_list[0]
            if "cert" not in first_das:
                # print(" - Returning payload")
                return first_das.data_bytes
            return True
        raise UntrustedChainError("Chain does not link to trusted certs")




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

            das_bytes = b3.item.decode_value(data_type, has_data, is_null, data_len, buf, index)  # fixme: should be b3.decode_value

            if len(das_bytes) == 0:
                raise StructureError("List item data is missing")

            # Now unpack the actual dict too
            dx = b3.schema_unpack(schema, das_bytes)
            self.schema_assert_mandatory_fields_truthy(schema, dx)
            out.append(AttrDict(dx))
            index += data_len
        return out


    def schema_assert_mandatory_fields_truthy(self, schema, dx):
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
            key, data_type, has_data, is_null, data_len, index = b3.item.decode_header(buf, index)  #fixme: should be b3.decode_header
        except (IndexError, UnicodeDecodeError):
            raise StructureError("Header structure is invalid")  # from None
            # raise .. from None disables py3's chaining (cleaner unhandled prints) but isnt legal py2
        if key not in want_keys:
            raise StructureError("Incorrect key in header - wanted %r got %r" % (want_keys, key))
        if data_type != want_type:
            raise StructureError("Incorrect type in header - wanted %r got %r" % (want_type, data_type))
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


    def write_files(self, name, public_part, private_part=b"", combine=True, desc=""):
        pub_desc = desc if desc else (name + " - Payload & Public Certs")
        priv_desc = (desc or name) + " - PRIVATE Key"
        pub_str = self.asc_header(pub_desc) + "\n" + base64.encodebytes(public_part).decode()
        priv_str = self.asc_header(priv_desc) + "\n" + base64.encodebytes(private_part).decode()

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
        pub_block = b""
        priv_block = b""
        header_rex = r"^-+\[ (.*?) \]-+$"

        combine_name = name + ".b64.txt"
        if os.path.isfile(combine_name):
            print("Loading combined file ", combine_name)
            both_strs = open(combine_name,"r").read()

            # regex cap the header lines

            hdrs = list(re.finditer(header_rex, both_strs, re.MULTILINE))
            if len(hdrs) != 2:
                print(" Error: number of headers in combined file is not 2")

            # Structure: first header, first data, second header, second data, end of file
            # data offsets are end-of-first-header : start-of-second-header,
            block0_b64 = both_strs[hdrs[0].end() : hdrs[1].start()]
            block1_b64 = both_strs[hdrs[1].end():]

            # There will be extraneous \n's but thankfully b64decode ignores them.
            block0 = base64.b64decode(block0_b64)
            block1 = base64.b64decode(block1_b64)

            # normally the second block is the private block, but if a user has shuffled things around
            # we cater for that by checking which block has 'PRIVATE' in its header description
            if "PRIVATE" in hdrs[0].group(1):       # Private block comes first (not the normal case)
                pub_block, priv_block = block1, block0
            else:   # Otherwise assume the public block comes first.
                print("normal")
                pub_block, priv_block = block0, block1

        # Enable more-specific files to override the combined file, if both exist

        pub_only_name = name + ".public.b64.txt"
        if os.path.isfile(pub_only_name):
            print("Loading public file ", pub_only_name)
            pub_str = open(pub_only_name, "r").read()
            hdrs = list(re.finditer(header_rex, pub_str, re.MULTILINE))
            if len(hdrs) != 1:
                print(" Error: too many headers in public file")
            pub_block_b64 = pub_str[hdrs[0].end():]
            pub_block = base64.b64decode(pub_block_b64)

        priv_only_name = name + ".PRIVATE.b64.txt"
        if os.path.isfile(priv_only_name):
            print("Loading private file ", priv_only_name)
            priv_str = open(priv_only_name, "r").read()
            hdrs = list(re.finditer(header_rex, priv_str, re.MULTILINE))
            if len(hdrs) != 1:
                print(" Error: too many headers in private file")
            priv_block_b64 = priv_str[hdrs[0].end():]
            priv_block = base64.b64decode(priv_block_b64)

        return pub_block, priv_block

    # ============================== Friendly Fields ===============================================

    # In: public_part bytes, schema for first dict, field names to output in friendly format
    # Out: field names & values as text lines
    # Note: this doesn't exception, it best-efforts with print warnings b/c intended commandline use.

    def make_friendly_fields(self, public_part, schema, friendly_field_names):
        # --- get to that first dict ---
        # Assume standard pub_bytes structure (das_list with header)
        try:
            ppkey, index = self.expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, public_part, 0)
            public_part = public_part[index:]
            das0 = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)[0]
            dx0 = AttrDict(b3.schema_unpack(schema, das0.data_bytes))
        except Exception as e:
            print("Skipping making friendly fields - error parsing cert/payload:\n   "+str(e))
            return ""
        found_something = False

        # --- Cross-check whether wanted fields exist (and map names to types) ---
        # This is because we're doing this with payloads as well as certs
        # The rest of the C3 system is fully payload-agnostic but we aren't.
        types_by_name = {}
        for typ, name in [i[:2] for i in schema]:
            if name in dx0 and name in friendly_field_names:
                types_by_name[name] = typ
        if not types_by_name:
            print("Skipping making friendly fields - no applicable fields found")
            return ""

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
                print("  !!! Visible field '%s' cannot be text-converted (type %s), skipping" % (name, b3.b3_type_name(typ)))
                continue
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
    # In: text with friendly-fields lines, followed by the base64 of the public part.
    # Out: exceptions or True.
    # We're pretty strict compared to make, any deviations at all will raise an exception.
    # This includes spurious fields, etc.

    # We expect there to be an empty line (or end of file) after the base64 block, and NOT more stuff.
    # More stuff immediately after the base64 block is an error.

    def check_friendly_fields(self, text_public_part, schema):
        types_by_name = {i[1]: i[0] for i in schema}
        # --- Ensure vertical structure is legit ---
        # 1 or no header line (-), immediately followed by 0 or more FF lines ([),
        # immediately followd by base64 then only whitespace or eof.
        lines = text_public_part.splitlines()
        c0s = ''.join([line[0] if line else ' ' for line in lines])+' '
        X = re.match(r"^ *(-?)(\[*)([a-z-A-Z0-9/=+]+) ", c0s)
        if not X:
            raise StructureError("Public part text structure is invalid")
        ff_lines = lines[X.start(2) : X.end(2)]    # extract FF lines
        b64_lines = lines[X.start(3) : X.end(3)]   # extract base64 lines
        b64_block = ''.join(b64_lines)
        public_part = base64.b64decode(b64_block)

        # --- get to that first dict in the secure block ---
        # Assume standard pub_bytes structure (das_list with header)
        # Let these just exception out.
        ppkey, index = self.expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_CERTS], b3.LIST, public_part, 0)
        public_part = public_part[index:]
        das0 = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)[0]
        dx0 = AttrDict(b3.schema_unpack(schema, das0.data_bytes))

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
            elif typ == b3.SCHED:
                val = "%s, %s" % (val.strftime("%-I:%M%p").lower(), val.strftime("%-d %B %Y"))
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
        return True  # success



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


    # Make/Sign actions:
    MAKE_SELFSIGNED = 1
    MAKE_INTERMEDIATE = 2
    SIGN_PAYLOAD = 3

    # name = name to give selfsigned cert, name to give inter cert.  (payload doesnt get a name)
    # payload  = the payload bytes, if signing a payload
    # using_priv, using_pub/using_name = the parts of the Using keypair, if not making selfsigned
    # Note: incoming using_priv comes in bare, caller must decrypt.
    #       return var new_key_priv goes out bare, caller must encrypt.

    def MakeSign(self, action, name="", payload=b"", using_priv=b"", using_pub=b"", using_name=""):
        # todo: change using_name to bytes. Also change name to bytes.
        # if using Using, sanity-check using - enforce exclusive either-or
        if action in (self.MAKE_INTERMEDIATE, self.SIGN_PAYLOAD):
            if not using_name and not using_pub:
                raise ValueError("both using_name and using_pub are empty, please select one")
            if using_name and using_pub:
                raise ValueError("both using_name and using_pub have values, please select one")

        new_key_priv = None

        # --- Key gen if applicable ---
        if action in (self.MAKE_SELFSIGNED, self.MAKE_INTERMEDIATE):
            # make keys
            new_key_priv, new_key_pub = self.GenKeysECDSANist256p()

            # make pub cert for pub key
            expooo = datetime.date.today()
            new_pub_cert = AttrDict(name=name, public_key=new_key_pub, expiry=expooo)  # fixme: expiry
            new_pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, new_pub_cert)
            payload_bytes = new_pub_cert_bytes
        # --- Load payload if not key-genning ---
        else:
            payload_bytes = payload

        # --- Make a selfsign if applicable ---
        if action == self.MAKE_SELFSIGNED:
            # self-sign it, make sig
            SK = ecdsa.SigningKey.from_string(new_key_priv, ecdsa.NIST256p)
            sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name=name)  # note byname
            sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Sign the thing (cert or payload) using Using, if not selfsign ----
        else:
            SK = ecdsa.SigningKey.from_string(using_priv, ecdsa.NIST256p)
            sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name=using_name)
            # note  ^^^ issuer_name can be blank, in which case using_pub should have bytes to append
            sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Make data-and-sig structure ---
        das = AttrDict(data_bytes=payload_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # --- prepend header for das itself so straight concatenation makes a list-of-das ---
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # --- Append Using's public_part (the chain) if applicable ---
        if using_pub and action != self.MAKE_SELFSIGNED:
            # we need to:
            # 1) strip using_public_part's public_part header,
            # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)
            # (we should test this)
            _, index = self.expect_key_header([KEY_LIST_CERTS], b3.LIST, using_pub, 0)
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



if __name__ == "__main__":
    CommandlineMain()



