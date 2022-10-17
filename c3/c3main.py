
from __future__ import print_function

import sys, re, base64, os, traceback, random, binascii
from pprint import pprint

import ecdsa
import six

import b3
b3.composite_schema.strict_mode = True  # helpful errors when packing wrong

import getpassword
import pass_protect     # todo: packagize

# TODO TOMORROW:
# integrate everything for commandline operations
# expiry dates
# do ascii fields


# Todo: distribute Verify as it's own package/module.
#       b/c passprotect depends on e.g pathlib2, sodium, etc.

# --- Public structure stuff ---

# tag/key values (mostly for sanity checking)
# level0
KEY_LIST_PAYLOAD = 55  # cert chain with a payload as the first entry
KEY_LIST_SIGNER = 66   # cert chain with a cert as the first entry
# level1
KEY_DAS = 77
# Policy: we are NOT doing multi-sig DAS now. Too hard.
# Note: in future if multi-signature support is wanted, we can add new tag/key values to indicate
#       the different data-and-[list of signatures] structure.

KEY_PRIV_CRCWRAPPED = 88       # "priv data with a crc32 integrity check"

CERT_SCHEMA = (
    (b3.UTF8,  "name",  1, True),
    (b3.BYTES, "pub_key", 2, True),
    # (b3.SCHED, "expiry", 3),
    )

SIG_SCHEMA = (
    (b3.BYTES, "sig_val", 1,  True),
    (b3.UTF8, "issuer_name", 2, False),  # value can be empty. todo: want this to be This is bytes for IDs.
)

DATA_AND_SIG = (
    (b3.BYTES, "data_bytes", 1, True),
    (b3.BYTES, "sig_bytes", 2, True),
)

# --- Private structure stuff ---

PRIV_CRCWRAPPED = (
    (b3.UVARINT, "privtype", 1, True),      # protection method (e.g. bare/none, or pass_protect)
    (b3.UVARINT, "keytype",  2, True),      # actual type of private key (e.g. ecdsa 256p)
    (b3.BYTES,   "privdata", 3, True),
    (b3.UVARINT, "crc32",    4, True),      # crc of privdata for integrity check
)

# Add more of these as we get more key types and/or more encryption mechanisms
PRIVTYPE_BARE = 1
PRIVTYPE_PASS_PROTECT = 2
KEYTYPE_ECDSA_256P = 1
KNOWN_PRIVTYPES = [1,2]
KNOWN_KEYTYPES = [1]

KEY2NAME = {55 : "KEY_LIST_PAYLOAD", 66 : "KEY_LIST_SIGNER", 77 : "KEY_DAS", 88 : "KEY_PRIV_CRCWRAPPED"}

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


# ============ Command line ========================================================================


# Caller has to write_files with combine false or true, depending.

# if payload_or_cert:
#     # signed-payload output
#     out_public_with_hdr = b3.encode_item_joined(KEY_LIST_PAYLOAD, b3.LIST, out_public_part)
#     self.write_files(name, out_public_with_hdr, b"", combine=False)  # wont write private_part if its empty
# else:
#     # signer (self or chain) output
#     out_public_with_hdr = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, out_public_part)
#     self.write_files(name, out_public_with_hdr, new_key_priv, combine=True)


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

# make --name=fred --using==self --parts=combine
# make --name=bob --using=fred --parts=split
# sign --payload=FILE --using=bob  --outfile=FILE.signed

# verify --file=FILE.signed



def CommandlineMain():
    if len(sys.argv) < 2:
        UsageBail()
    cmd = sys.argv[1].lower()
    args = ArgvArgs()

    c3m = C3()

    # c3 make --name=root1 --using=self  --parts=split
    # c3 make --name=inter1 --using=root1 --link=name --parts=combine

    if cmd == "make":
        if "using" not in args:
            print("'make' needs --using=<name> or '--using=self', please supply")
            return
        if args.using == "self":
            pub, priv = c3m.MakeSign(action=c3m.MAKE_SELFSIGNED, name=args.name)
        else:
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




    if cmd == "verify":
        public_part, _ = c3m.load_files(args.name)
        ret = c3m.verify(c3m.load(public_part))
        print("\n\nverify returns", repr(ret))
        return

    # if cmd == "fuzz":
    #     FuzzEKH2()
    #     return


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

    # policy: how to use:
    #         # self.MakeSign( blah blah using_priv=self.yield_private_key(self.load_priv_block(self.LoadFiles(name).priv_block))

    # in: block bytes from e.g. LoadFiles
    # out: keytype, privtype, shucked privbytes
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

    # Todo: do we want this to return blank, or exception?

    def decrypt_private_key(self, privd):
        if privd.privtype == PRIVTYPE_BARE:
            return privd.privdata
        if privd.privtype != PRIVTYPE_PASS_PROTECT:
            raise StructureError("Unknown privtype %d in priv block (wanted %r)" % (privd.privtype, KNOWN_PRIVTYPES))
        if self.pass_protect.DualPasswordsNeeded(privd.privdata):  # todo: allow for dual passwords
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
                # print("No password supplied, exiting")
                # break

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
        ppkey, index = self.expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, public_part, 0)
        public_part = public_part[index:]               # chop off the header
        if not public_part:
            raise StructureError("Missing cert chain / payload")

        # Should be a list of DAS structures, so pythonize the list
        das_list = self.list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)

        # unpack the certs & sigs in das_list
        for i, das in enumerate(das_list):
            # dont unpack cert if this is the first das and ppkey is PAYLOAD
            if i > 0 or ppkey == KEY_LIST_SIGNER:
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

    # Apart from actual signature fails, there are 3 ways for this to fail:
    # 1) "fell off" - unnamed issuer cert and no next cert in line
    # 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verified OK but isn't in the trust store.

    # verify() = Data-And-Sigs items list -> payload bytes or an Exception

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
                VK = ecdsa.VerifyingKey.from_string(next_cert.pub_key, ecdsa.NIST256p)
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

            das_bytes = b3.item.decode_value(data_type, has_data, is_null, data_len, buf, index)

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
            key, data_type, has_data, is_null, data_len, index = b3.item.decode_header(buf, index)
        except (IndexError, UnicodeDecodeError):
            raise StructureError("Header structure is invalid")  # from None
            # raise .. from None disables py3's chaining (cleaner unhandled prints) but isnt legal py2
        if key not in want_keys:
            raise StructureError("Incorrect key in header - wanted %r got %r" % (want_keys, key))
        if data_type != want_type:
            raise StructureError("Incorrect type in header - wanted %r got %r" % (want_type, data_type))
        if not has_data:
            raise StructureError("Invalid header - no has_data")
        return key, index


    # ============================== File Saving/Loading ===========================================

    # Policy: b3 header for "whole of private_part" and "whole of public_part" happens at our CALLER'S level
    #         validation that "this block of bytes is in fact the private part" happens there too.
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



    # ============================== Signing =======================================================

    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state

    # load_files()  single or combined files ->  public_part bytes and private_part bytes maybe
    # load() = public_part bytes -> list of Data-And-Sigs items.
    # verify() = Data-And-Sigs items list -> payload bytes or an Exception

    # write_files()  public_part bytes and private_part bytes maybe -> single or combined files

    # save()  list of data-and-sigs items   ?   ->   public_part bytes

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

    def MakeSign(self, action, name="", payload=b"", using_priv=b"", using_pub=b"", using_name=""):          # todo: change using_name to bytes. Also change name to bytes.
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
            new_pub_cert = AttrDict(name=name, pub_key=new_key_pub)
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
            _, index = self.expect_key_header([KEY_LIST_SIGNER], b3.LIST, using_pub, 0)
            using_pub = using_pub[index:]
            # 2) concat our data + using_public_part's data
            out_public_part = das_bytes_with_hdr + using_pub
        else:
            out_public_part = das_bytes_with_hdr

        # --- Prepend a new overall public_part header & return pub & private bytes ---
        if action == self.SIGN_PAYLOAD:
            key_type = KEY_LIST_PAYLOAD
        else:
            key_type = KEY_LIST_SIGNER
        out_public_with_hdr = b3.encode_item_joined(key_type, b3.LIST, out_public_part)

        return out_public_with_hdr, new_key_priv











if __name__ == "__main__":
    CommandlineMain()



