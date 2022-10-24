
from __future__ import print_function

import sys, re, base64, os, binascii, functools, datetime, copy

import ecdsa
import b3

import getpassword
import pass_protect

from constants import *
from errors import *
import structure
from structure import AttrDict
import textfiles

b3.composite_schema.strict_mode = True

# Policy: Be as janky with this stuff as we want right now, we're not doing a public release,
#         just making the UX not suck too bad for us. This means click is out, --nopassword=yes is ok.
# Policy: For simplicity for now, the subject names and cert_ids are the same. Later there should be ULIDs.

# [NOT DOING] DNF Flags
# [DONE] * fix the new field names in the code.
# [DONE]  - rebuild the test data with the new field names.
# [DONE] * get expiry dates and expiry handling in.
# [DONE] * have verify return a nice chain along with the payload if any.
# [DONE] * the update b3 fixmes
# [DONE] * cross check priv key with pub key on using load
# [DONE] * integrate check_friendly's vertical validation with load_files loader.
# [DONE] * integrate make_friendly at commandline level or save_files level
# [DONE] * fix up commandline handling - do this in conjunction with the Licensing use case.

# * Break the code up into bytes operations (c3main.C3) and files stuff (load/save & friendlies)
#   - Turn into Package.
# * Clean up password prompts and commandline UX
# * improve expiry date parsing
# * Do build to pypi, 0.9.0


# [DO THIS DURING LICENSING]  - so e.g. licensing gets its own friendly fields.


# ============ Command line ========================================================================



def UsageBail(msg=""):
    help_txt = """
    %s
    Usage:
    # python c3main.py  make --name=root1 --using=self  --parts=split
    # python c3main.py  make --name=inter1 --using=root1 --link=name --parts=combine   

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

            upub, uepriv = textfiles.load_files(args.using)         # uses files
            upriv = c3m.decrypt_private_key(structure.load_priv_block(uepriv))  # (might) ask user for password
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
        pub_ffields = textfiles.make_friendly_fields(pub, CERT_SCHEMA, pub_ff_names)
        textfiles.write_files(args.name, pub, epriv, combine, pub_ff_lines=pub_ffields)
        return

    # python c3main.py  sign --payload=payload.txt --link=append  --using=inter1

    if cmd == "sign":
        if "payload" not in args:
            print("please supply --payload=<filename>")
            return
        payload_bytes = open(args.payload, "rb").read()

        upub, uepriv = textfiles.load_files(args.using)  # uses files
        upriv = c3m.decrypt_private_key(structure.load_priv_block(uepriv))  # (might) ask user for password
        link = {"append": c3m.LINK_APPEND, "name": c3m.LINK_NAME}[args.link]

        pub, priv = c3m.MakeSign(action=c3m.SIGN_PAYLOAD, name=args.name, payload=payload_bytes,
                                 using_priv=upriv, using_pub=upub, link=link)

        # pub_ff_names = ["whatever", "app_specific", "fields_app_schema_has"]
        # pub_ffields = c3m.make_friendly_fields(pub, APP_SCHEMA, pub_ff_names)
        textfiles.write_files(args.payload, pub, b"", combine=False)   #, pub_ff_lines=pub_ffields))
        # Note: ^^ no private part, so no combine.         ^^^ how to friendly-fields for app
        return

    # python c3main.py  verify --name=payload.txt --trusted=root1

    if cmd == "verify":
        if "trusted" in args:
            print("Loading trusted cert ",args.trusted)
            tr_pub, _ = textfiles.load_files(args.trusted)
            print("tr_pub is ",repr(tr_pub))
            c3m.add_trusted_certs(tr_pub)
        else:
            print("Please specify a trusted cert with --trusted=")
            return

        public_part, _ = textfiles.load_files(args.name)
        ret = c3m.verify(structure.load(public_part))
        print("\n\nverify returns", repr(ret))
        return

    UsageBail("Unknown command")





# ===================== MAIN CLASS =================================================================


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
        cert_chain = structure.load(certs_bytes)
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


    # ============ Private key encryptio / decryption  =============================================
    # Policy: we keep these here at top level because they interact with the user (passwords)
    #         and use a pass_protect object which needs startup initialisation (load libsodium)

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


    # ============ Verify =================================================================

    # Policy: Lives at top level because it needs access to toplevel's trust store

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
                    raise ShortChainError(structure.ctnm(das)+"Next issuer cert is missing")
                next_cert = chain[i + 1].cert
            else:
                # --- got a name, look in trusted for it, then in ourself (self-signed) ---
                if signing_cert_id in self.trusted_certs:
                    next_cert = self.trusted_certs[signing_cert_id]
                    found_in_trusted = True
                elif signing_cert_id in certs_by_id:
                    next_cert = certs_by_id[signing_cert_id]
                else:
                    raise CertNotFoundError(structure.ctnm(das)+"wanted cert %r not found" % signing_cert_id)

            # --- Actually verify the signature ---
            try:
                VK = ecdsa.VerifyingKey.from_string(next_cert.public_key, ecdsa.NIST256p)
                VK.verify(das.sig.signature, das.data_part)  # returns True or raises exception
            except Exception:       # wrap theirs with our own error class
                raise InvalidSignatureError(structure.ctnm(das)+"Signature failed to verify")
            # --- Now do next das in line ---

        # Chain verifies completed without problems. Make sure we got to a trust store cert.
        # If there is a payload, return it otherwise return True. (So bool-ness works.)
        # Even tho all errors are exceptions.
        if found_in_trusted:
            return True
        raise UntrustedChainError("Chain does not link to trusted certs")



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
        using_pub_key = structure.extract_first_dict(using_pub_block, CERT_SCHEMA).public_key
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
            _, index = structure.expect_key_header([KEY_LIST_CERTS], b3.LIST, using_pub, 0)
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
        dx0 = structure.extract_first_dict(using_pub, CERT_SCHEMA)
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
