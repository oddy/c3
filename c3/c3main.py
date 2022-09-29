
from __future__ import print_function

import sys, re, base64, os, traceback, random
from pprint import pprint

import six

import b3
b3.composite_schema.strict_mode = True   # to make b3 error when we field names wrong when schema_packing
import ecdsa


# Todo: Consider fuzz-friendly-ing the structure error messages.

# So far we dont have any optional fields.

# tag/key values (mostly for sanity checking)
# level0
KEY_LIST_PAYLOAD = 55  # cert chain with a payload as the first entry
KEY_LIST_SIGNER = 66   # cert chain with a cert as the first entry
# level1
KEY_DAS = 77

KEY2NAME = {55:"KEY_LIST_PAYLOAD", 66:"KEY_LIST_SIGNER", 77:"KEY_DAS"}

CERT_SCHEMA = (
    (b3.UTF8,  "name",  1, True),
    (b3.BYTES, "pub_key", 2, True),
    # (b3.SCHED, "expiry", 3),
    )

SIG_SCHEMA = (
    (b3.BYTES, "sig_val", 1,  True),
    (b3.UTF8, "issuer_name", 2, False),     # field value can be optional
)

DATA_AND_SIG = (
    (b3.BYTES, "data_bytes", 1, True),
    (b3.BYTES, "sig_bytes", 2, True),
)


class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]


# Errors
class C3Error(ValueError):
    pass
class StructureError(C3Error):  # something wrong with the data/binary structure; misparse, corrupt
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



# Policy: verify() only reads from self.trusted_certs, it doesnt write anything into there.
#         That's the caller's (user's) remit.

class C3(object):
    def __init__(self):
        self.trusted_certs = {}   # by name. For e.g. root certs etc.
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

    # This does not count using write_files or read_files

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

    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state

    # Make/Sign actions:
    MAKE_SELFSIGNED = 1
    MAKE_INTERMEDIATE = 2
    SIGN_PAYLOAD = 3

    # name = name to give selfsigned cert, name to give inter cert.  (payload doesnt get a name)
    # payload_bytes  = the payload, if signing a payload
    # using_pub_bytes, using_priv_bytes = the parts of the Using keypair, if not making selfsigned


    def MakeSign(self, action, name="", payload="", using_pub=b"", using_priv=b""):

        # payload_or_cert True = sign a payload
        # payload_or_cert False = gen keys, make a cert/signer

        # payload = afilename
        # payload = nothing -> generate a key
        # using == self  -> selfsign
        # using = afilename

        # [key gen]  if applicable   - if not payload

        # [make a selfsign] if applicable  - if using = self (and not payload). cant sign a payload with self, error.

        # [sign the thing using using] if not selfsign

        # [append pub] if applicable   - if not selfsign (and maybe later, options + DoNotDistribute)

        # [prepend header] for payload-or-not

        # <also deliver priv> if applicable

        new_key_priv = None
        append = False      # whether to append Using's public part or link by issuer_name instead.

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
            sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name=name)  # note byname, not append
            append = False                                                      # note byname, not append
            sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Sign the thing (cert or payload) using Using, if not selfsign ----
        else:
            SK = ecdsa.SigningKey.from_string(using_priv, ecdsa.NIST256p)
            sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name="")    # note append, not byname
            # sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name=using_file_part_name)  # if we were using byname instead of append.
            append = True                                                       # note append, not byname
            sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Make data-and-sig structure ---
        das = AttrDict(data_bytes=payload_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)
        # --- prepend header for das itself so straight concatenation makes a list-of-das ---
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)


        # --- Append Using's public_part (the chain) if applicable ---
        if append:
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

        # Caller has to write_files with combine false or true, depending.

        # if payload_or_cert:
        #     # signed-payload output
        #     out_public_with_hdr = b3.encode_item_joined(KEY_LIST_PAYLOAD, b3.LIST, out_public_part)
        #     self.write_files(name, out_public_with_hdr, b"", combine=False)  # wont write private_part if its empty
        # else:
        #     # signer (self or chain) output
        #     out_public_with_hdr = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, out_public_part)
        #     self.write_files(name, out_public_with_hdr, new_key_priv, combine=True)









    # TODO TOMORROW:

    # 1) make inter1 that asks for root1 by name, instead of having root1 tacked on.  [DONE TESTED]
    # 2) make basic trust store, put root1 in it.   [DONE basic]
    # 3) run verify with (1) and (2)                [DONE basic]
    # 4) make test data root/inter/payload certs that exercise (1)(2)(3) scenarios.  [DONE TESTED]

    # 5) make the error messages be nice for all of (4)  [DONE]
    # 6) yield true and payload else raise exception with nice error message.   [payload vs commandline UX needs locking down]

    # 7) it would be nice to get multisig in at this point?
    # 8) make the code nice with classes and stuff, big clean up of the verify side  [DONE]
    # 9) then big clean up of the sign/make side [DONE mostly]

    # 10) TESTS

    # AND THEN

    # multi-signature
    # keytypes & libsodium & libsodium loading
    # passprotect porting to b3
    # File saving, split/combine & ascii                [MOSTLY DONE]
    # File loading, --using, split/combine & ascii      [MOSTLY DONE]
    # signing expiry dates
    # clean up commandline API and function call API
    # list-signatures, multi cert seeking, building a chain, looping through a chain.  [MOSTLY DONE]
    # Turning the chain into python data structure  [DONE]
    # libsodium and how things are gonna have to be a class for libsodium, so it can load its DLL on startup.
    # vetting the libsodium dlls with a hash. (we need this because then they vet everything else)

    # THEN

    # 10) ascii fields
    # 11) release!

    # if root1 is self-signed we get here now and everything is happy
    # BECAUSE, the loop doesn't try and access the next cert at the end and blow up like it did before
    # and the loop gets to complete!





# Step 1: make 'makesigner' command.  With self-sign.
#         going with x=y argv structure for now, consider click later.

# Step 2: make verify ?

def CommandlineMain():
    if len(sys.argv) < 2:
        UsageBail()
    cmd = sys.argv[1].lower()
    args = ArgvArgs()

    c3m = C3()
    root1_b64 = """
    2UKgAelNnAEJAUsZAQVyb290MQkCQDwdIh7DZkYyPcz+W2cBYozFZ38FanSeEHW9sSsZB+uyNiwr
    etOgCKGUUzwULJVky5UOoZNaq/n79gpPhGhmVvAJAksJAUDuGhovJ49GsybchICpAa4iv1Z73T3B
    03wZn9LWfqwY2PJ/uB0zjnkTt+n9kpiSdVctyyGq3/m3Doo/mzk9HI7wGQIFcm9vdDE=    
    """
    root1_block = base64.b64decode(root1_b64)
    print("=======[ Verifying baked in root1 ]==========")
    c3m.add_trusted_certs(root1_block)
    print("=======[ Done Verifying baked in root1 ]==========")


    root3_b64 = """
    2UKgAelNnAEJAUsZAQVyb290MwkCQPtd9mb/53QGKK6TYFwluM9d1uRQBVMDC6eCQo//btLi1Ens
    Mi7O3hL77kih8Q83GtHUhP8Mu7YGARqV6ecsUX8JAksJAUAQdmLTqWUKoOaMnvOHyoBZAQSk2Yhl
    tCbtfzLEP0hn15424ybRC1AujqQ+NrnlmonvxVzWS1PxTOeZrNztYDqTGQIFcm9vdDM=  
    """
    root3_block = base64.b64decode(root3_b64)
    print("=======[ Verifying baked in root3 ]==========")
    c3m.add_trusted_certs(root3_block)
    print("=======[ Done Verifying baked in root3 ]==========")




    # todo: This should become --append or --link when we click-ify the commandline.
    # if "sign" in cmd and ("mode" not in args or args.mode not in ("append", "link") and args.using != "self"):
    #     print("please specify --mode=append or --mode=link")
    #     print("       append - add using's public part to the payload cert chain")
    #     print("       link   - add the NAME of using's public part to the payload cert chain")
    #     UsageBail()


    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state

    if cmd != "verify":
        using_name = args.using
        name = args.name
    #
    # if cmd == "makesignerselfsigned":
    #
    #     c3m.MakeSign(False, name, "self")
    #     # c3m.MakeSignerSelfSigned(args)
    #     return
    #
    # if cmd == "makesignerusingsignerappended":
    #     c3m.MakeSign(False, name, using_name)
    #     #c3m.MakeSignerUsingSignerAppended(args)
    #     return
    #
    # # if cmd == "makesignerusingsignerbyname":
    # #     c3m.MakeSignerUsingSignerByName(args)
    # #     return
    #
    #
    # if cmd == "signpayload":
    #     c3m.MakeSign(True, name, using_name)
    #     #c3m.SignPayload(args)
    #     return


    if cmd == "verify":
        public_part, _ = c3m.load_files(args.name)
        ret = c3m.verify(c3m.load(public_part))
        print("\n\nverify returns", repr(ret))
        return

    # if cmd == "fuzz":
    #     FuzzEKH2()
    #     return


    UsageBail("Unknown command")


# Policy: names are short and become the filename. They can go in the cert too.
#         Skip IDs for now.

# File input output
# --using name or NAME  (check environ if upper case)

# --output combined or --output split

# print(len(base64.encodebytes(b"a"*500).decode().splitlines()[0]))    = 76


def UsageBail(msg=""):
    help_txt = """
    %s
    Usage:    
    c3main makesigner --using=self --output=split --name=cert1 --expiry=2025-05-05
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


if __name__ == "__main__":
    CommandlineMain()



