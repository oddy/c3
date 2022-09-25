
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

# What we have to do to test it.
# Make selfsigned root1, make inter1, make

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
class UntrustedChainError(VerifyError): # the chain ends with a self-sign we dont have in Trusted
    pass




# Policy: verify() only reads from self.trusted_certs, it doesnt write anything into there.
#         That's the caller's (user's) remit.


class C3(object):
    def __init__(self):
        self.trusted_certs = {}   # by name. For e.g. root certs etc.
        return

    # ===================================== API ====================================================

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
        if "cert" in das:
            return " (cert %r) " % das.cert.name
        else:
            return " (payload) "

    # Apart from actual signature fails, there are 3 ways for this to fail:
    # 1) "fell off" - unnamed issuer cert and no next cert in line
    # 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verified OK but isn't in the trust store.

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
        raise UntrustedChainError(self.ctnm(das)+"Chain does not link to trusted certs")




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

    def MakeSigner(self):
        return


    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state



    def MakeSign(self, payload_file_name, using_file_part_name, new_key_name):

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
        out = []
        append = False      # whether to append Using's public part or link by issuer_name instead.

        if payload_file_name and using_file_part_name == "self":
            raise TypeError("using=self is only for creating selfsigning certs, not signing payloads")


        # --- Key gen if applicable ---
        if not payload_file_name:
            # make keys
            new_key_priv, new_key_pub = self.GenKeysECDSANist256p()

            # make pub cert for pub key
            new_pub_cert = AttrDict(name=new_key_name, pub_key=new_key_pub)
            new_pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, new_pub_cert)
            payload_bytes = new_pub_cert_bytes
        # --- Load payload if not key-genning ---
        else:
            payload_bytes = open(payload_file_name,"rb").read()


        # --- Make a selfsign if applicable ---
        if using_file_part_name == "self":      # we have new_key_priv because not payload_file_name is guaranteed
            # self-sign it, make sig
            SK = ecdsa.SigningKey.from_string(new_key_priv, ecdsa.NIST256p)
            sig_d = AttrDict(sig_val=SK.sign(payload_bytes), issuer_name=new_key_name)  # note byname, not append
            append = False                                                              # note byname, not append
            sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Sign the thing (cert or payload) using Using, if not selfsign ----
        else:
            using_public_part, using_private_part = self.load_files(using_file_part_name)
            SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)
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
            _, index = self.expect_key_header([KEY_LIST_SIGNER], b3.LIST, using_public_part, 0)
            using_public_part = using_public_part[index:]
            # 2) concat our data + using_public_part's data
            out_public_part = das_bytes_with_hdr + using_public_part
        else:
            out_public_part = das_bytes_with_hdr

        # --- Prepend a new overall public_part header & save out files ---
        if payload_file_name:
            # signed-payload output
            out_public_with_hdr = b3.encode_item_joined(KEY_LIST_PAYLOAD, b3.LIST, out_public_part)
            self.write_files(payload_file_name, out_public_with_hdr, b"", combine=False)  # wont write private_part if its empty
        else:
            # signer (self or chain) output
            out_public_with_hdr = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, out_public_part)
            self.write_files(payload_file_name, out_public_with_hdr, new_key_priv, combine=True)





    def MakeSignerSelfSigned(self, args):
        MAKESIGNER_REQ_ARGS = ("name",)  # "expiry")  # ,"using", "output")
        for req_arg in MAKESIGNER_REQ_ARGS:
            if req_arg not in args:
                UsageBail("please supply --%s=" % (req_arg,))

        # make keys
        priv_bytes, pub_bytes = GenKeysECDSANist256p()

        # make pub cert for pub key
        pub_cert = AttrDict(name=args.name, pub_key=pub_bytes)
        pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, pub_cert)

        # self-sign it, make sig
        sk = ecdsa.SigningKey.from_string(priv_bytes, ecdsa.NIST256p)
        sig_d = AttrDict(sig_val=sk.sign(pub_cert_bytes),
                         issuer_name=args.name)  # issuer == us bc self-sign
        sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # wrap cert and sig together
        das = AttrDict(data_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # prepend header for das itself so straight concatenation makes a list-of-das
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # prepend the overall public_part header
        public_part = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, das_bytes_with_hdr)

        # Save to combined file.
        self.write_files(args.name, public_part, priv_bytes, combine=True)

        return

    def MakeSignerUsingSignerAppended(self, args):
        for req_arg in ("name", "using"):
            if req_arg not in args:
                UsageBail("please supply --%s=" % (req_arg,))

        # ---- Load signer & ready the ecdsa object ----
        using_public_part, using_private_part = self.load_files(args.using)
        SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)

        # make keys
        priv_bytes, pub_bytes = GenKeysECDSANist256p()

        # make pub cert
        pub_cert = AttrDict(name=args.name, pub_key=pub_bytes)
        pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, pub_cert)

        # sign it, make sig
        sig_d = AttrDict(sig_val=SK.sign(pub_cert_bytes))
        sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # wrap cert & sig
        das = AttrDict(data_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # prepend header for das itself so straight concatenation makes a list-of-das
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # we need to
        # 1) strip using_public_part's public_part header,
        # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)

        _, index = expect_key_header2([KEY_LIST_SIGNER], b3.LIST, using_public_part, 0)
        using_public_part = using_public_part[index:]

        # 2) concat our data + using_public_part's data
        out_public_part = das_bytes_with_hdr + using_public_part

        # 3) prepend a new overall public_part header
        out_public_part = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, out_public_part)

        # Save to combined file.
        self.write_files(args.name, out_public_part, priv_bytes, combine=True)



    def MakeSignerUsingSignerByName(self, args):
        for req_arg in ("name", "using"):
            if req_arg not in args:
                UsageBail("please supply --%s=" % (req_arg,))

        # ---- Load signer & ready the ecdsa object ----
        _, using_private_part = self.load_files(args.using)
        SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)

        # make keys
        priv_bytes, pub_bytes = GenKeysECDSANist256p()

        # make pub cert
        pub_cert = AttrDict(name=args.name, pub_key=pub_bytes)
        pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, pub_cert)

        # sign it, make sig
        sig_d = AttrDict(sig_val=SK.sign(pub_cert_bytes) , issuer_name=args.using)
        sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # wrap cert & sig
        das = AttrDict(data_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # prepend header for das itself so straight concatenation makes a list-of-das
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # # we need to
        # # 1) strip using_public_part's public_part header,
        # # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)
        #
        # _, index = expect_key_header([KEY_LIST_SIGNER], b3.LIST, using_public_part, 0)
        # using_public_part = using_public_part[index:]
        #
        # # 2) concat our data + using_public_part's data
        # out_public_part = das_bytes_with_hdr + using_public_part

        # 3) prepend a new overall public_part header
        out_public_part = b3.encode_item_joined(KEY_LIST_SIGNER, b3.LIST, das_bytes_with_hdr)

        # Save to combined file.
        self.write_files(args.name, out_public_part, priv_bytes, combine=True)

    def SignPayload(self, args):
        for req_arg in ("name", "using"):  # using name as the input filename too atm.
            if req_arg not in args:
                UsageBail("please supply --%s=" % (req_arg,))

        # ---- Load signer & ready the ecdsa object ----
        using_public_part, using_private_part = self.load_files(args.using)
        SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)

        # load payload
        payload_bytes = open(args.name, "rb").read()

        # sign it, make sig
        sig_actual_bytes = SK.sign(payload_bytes)
        print("sig_actual_bytes ", repr(sig_actual_bytes))
        print(len(sig_actual_bytes))

        sig_d = AttrDict(sig_val=sig_actual_bytes)
        sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

        # wrap payload & sig
        das = AttrDict(data_bytes=payload_bytes, sig_bytes=sig_bytes)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # prepend header for das itself so straight concatenation makes a list-of-das
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # # concat using's public with our cas
        # output_public = das_bytes_with_hdr + using_public_part

        # we need to
        # 1) strip using_public_part's public_part header,
        # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)

        _, index = expect_key_header2([KEY_LIST_SIGNER], b3.LIST, using_public_part, 0)
        using_public_part = using_public_part[index:]

        # 2) concat our data + using_public_part's data
        out_public_part = das_bytes_with_hdr + using_public_part

        # 3) prepend a new overall public_part header
        out_public_part = b3.encode_item_joined(KEY_LIST_PAYLOAD, b3.LIST, out_public_part)

        # Save to combined file.
        self.write_files(args.name, out_public_part, b"", combine=False)  # wont write private_part if its empty


    # using=using name, mode=append or link.
    # payload or no payload.










    # TODO TOMORROW:

    # 1) make inter1 that asks for root1 by name, instead of having root1 tacked on.  [DONE TESTED]
    # 2) make basic trust store, put root1 in it.   [DONE basic]
    # 3) run verify with (1) and (2)                [DONE basic]
    # 4) make test data root/inter/payload certs that exercise (1)(2)(3) scenarios.  [DONE TESTED]

    # 5) make the error messages be nice for all of (4)  [DONE]
    # 6) yield true and payload else raise exception with nice error message.   [payload vs commandline UX needs locking down]

    # 7) it would be nice to get multisig in at this point?
    # 8) make the code nice with classes and stuff, big clean up of the verify side  [DONE]
    # 9) then big clean up of the sign/make side

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

    # todo: This should become --append or --link when we click-ify the commandline.
    if "sign" in cmd and ("mode" not in args or args.mode not in ("append", "link") and args.using != "self"):
        print("please specify --mode=append or --mode=link")
        print("       append - add using's public part to the payload cert chain")
        print("       link   - add the NAME of using's public part to the payload cert chain")
        UsageBail()

    if cmd == "makesignerselfsigned":
        c3m.MakeSignerSelfSigned(args)
        return

    if cmd == "makesignerusingsignerappended":
        c3m.MakeSignerUsingSignerAppended(args)
        return

    if cmd == "makesignerusingsignerbyname":
        c3m.MakeSignerUsingSignerByName(args)
        return


    if cmd == "signpayload":
        c3m.SignPayload(args)
        return


    if cmd == "verify":
        public_part, _ = c3m.load_files(args.name)
        ret = c3m.verify(c3m.load(public_part))
        print("\n\nverify returns", repr(ret))
        return

    # if cmd == "fuzz":
    #     FuzzEKH2()
    #     return


    UsageBail("Unknown command")

def GenKeysECDSANist256p():
    curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
    priv  = ecdsa.SigningKey.generate(curve=curve)
    pub   = priv.get_verifying_key()
    return priv.to_string(), pub.to_string()


def expect_key_header2(want_keys, want_type, buf, index):
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


# step 1: just verify the in-place stuff. So we're temporarily ignoring the fact that there's no seperate root pub key,
#         and our root pub key is part of the incoming payload concatenation
# step 2: write the seeker after this.










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



# ---- Basic fuzzing of the initial header check ----
#
# def FuzzEKH():
#     for i in range(0,255):
#         buf = six.int2byte(i) #+ b"\x0f\x55\x55"
#         try:
#             ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, buf, 0)
#             print("%4i %02x - SUCCESS - key = %r" % (i,i, ppkey))
#         except Exception as e:
#             print("%4i %02x -  %s" % (i,i, e))
#             #print(traceback.format_exc())
#
# def FuzzEKH2():
#     i = 0
#     z = {}
#     while True:
#         i += 1
#         buf = random.randbytes(20)
#         try:
#             ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, buf, 0)
#             out = "SUCCESS - key = %r" % ppkey
#         except Exception as e:
#             out = "%r" % e
#
#         #print(out)
#         z[out] = z.get(out,0) + 1
#
#         if i % 100000 == 0:
#             print()
#             print(len(z))
#             pprint(z)
#
#



#
#
#
# def VerifyBlock(public_part):
#     global certs_by_name
#     print("certs by name",certs_by_name)
#     prevalid_certs_by_name = {}  # so self-signeds can be validated
#     found_in_global = False
#
#     # public_part = b"\xdd\x37\x03\xed\x4d\x01\x44"
#     # dd list-hdr x37=55=KEY_LIST_PAYLOAD 03=len  ed dict-hdr x4d=77=KEY_DAS 0x=len
#     # And we're into unpack DATA_AND_SIG and fail mando checks at that point, so we can stop checking everything so much.
#
#
#     # The public part should have an initial header that indicates whether the first das is a payload or a cert
#     ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, public_part, 0)
#     print("Initial header got key: ", ppkey,"  ",KEY2NAME[ppkey])
#     public_part = public_part[index:]               # chop off the header
#
#     # Should be a list of DAS structures, so pythonize the list
#     if not public_part:
#         raise StructureError("Missing cert chain / payload")
#
#     das_list = list_of_schema_unpack(DATA_AND_SIG, [KEY_DAS], public_part)
#     print("Got das list")
#     pprint(das_list)
#     #   - validated key=key_das
#     #   - type=dict is implicit to the function
#
#     # unpack the certs & sigs in das_list
#
#     for i, das in enumerate(das_list):
#         # dont unpack cert if this is the first das and ppkey is PAYLOAD
#         # so DO unpack cert if this is not the first das, or if ppkey is signer
#         if i > 0 or ppkey == KEY_LIST_SIGNER:
#             das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_bytes))       # creates a 'none none' cert entry for the payload das.
#
#         # always unpack sig
#         das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_bytes))
#         schema_assert_mandatory_fields_truthy(SIG_SCHEMA, das.sig)
#
#         if "cert" in das:
#             schema_assert_mandatory_fields_truthy(CERT_SCHEMA, das.cert)
#             # update name:cert map/index.  (This will later have the root cert in it, and can be a cache.)
#             prevalid_certs_by_name[das.cert.name] = das.cert
#
#
#     print()
#     print("========")
#     print()
#     pprint(das_list)
#     print()
#     print("========")
#     print()
#     pprint(certs_by_name)
#     print()
#     print("++++++++")
#
#     # ok we got payload bytes (das.data_bytes) and sig bytes (das.sig.sig_bytes)
#
#     for i, das in enumerate(das_list):
#         print()
#         print("next cert")
#         found_in_global = False
#
#         # seek the signing cert for the sig
#         issuer_name = das.sig.issuer_name
#         print("sig issuer name is ",repr(issuer_name))
#
#         # if it's empty, that means "next cert in the chain"
#         if not issuer_name:
#             print("no issuer name, assuming next cert in chain is the signer")
#
#             if i+1 >= len(das_list):
#                 raise VerifyError("Cert chain has no link to trust store (end of chain reached)")     # FAIL: fell off
#
#             next_das = das_list[i + 1]
#             issuer_cert_pub_key_bytes = next_das.cert.pub_key
#         # if it's not, try to get the cert from our cache
#         # This will work for self-signed roots because their sig's issuer_name == their name
#         else:
#             print("got issuer name, looking up in certs_by_name")
#             # Try it in both, if its in prevalid then ok
#             # if its in global, then even better, and set found_in_trust_root true
#             if issuer_name in certs_by_name:
#                 print("found in GLOBAL certs_by_name")
#                 issuer_cert = certs_by_name[issuer_name]
#                 found_in_global = True
#             elif issuer_name in prevalid_certs_by_name:
#                 print("found in prevalid certs_by_name")
#                 issuer_cert = prevalid_certs_by_name[issuer_name]
#             else:
#                 raise VerifyError("Issuer cert %r not found in trust store" % issuer_name)        # FAIL: requested name not found
#
#             print("got cert")
#             issuer_cert_pub_key_bytes = issuer_cert.pub_key
#
#         # make ecdsa VK
#         VK = ecdsa.VerifyingKey.from_string(issuer_cert_pub_key_bytes, ecdsa.NIST256p)
#
#         # Do verify
#         ret = VK.verify(das.sig.sig_val, das.data_bytes)
#         if i == 0 and ppkey == KEY_LIST_PAYLOAD:
#             vname = "payload"
#         else:
#             vname = "cert "+das.cert.name
#
#         print("Verifying ", vname, " returns ",ret)
#
#         # ok if we got here the cert or payload is valid
#         if ret == True:
#             # if we found our issuer in the global store, we are successful
#             if found_in_global == True:
#                 print("Validated by global cert! we have won.")
#
#                 # TODO: only NOW do we want to load all the certs in the chain
#                 # TODO: this needs to be reworked to only save into global, certs that have been fully validated.
#                 #       so make a proper cert cache
#                 if i > 0 or ppkey == KEY_LIST_SIGNER:  # put the cert in global certs_by_name
#                     print("cert ", vname, " is valid, putting in global certs_by_name")
#                     certs_by_name[das.cert.name] = das.cert
#
#                 return True
#
#     # otherwise we got to the end and the cert was not found in global
#     print("got to the end and cert wasnt found in global")
#     return False        # for now so we can use this as code_root1's loader
#
#     raise VerifyError("End of cert chain but no issuer found in global trust store")
#
#
#     # There are 3 ways for this to fail:
#     # 1) "fell off" - unnamed issuer cert and no next cert in line
#     # 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
#     # 3) Last cert is self-signed and verified OK but isn't in the trust store.
#
#     # So its about "getting to" the pretrusted cert(s).
#     # Once we're in the trust store we can stop, and return success.
#     # - along with the payload, if ppkey says there is a payload.
#
#     # (1) - fail trying to pull next_das.
#     # (2) - cert not found in certs_by_name.
#     # (3) - at the end but trust_store flag is not on (or something).
#
