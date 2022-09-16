
from __future__ import print_function

import sys, re, base64, os
from pprint import pprint

import b3
import ecdsa

CERT_SCHEMA = (
    (b3.UTF8,  "name",  1),
    (b3.BYTES, "pub_key", 2),
    # (b3.SCHED, "expiry", 3),
    )

SIG_SCHEMA = (
    (b3.BYTES, "sig_bytes", 1),

)

DATA_AND_SIG = (
    (b3.BYTES, "data_bytes", 1),
    (b3.BYTES, "sig_bytes", 2),
)

class AttrDict(dict):
    def __getattr__(self, name):
        return self[name]


# Step 1: make 'makesigner' command.  With self-sign.
#         going with x=y argv structure for now, consider click later.

# Step 2: make verify ?

def CommandlineMain():
    if len(sys.argv) < 2:
        UsageBail()
    cmd = sys.argv[1].lower()
    args = ArgvArgs()

    if cmd == "makesignerselfsigned":
        MakeSignerSelfSigned(args)
        return

    if cmd == "makesignerusingsigner":
        MakeSignerUsingSigner(args)
        return

    if cmd == "signpayload":
        SignPayload(args)
        return

    if cmd == "verify":
        Verify(args)
        return

    if cmd == "loadfiles":
        pub,priv = LoadFiles(args.using)
        print("Pub:  " ,pub)
        print("Priv: ",priv)
        return

    UsageBail("Unknown command")

def GenKeysECDSANist256p():
    curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
    priv  = ecdsa.SigningKey.generate(curve=curve)
    pub   = priv.get_verifying_key()
    return priv.to_string(), pub.to_string()


MAKESIGNER_REQ_ARGS = ("name", ) # "expiry")  # ,"using", "output")

def MakeSignerSelfSigned(args):
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
    sig_d = AttrDict(sig_bytes=sk.sign(pub_cert_bytes))
    sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

    # wrap cert and sig together
    das = AttrDict(data_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
    das_bytes = b3.schema_pack(DATA_AND_SIG, das)

    # prepend header for das itself so straight concatenation makes a list-of-das
    das_bytes_with_hdr = b3.encode_item_joined(None, b3.DICT, das_bytes)

    # Save to combined file.
    WriteFiles(args.name, das_bytes_with_hdr, priv_bytes, combine=True)

    return


def MakeSignerUsingSigner(args):
    for req_arg in ("name", "using"):
        if req_arg not in args:
            UsageBail("please supply --%s=" % (req_arg,))

    # ---- Load signer & ready the ecdsa object ----
    using_public_part, using_private_part = LoadFiles(args.using)
    SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)

    # make keys
    priv_bytes, pub_bytes = GenKeysECDSANist256p()

    # make pub cert
    pub_cert = AttrDict(name=args.name, pub_key=pub_bytes)
    pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, pub_cert)

    # sign it, make sig
    sig_d = AttrDict(sig_bytes=SK.sign(pub_cert_bytes))
    sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

    # wrap cert & sig
    das = AttrDict(data_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
    das_bytes = b3.schema_pack(DATA_AND_SIG, das)

    # prepend header for das itself so straight concatenation makes a list-of-das
    das_bytes_with_hdr = b3.encode_item_joined(None, b3.DICT, das_bytes)

    # concat using's public with our cas
    output_public = das_bytes_with_hdr + using_public_part

    # Save to combined file.
    WriteFiles(args.name, output_public, priv_bytes, combine=True)



def SignPayload(args):
    for req_arg in ("name","using"):       # using name as the input filename too atm.
        if req_arg not in args:
            UsageBail("please supply --%s=" % (req_arg,))

    # ---- Load signer & ready the ecdsa object ----
    using_public_part, using_private_part = LoadFiles(args.using)
    SK = ecdsa.SigningKey.from_string(using_private_part, ecdsa.NIST256p)

    # load payload
    payload_bytes = open(args.name, "rb").read()

    # sign it, make sig
    sig_d = AttrDict(sig_bytes=SK.sign(payload_bytes))
    sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)

    # wrap payload & sig
    das = AttrDict(data_bytes=payload_bytes, sig_bytes=sig_bytes)
    das_bytes = b3.schema_pack(DATA_AND_SIG, das)

    # prepend header for das itself so straight concatenation makes a list-of-das
    das_bytes_with_hdr = b3.encode_item_joined(None, b3.DICT, das_bytes)

    # concat using's public with our cas
    output_public = das_bytes_with_hdr + using_public_part

    # Save to combined file.
    WriteFiles(args.name, output_public, b"", combine=False)    # wont write private_part if its empty


# step 1: just verify the in-place stuff. So we're temporarily ignoring the fact that there's no seperate root pub key,
#         and our root pub key is part of the incoming payload concatenation
# step 2: write the seeker after this.



# Expects a list of the same schema object. This should eventually be part of b3.
# the schema objects need headers in an e.g. with_header way.
# so, list item headers in the case of a list of DAS objects.

def list_of_schema_unpack(schema, buf):
    end = len(buf)
    index = 0
    out = []
    while index < end:
        print("decoding header, index=",index)
        key, data_type, has_data, is_null, data_len, index = b3.item.decode_header(buf, index)
        print("key %r  data_type %r  has %r  null %r  len %r  index %r" % (key,data_type,has_data,is_null,data_len,index))

        assert key is None  # we dont care about key (we are a list not dicts so there shouldn't be any keys)
        assert has_data is True
        assert is_null is False
        assert data_type == b3.DICT
        assert data_len > 0
        # decode_value will just get us the bytes
        # Note: we could make a super simplified b3 decode_header that just extracts data_len here
        #       (and asserts data_type is dict, has_data true, not_null true, etc)
        #       favour rigour over performace ? these aren't hotpath apart from ACMD messages which get swamped by the ecdsa verify anyway.
        #       but then we could also make this a b3 function itself anyway.
        das_bytes = b3.item.decode_value(data_type, has_data, is_null, data_len, buf, index)

        # Now unpack the actual dict too
        dx = b3.schema_unpack(schema, das_bytes)
        out.append(AttrDict(dx))
        index += data_len
    return out


def Verify(args):

    # temporarily not using --using, everything coming from the signed-payload-file

    public_part, private_part = LoadFiles(args.name)

    # Should be a list of DAS structures, so pythonize the list
    das_list = list_of_schema_unpack(DATA_AND_SIG, public_part)

    # unpack the certs & sigs in das_list
    for das in das_list:
        das["cert"] = AttrDict(b3.schema_unpack(CERT_SCHEMA, das.data_bytes))     # creates a 'none none' cert entry for the payload das.
        das["sig"] = AttrDict(b3.schema_unpack(SIG_SCHEMA, das.sig_bytes))

        print()
        pprint(das)

    # ok we got payload bytes (das.data_bytes) and sig bytes (das.sig.sig_bytes)

    for i,das in enumerate(das_list):

        # seek the signing cert for the sig (currently just the next in line)
        next_das = das_list[i+1]
        issuer_cert_pub_key_bytes = next_das.cert.pub_key

        # make ecdsa VK
        VK = ecdsa.VerifyingKey.from_string(issuer_cert_pub_key_bytes, ecdsa.NIST256p)

        # Do verify
        ret = VK.verify(das.sig.sig_bytes, das.data_bytes)
        print("Verifying name ", das.cert.name, " returns ",ret)

        # we dont have a current indicator that the end is self-signed.
        # next step is to add issuer-names to the sigs.








    #
    # cas_b64 = open("cas.b64", "rb").read()
    # cas_bytes = base64.b64decode(cas_b64)
    # cas = AttrDict(b3.schema_unpack(CERT_AND_SIG, cas_bytes))
    # print(cas)
    # cert = AttrDict(b3.schema_unpack(CERT_SCHEMA, cas.cert_bytes))  # note we use cert_bytes HERE
    #
    # # verify selfsign - certs pubkey and cas.sig_bytes
    # print("Verifying using cert named: ", cert.name)
    # verify_key = ecdsa.VerifyingKey.from_string(cert.pub_key, ecdsa.NIST256p)
    # ret = verify_key.verify(cas.sig_bytes, cas.cert_bytes)          # and also HERE
    # print("Verify ret: ",repr(ret))


# Policy: names are short and become the filename. They can go in the cert too.
#         Skip IDs for now.

# File input output
# --using name or NAME  (check environ if upper case)

# --output combined or --output split

# print(len(base64.encodebytes(b"a"*500).decode().splitlines()[0]))    = 76

def AscHeader(msg):
    m2 = "[ %s ]" % msg
    offs = 37 - len(m2)//2
    line = "-"*offs
    line += m2
    line += "-"*(76-len(line))
    return line



def WriteFiles(name, public_part, private_part=b"", combine=True, desc=""):
    pub_desc = desc if desc else (name + " - Payload & Public Certs")
    priv_desc = (desc or name) + " - PRIVATE Key"
    pub_str = AscHeader(pub_desc) + "\n" + base64.encodebytes(public_part).decode()
    priv_str = AscHeader(priv_desc) + "\n" + base64.encodebytes(private_part).decode()
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



# I think we should have a marker byte, NOT at our level, so we can say public/private etc.
# Much easier and more robust than paying any attention to the headerlines or the filenames.
# If the "marker byte" is actually a b3 header, then the actual binary can just be concatenated, in a bin file
# and the b64 can just be concatenated, in a "naked" b64 file or paste.

# Policy: b3 header for "whole of private_part" and "whole of public_part" happens at our CALLER'S level
#         validation that "this block of bytes is in fact the private part" happens there too.

# look for name.PRIVATE and name.PUBLIC (.b64.txt)
# split trumps combined.
# Return "" for private_part if there is none, callers can validate


def LoadFiles(name):
    pub_block = b""
    priv_block = b""
    header_rex = r"^-+\[ (.*?) \]-+$"

    combine_name = name + ".b64.txt"
    if os.path.isfile(combine_name):
        # --------------------------------- Combined mode file ---------------------------------
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











    # ---- D I M E N S I O N S ----

    # keytypes & libsodium & libsodium loading
    # passprotect porting to b3
    # File saving, split/combine & ascii
    # File loading, --using, split/combine & ascii

    # list-signatures, multi cert seeking, building a chain, looping through a chain.
    # Turning the chain into python data structure





    # libsodium and how things are gonna have to be a class for libsodium, so it can load its DLL on startup.
    # vetting the libsodium dlls with a hash. (we need this because then they vet everything else)


    # the Using loader
    # the file savers

    # libsodium

    # multi-signature
    # - the b3 list-of-schemaDicts function.

    # We need to make Tests for the list-of-schemaDicts stuff.
    # cant test without file saving/loading so



    # The next step for us is chain-signing.




    # MAKESIGNER TODO:

    # make priv and pub keypair bytes
    # pub + expiry + name -> cert bytes
    # sign cert bytes with priv, make sig bytes

    # output a simple base64 of the pub and of the priv.
    # enough to simple-load and run verify.

    # -----------------------------------------------------------------------

    # Takes a password for crypting the private key (ideally twice)
    # outputs e.g. root1.public.txt and root1.PRIVATE.txt
    # --using=self first.

    # turn priv into an encrypted priv
    # output priv in a nice texty way

    # turn pub into a cert then cert bytes
    # load the --using cert
    # sign the cert bytes, make a signature bytes

    # glue the signature and cert bytes together
    # add the chain bytes (?)

    # output in a nice texty way






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