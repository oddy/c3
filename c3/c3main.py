
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
    (b3.BYTES, "sig_bytes", 1)
)

CERT_AND_SIG = (
    (b3.BYTES, "cert_bytes", 1),
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

    if cmd == "makesigner":
        MakeSigner(args)
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

def MakeSigner(args):
    for req_arg in MAKESIGNER_REQ_ARGS:
        if req_arg not in args:
            UsageBail("please supply --%s=" % (req_arg,))

    # make keys
    priv_bytes, pub_bytes = GenKeysECDSANist256p()
    priv_b64 = base64.b64encode(priv_bytes)     # note is bytes

    # make pub cert for pub key
    pub_cert = AttrDict(name=args.name, pub_key=pub_bytes)
    pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, pub_cert)

    # self-sign it, make sig
    sk = ecdsa.SigningKey.from_string(priv_bytes, ecdsa.NIST256p)
    sig_d = AttrDict(sig_bytes=sk.sign(pub_cert_bytes))
    sig_bytes = b3.schema_pack(SIG_SCHEMA, sig_d)


    # wrap cert and sig together
    cas = AttrDict(cert_bytes=pub_cert_bytes, sig_bytes=sig_bytes)
    cas_bytes = b3.schema_pack(CERT_AND_SIG, cas)
    cas_b64 = base64.b64encode(cas_bytes)

    # save cert-and-sig
    with open("cas.b64", "wb") as f:
        f.write(cas_b64)
    print(" wrote cas.b64")

    # save private key
    with open("priv.b64", "wb") as f:
        f.write(priv_b64)
    print(" write priv.b64")

    return


def Verify(args):
    cas_b64 = open("cas.b64", "rb").read()
    cas_bytes = base64.b64decode(cas_b64)
    cas = AttrDict(b3.schema_unpack(CERT_AND_SIG, cas_bytes))
    print(cas)
    cert = AttrDict(b3.schema_unpack(CERT_SCHEMA, cas.cert_bytes))  # note we use cert_bytes HERE

    # verify selfsign - certs pubkey and cas.sig_bytes
    print("Verifying using cert named: ", cert.name)
    verify_key = ecdsa.VerifyingKey.from_string(cert.pub_key, ecdsa.NIST256p)
    ret = verify_key.verify(cas.sig_bytes, cas.cert_bytes)          # and also HERE
    print("Verify ret: ",repr(ret))


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
            f.write(pub_str)
            f.write("\n")
            f.write(priv_str)
        print("Wrote combined file: ",fname)
    else:
        fname = name + ".public.b64.txt"
        with open(fname, "w") as f:
            f.write(pub_str)
        print("Wrote public file:  ", fname)

        fname = name + ".PRIVATE.b64.txt"
        with open(fname, "w") as f:
            f.write(priv_str)
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
    combine_name = name + ".b64.txt"
    if os.path.isfile(combine_name):
        print("Loading ", combine_name)
        both_strs = open(combine_name,"r").read()
        # regex cap the header lines
        header_rex = r"^-+\[ (.*?) \]-+$"
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
        if "PRIVATE" in hdrs[0].group(1):
            # Private block comes first (not the normal case)
            print("not normal")
            return block1, block0       # public, private
        else:
            # Otherwise assume the public block comes first.
            print("normal")
            return block0, block1       # public, private


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