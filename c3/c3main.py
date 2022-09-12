
from __future__ import print_function

import sys, re, base64

import b3
import ecdsa

CERT_SCHEMA = (
    (b3.UTF8,  "name",  1),
    (b3.BYTES, "pub_key", 2),
    # (b3.SCHED, "expiry", 3),
    )

# SIG_SCHEMA = (
#     (b3.BYTES, "sig_bytes", 1)
# )

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
    sig_bytes = sk.sign(pub_cert_bytes)     # note not using SIG_SCHEMA yet

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
    cert = AttrDict(b3.schema_unpack(CERT_SCHEMA, cas.cert_bytes))

    # verify selfsign - certs pubkey and cas.sig_bytes
    print("Verifying using cert named: ", cert.name)
    verify_key = ecdsa.VerifyingKey.from_string(cert.pub_key, ecdsa.NIST256p)
    ret = verify_key.verify(cas.sig_bytes, cas.cert_bytes)
    print("Verify ret: ",repr(ret))



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