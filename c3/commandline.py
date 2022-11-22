
# C3 Command-line operations (make keys, sign etc).
# Doubles as usage examples for the various components.

from __future__ import print_function

import sys, re, datetime, shlex
from pprint import pprint

from c3.signverify import SignVerify

# Use cases:
# * Make license (sign),  verify license
# * Make acmd key, make (sign) acmd message, verify acmd message
# * make build key [nocode], sign build manifest [nocode], verify build manifest  [signverify]

def CommandlineMain(cmdline_str=""):
    args = ArgvArgs(cmdline_str)    # cmdline_str is for testing, usually this pulls from sys.argv
    cmd = args.cmd
    c3m = SignVerify()

    try:
        # --- CSR / certchain pipeline ---
        if cmd == "make":
            parts = args.parts
            # --- pub cert (signing request) ---
            csr = c3m.make_csr(name=args.name, expiry=args.expiry, cert_type=args.type)
            # --- private key (encrypt) ---
            if "nopassword" in args:
                csr.private_key_set_nopassword()
            else:
                csr.private_key_encrypt_user()
            # --- save file(s) ---
            write_out_file(csr, parts, args.name)
            return

        if cmd == "signcert":
            parts = args.parts
            to_sign = c3m.load(filename=args.name)
            if args.using == "self":
                signer = to_sign
            else:
                signer = c3m.load(filename=args.using)
            link_by_name = "link" in args and args.link == "name"
            signer.private_key_decrypt_user()
            c3m.sign(to_sign, signer, link_by_name)
            write_out_file(to_sign, parts, args.name)
            return

        # --- Payload pipeline ---
        if cmd == "signpayload":
            signer = c3m.load(filename=args.using)
            payload = c3m.make_payload(open(args.payload, "rb").read())
            signer.private_key_decrypt_user()
            c3m.sign(payload, signer)
            payload.pub.write_text_file(args.payload)
            return

        # --- Load & verify ---
        if cmd == "verify":
            c3m.load_trusted_cert(filename=args.trusted)
            ce = c3m.load(filename=args.name)
            if c3m.verify(ce):
                print("\nVerify OK")
            return

        if cmd == "load":
            x = c3m.load(filename=args.name)
            print("pub_type ", x.pub_type)
            print("chain    ")
            pprint(x.chain)
            print("payload  ")
            print(x.payload)
            return

        Usage()
        print("Unknown Command %r" % cmd)

    except Exception as e:
        if "debug" in args:
            raise
        else:
            Usage()
            print("ERROR:  "+str(e))
            return


def write_out_file(ce, parts, name):
    # --- Write split or combined text files ---
    if parts == "split":
        ce.pub.write_text_file(name)
        ce.priv.write_text_file(name)
    elif parts == "combine":
        ce.both.write_text_file(name)
    else:
        print("\nERROR:  Please specify --parts=split or --parts=combine")


def Usage(msg=""):
    help_txt = """%s
Usage:
    c3 make        --name=root1  --expiry="24 oct 2024" --parts=split
    c3 signcert    --name=root1  --using=self           --parts=split
    c3 make        --name=inter1 --expiry="24 oct 2024" --parts=combine
    c3 signcert    --name=inter1 --using=root1          --parts=combine
    c3 signpayload --payload=payload.txt --using=inter1
    c3 verify      --name=payload.txt --trusted=root1
    """ % (msg,)
    print(help_txt)

class ArgvArgs(dict):
    def __init__(self, cmdline_str=""):
        super(ArgvArgs, self).__init__()
        if cmdline_str:                         # for testing
            argv = shlex.split(cmdline_str)
        else:
            argv = sys.argv
        if len(argv) < 2:
            Usage()
            sys.exit(1)
        self.cmd = argv[1].strip().lower()
        for arg in argv:
            z = re.match(r"^--(\w+)=(.+)$", arg)
            if z:
                k, v = z.groups()
                self[k] = v
        self.optional_args = ["type"]
    def __getattr__(self, name):
        if name not in self:
            if name in self.optional_args:
                return None
            raise Exception("Please specify missing commandline argument   --%s="%name)
        return self[name]


