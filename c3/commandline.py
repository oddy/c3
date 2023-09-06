
# C3 Command-line operations (make keys, sign etc).
# Doubles as usage examples for the various components.

from __future__ import print_function

import sys, re, datetime, shlex
from pprint import pprint

from c3.signverify import SignVerify
from c3.errors import NoPassword

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
            # --- pub cert (signing request) ---
            csr = c3m.make_csr(name=args.name, expiry=args.expiry, cert_type=args.type, key_type=args.keytype)
            # --- private key (encrypt) ---
            if "nopassword" in args:
                csr.private_key_set_nopassword()
            else:
                try:
                    csr.private_key_encrypt_user()
                except NoPassword:
                    print("\nNo password entered, bailing.")
                    return
            # --- save file(s) ---
            csr.write_files(args.parts, True)     # note: args.parts can be None
            print("Success!")
            return

        if cmd == "signcert":
            to_sign = c3m.load(filename=args.name)
            if args.using == "self" or args.using == args.name:
                signer = to_sign
            else:
                signer = c3m.load(filename=args.using)
            # todo: twiddle to_sign's expiry date if args.expiry exists. (ie, 'renew')
            link_by_name = "link" in args and args.link == "name"
            signer.private_key_decrypt_user()
            c3m.sign(to_sign, signer, link_by_name)
            to_sign.write_files(args.parts, True)
            print("Success!")
            return

        # --- Payload pipeline ---
        if cmd == "signpayload":
            signer = c3m.load(filename=args.using)
            payload = c3m.make_payload(open(args.payload, "rb").read())
            signer.private_key_decrypt_user()
            c3m.sign(payload, signer)
            payload.write_prints = True
            payload.pub.write_text_file(args.payload)
            print("Success!")
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


def Usage(msg=""):
    help_txt = """%s
Usage:
    c3 make        --name=root1  --expiry="24 oct 2024" 
    c3 signcert    --name=root1  --using=self           
    c3 make        --name=inter1 --expiry="24 oct 2024"
    c3 signcert    --name=inter1 --using=root1
    c3 signpayload --payload=payload.txt --using=inter1
    c3 verify      --name=payload.txt    --trusted=root1
    make options   --type=rootcert --parts=split/combine --nopassword=y
    sign options   --link=name/append
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
        self.optional_args = ["type", "parts", "keytype"]
    def __getattr__(self, name):
        if name not in self:
            if name in self.optional_args:
                return None
            raise Exception("Please specify missing commandline argument   --%s="%name)
        return self[name]


