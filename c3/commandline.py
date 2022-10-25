
# C3 Command-line operations (make keys, sign etc).
# Doubles as usage examples for the various components.

from __future__ import print_function

import sys, re, datetime
from pprint import pprint

from c3.constants import *
from c3 import signverify
from c3 import structure
from c3 import textfiles


# Policy: Be as janky with this stuff as we want right now, we're not doing a public release,
#         just making the UX not suck too bad for us. This means click is out, --nopassword=yes is ok.
# Policy: For simplicity for now, the subject names and cert_ids are the same. Later there should be ULIDs.

# - Turn into Package.
# * Clean up password prompts and commandline UX
# * improve expiry date parsing
# * Do build to pypi, 0.9.0

# Use cases:
# * Make license (sign),  verify license
# * Make acmd key, make (sign) acmd message, verify acmd message
# * make build key [nocode], sign build manifest [nocode], verify build manifest  [signverify]


# need to do __init__.py  and have an external test code.
# For signing things, and verifying things.


# [DO THIS DURING LICENSING]  - so e.g. licensing gets its own friendly fields.


#               |     no payload             payload
#  -------------+-------------------------------------------------
#  using cert   |     make chain signer      sign payload
#               |
#  using self   |     make self signer       ERROR invalid state


def CommandlineMain(zargs=None):
    print("Checking Function args received (for entry point testing): ",repr(zargs))
    if zargs is None:
        zargs = sys.argv[1:]
    if len(zargs) < 1:
        UsageBail()
    cmd = zargs[0].lower()
    args = ArgvArgs(zargs)

    c3m = signverify.SignVerify()

    # python commandline.py  make --name=root1 --using=self  --parts=split --expiry=2022-02-02
    # python commandline.py  make --name=inter1 --using=root1 --link=name --parts=combine --expiry=2022-02-02

    if cmd == "make":
        if "using" not in args:
            print("'make' needs --using=<name> or --using=self, please supply")
            return

        expiry = ParseExpiryDate(args.expiry)
        if args.using == "self":
            pub_block, priv = c3m.make_sign(action=MAKE_SELFSIGNED, name=args.name, expiry=expiry)
        else:
            if "link" not in args:
                print("'make' needs --link=append or --link=name, please supply")
                return

            upub, uepriv = textfiles.load_files(args.using)         # uses files
            upriv = c3m.decrypt_private_key(structure.load_priv_block(uepriv))  # (might) ask user for password
            link = {"append" : LINK_APPEND, "name" : LINK_NAME}[args.link]

            pub_block, priv = c3m.make_sign(action=MAKE_INTERMEDIATE, name=args.name, expiry=expiry,
                                 using_priv=upriv, using_pub=upub, using_name=args.using, link=link)

        bare = "nopassword" in args  # Note: has to be --nopassword=blah for now.
        if not bare:
            print("Setting password on private key-")
            epriv = c3m.encrypt_private_key(priv)
        else:
            epriv = priv
        epriv_block = structure.make_priv_block(epriv, bare)

        combine = True
        if "parts" in args and args.parts == "split":
            combine = False

        pub_ff_names = ["subject_name", "expiry_date", "issued_date"]
        pub_ffields = textfiles.make_friendly_fields(pub_block, CERT_SCHEMA, pub_ff_names)

        textfiles.write_files(args.name, pub_block, epriv_block, combine, pub_ff_lines=pub_ffields)
        return

    # python commandline.py  sign --payload=payload.txt --link=append  --using=inter1

    if cmd == "sign":
        if "payload" not in args:
            print("please supply --payload=<filename>")
            return
        payload_bytes = open(args.payload, "rb").read()

        upub, uepriv = textfiles.load_files(args.using)  # uses files
        upriv = c3m.decrypt_private_key(structure.load_priv_block(uepriv))  # (might) ask user for password
        link = {"append": LINK_APPEND, "name": LINK_NAME}[args.link]

        pub, priv = c3m.make_sign(action=SIGN_PAYLOAD, name=args.name, payload=payload_bytes,
                                  using_priv=upriv, using_pub=upub, link=link)

        # pub_ff_names = ["whatever", "app_specific", "fields_app_schema_has"]
        # pub_ffields = c3m.make_friendly_fields(pub, APP_SCHEMA, pub_ff_names)
        textfiles.write_files(args.payload, pub, b"", combine=False)   #, pub_ff_lines=pub_ffields))
        # Note: ^^ no private part, so no combine.         ^^^ how to friendly-fields for app
        return

    # python commandline.py  verify --name=payload.txt --trusted=root1

    if cmd == "verify":
        if "trusted" in args:
            print("Loading trusted cert ", args.trusted)
            tr_pub, _ = textfiles.load_files(args.trusted)
            c3m.add_trusted_certs(tr_pub)
        else:
            print("Please specify a trusted cert with --trusted=")
            return

        public_part, _ = textfiles.load_files(args.name)
        chain = structure.load_pub_block(public_part)
        ret = c3m.verify(chain)
        print("\n\nverify returns", repr(ret))
        if not ret:
            return
        print("Chain:")
        pprint(structure.get_meta(chain))
        print("Payload:")
        print(structure.get_payload(chain))
        return

    UsageBail("Unknown command")



def ParseExpiryDate(exp_str):
    exp_d = datetime.datetime.strptime(exp_str, "%Y-%m-%d").date()
    # Put some intelligent regex matches here so we can decode a few of the most common date formats
    # yes we need this.
    return exp_d


def UsageBail(msg=""):
    help_txt = """
    %s
    Usage:
    # python commandline.py  make --name=root1 --using=self  --parts=split
    # python commandline.py  make --name=inter1 --using=root1 --link=name --parts=combine   

    """ % (msg+"\n",)
    print(help_txt)
    sys.exit(1)


def ArgvArgs(zargs):
    args = structure.AttrDict()
    for arg in zargs:
        z = re.match(r"^--(\w+)=(.+)$", arg)
        if z:
            k, v = z.groups()
            args[k] = v
    return args

if __name__ == "__main__":
    CommandlineMain()


