
# C3 Command-line operations (make keys, sign etc).
# Doubles as usage examples for the various components.

from __future__ import print_function

import sys, re, datetime
from pprint import pprint

from c3.constants import *
from c3 import signverify
from c3 import structure
from c3 import textfiles

# Use cases:
# * Make license (sign),  verify license
# * Make acmd key, make (sign) acmd message, verify acmd message
# * make build key [nocode], sign build manifest [nocode], verify build manifest  [signverify]


# python commandline.py  verify --name=payload.txt --trusted=root1
# python commandline.py  sign --payload=payload.txt --link=append  --using=inter1


# --debug or --verbose  turns on stack traces.

# make --name=blah --expiry=blah  --parts=split


# python -m c3 make --name=hello --expiry="24 oct 2024"  --parts=combine  --debug=y  --nopassword=y


def CommandlineMain():
    CheckUsageBail()
    cmd = sys.argv[1].lower()
    args = ArgvArgs()
    c3m = signverify.SignVerify()

    # make CSR  outputfilename
    # sign   file (csr, chain[renewal],payload)  using file
    # signcert  signpayload
    # verify  file  trusted file

    try:
        if cmd == "make":
            # --- pub cert (signing request) ---
            csr = c3m.make_csr(name=args.name, expiry_text=args.expiry)
            # --- private key (encrypt) ---
            if "nopassword" in args:
                csr.private_key_set_nopassword()
            else:
                csr.private_key_encrypt_user()
            # --- Write split or combined text files ---
            if args.parts == "split":
                csr.pub.write_text_file(args.name)
                csr.priv.write_text_file(args.name)
            elif args.parts == "combine":
                csr.both.write_text_file(args.name)
            else:
                print("\nERROR:  Please specify --parts=split or --parts=combine")
            return




    except Exception as e:
        if "debug" in args:
            raise
        else:
            Usage()
            print("\nERROR:  "+str(e))
            return



def CommandlineMainOld():
    if len(sys.argv) < 2:
        UsageBail()
        return
    cmd = sys.argv[1].lower()
    args = ArgvArgs()

    c3m = signverify.SignVerify()


    if cmd == "make":
        if "using" not in args:
            print("'make' needs --using=<name> or --using=self, please supply")
            return

        expiry = ParseBasicDate(args.expiry)
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
        pub_ffields = textfiles.make_visible_fields(pub_block, CERT_SCHEMA, pub_ff_names)

        textfiles.write_files(args.name, pub_block, epriv_block, combine, pub_ff_lines=pub_ffields)
        return



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
        # pub_ffields = c3m.make_visible_fields(pub, APP_SCHEMA, pub_ff_names)
        textfiles.write_files(args.payload, pub, b"", combine=False)   #, pub_ff_lines=pub_ffields))
        # Note: ^^ no private part, so no combine.         ^^^ how to visible-fields for app
        return



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


# Constraints:  Year must be 4 digits
#               American month-first date format is NOT allowed
# Examples:     23/2/2022  02_02_2016  '15 October 2021' 2024-05-26  2012/jan/13  etc.

MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")

def ParseBasicDate(txt):
    m = re.match(r"^(\d{1,4})[\.\- /](\w{1,9})[\.\- /](\d{1,4})$", txt)
    if not m:
        raise ValueError('Date format is invalid. (Ok formats: 23.2.2022 2022-04-04 "15 oct 2022")')

    # --- Month ---
    smon = m.group(2)
    if smon.isalpha():
        try:
            mon = MONTHS.index(smon[:3].lower()) + 1
        except ValueError:
            raise ValueError("Invalid month name '%s'" % (smon[:3],))  # from None  # backcompat put this back in when we drop py2
    else:
        mon = int(smon)
    if mon < 1 or mon > 12:
        raise ValueError("month %d not in range 1-12" % (mon,))

    # --- Day and Year ---
    g1 = m.group(1)
    g3 = m.group(3)
    # We already know they're digits thanks to the regex.
    # Now one value must be length 4 and the other must then be length 1 or 2.
    if len(g3) == 4 and len(g1) in (1, 2):
        day = int(g1)
        year = int(g3)
    elif len(g1) == 4 and len(g3) in (1, 2):
        day = int(g3)
        year = int(g1)
    else:
        raise ValueError("Year must be 4 digits and day must be 1 or 2 digits")

    return datetime.date(day=day, month=mon, year=year)

def CheckUsageBail():
    if len(sys.argv) < 2:
        Usage()
        sys.exit(1)

def Usage(msg=""):
    help_txt = """%s
Usage:
  (usage goes here)
    """ % (msg,)
    print(help_txt)



class ArgvArgs(dict):
    def __init__(self):
        super(ArgvArgs, self).__init__()
        for arg in sys.argv:
            z = re.match(r"^--(\w+)=(.+)$", arg)
            if z:
                k, v = z.groups()
                self[k] = v
    def __getattr__(self, name):
        if name not in self:
            raise Exception("Please specify missing commandline argument   --%s="%name)
        return self[name]


