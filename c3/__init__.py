
# Compact Crypto Certs (C3) Public API

__version__ = "0.9.3a1"


from c3.constants import *
from c3.errors import *
from c3 import signverify
from c3 import structure
from c3 import textfiles

# quick-start APIs for verifying
from c3.textfiles import pub_block_from_string, make_pub_txt_str
from c3.signverify import SignVerify

# "note: __all__ affects the from <module> import * behavior only."
# In theory these two things are all that is needed to code up a verifier.
__all__ = [
    "pub_block_from_string",
    "SignVerify"
]


# Future todos:
# - CSR workflow, creating a cert with --using=None
# - py2 support (b3 utf8, base64 encodebytes, p_p pathlib2, more?)
# - more key types e.g. libsodium

