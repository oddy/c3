
# Compact Crypto Certs (C3) Public API

__version__ = "1.1.3"

# 1.1.3 Text loading correctly handles windows CRLFs
# 1.1.2 Commandline file loading is simpler and more explicit now
# 1.1.1 Ability for Verify commandline to specify multiple --trusted to simulate multiple certs
#       being loaded into a trust store.
# 1.1.0 Added NaCl-sign keytype (is default keytype now). pass_protect now uses pynacl.
# 1.0.8 Initial release

from c3.errors import *
from c3.signverify import SignVerify
from c3.parsedate import ParseBasicDate

# "note: __all__ affects the from <module> import * behavior only."
__all__ = [
    "SignVerify"
]

# Future todos:
# - dual/multi passwords for private keys
# - Visible Fields support for PRIV_CRCWRAP_SCHEMA
# - it would be nice if the text description included whether things were CSRs etc
# - add --expiry override to sign for Renew operations.


