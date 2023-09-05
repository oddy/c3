
# Compact Crypto Certs (C3) Public API

__version__ = "1.1.0"

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



