
# SignVerify Public API

__version__ = "0.9.0"

from c3.constants import *
from c3.errors import *
from c3 import signverify
from c3 import structure
from c3 import textfiles

# quick-start APIs for verifying
from c3.textfiles import pub_block_from_string
from c3.signverify import SignVerify

# "note: __all__ affects the from <module> import * behavior only."
# In theory these two things are all that is needed to code up a verifier.
__all__ = [
    "pub_block_from_string",
    "SignVerify"
]

