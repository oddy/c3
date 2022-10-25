
# C3 Private key encryption/decryption

from c3.constants import *
from c3.errors import StructureError
from c3 import pass_protect
from c3 import getpassword

# NOTE that these interact with the user (password entry)
#         and use a pass_protect object which needs startup initialisation (load libsodium)

# Note: (pass_protect) loads libsodium on startup, which is why this is a class.

# This class is used by commandline, and is a user of pass_protect

class PrivCrypt(object):
    def __init__(self):
        # We need to load libsodium on startup if it is there. But also support cases where it's
        # not available (e.g.bare keys)
        self.load_error = None
        self.pass_protect = None
        try:
            self.pass_protect = pass_protect.PassProtect()
        except OSError as e:         # No libsodium dll found
            self.load_error = "Starting pass_protect: "+str(e)

    # In:  private key bytes  (and possibly user entering a password interactively)
    # Out: encrypted private key bytes

    def encrypt_private_key(self, priv_bytes):
        if not self.pass_protect:
            raise RuntimeError(self.load_error)
        prompt1 = "Private  key encryption password: "
        prompt2 = "Re-enter key encryption password: "
        passw = getpassword.get_double_enter_setting_password(prompt1, prompt2)
        if not passw:
            raise ValueError("No password supplied, exiting")
        epriv_bytes = self.pass_protect.SinglePassEncrypt(priv_bytes, passw)
        return epriv_bytes

    # In: dict from load_priv_block
    # Out: private key bytes for make_sign to use

    def decrypt_private_key(self, privd):
        if privd.priv_type == PRIVTYPE_BARE:
            return privd.priv_data
        if privd.priv_type != PRIVTYPE_PASS_PROTECT:
            raise StructureError \
                ("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
        if not self.pass_protect:       # usually because could not find libsodium DLL
            raise RuntimeError(self.load_error)
        if self.pass_protect.DualPasswordsNeeded \
                (privd.priv_data):  # todo: we dont support this here yet
            raise NotImplementedError("Private key wants dual passwords")

        # --- Try password from environment variables ---
        passw = getpassword.get_env_password()
        if passw:
            priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            # Note exceptions are propagated right out here, its an exit if this decrypt fails.
            return priv_ret

        # --- Try password from user ---
        prompt = "Password to unlock private key: "
        priv_ret = b""
        while not priv_ret:
            passw = getpassword.get_enter_password(prompt)
            if not passw:
                raise ValueError("No password supplied, exiting")

            try:
                priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            except Exception as e:
                print("Failed decrypting private key: ", str(e))
                continue        # let user try again
        return priv_ret

