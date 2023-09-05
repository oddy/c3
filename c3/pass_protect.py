
# This is used by C3 privcrypt, but is seperate and distinct code currently

import itertools, logging
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

from b3 import encode_uvarint, decode_uvarint

import nacl.utils
import nacl.secret
import nacl.pwhash
from nacl.pwhash.argon2i import OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE, SALTBYTES

# Password protection for private keys (or whatever else)
# WE are payload agnostic - dont care about key_types etc - all that stuff is the Caller's problem

# Binary format: [salt sz][xpayload sz][salt][num-passes][xpayload][xpayload][xpayload]...

class DecryptFailed(Exception):     pass        # can interpret as Incorrect Password

class PassProtect(object):
    def __init__(s):
        s.log = logging.getLogger('passprot')

    # passes is a list of passwords. We might make it a dict with tags (quasi-usernames) later.
    # we dont actually enforce any policy on how many passes, but do all 2-combos if > 1
    # It's up to the caller to enforce stuff like "this is a root key, it needs more than 1 password" etc.

    # we pack: Salt, number of passwords used, & list of encrypted payloads.
    # Binary format: [salt sz][xpayload sz][salt][num-passes][xpayload][xpayload][xpayload]...
    # (num passes because otherwise theres no way to tell diff between 1 and 2 passwords - both product 1 payload)
    # but WE dont care about key types etc, thats the caller's problem.

    def Pack(s, num_passes, salt, xpayloads):
        plen = len(xpayloads[0])
        return encode_uvarint(num_passes) + encode_uvarint(len(salt)) + encode_uvarint(plen) + salt + b''.join(xpayloads)

    def Unpack(s, buf):
        idx = 0
        num_passes,idx   = decode_uvarint(buf, idx)
        salt_len,idx     = decode_uvarint(buf, idx)
        xpayload_len,idx = decode_uvarint(buf, idx)
        if salt_len != SALTBYTES:   raise TypeError('salt is incorrect length')     # sanity
        salt = buf[idx:idx+salt_len]
        idx += salt_len
        xpayloads = [buf[i: i + xpayload_len] for i in range(idx, len(buf), xpayload_len)]
        return num_passes, salt, xpayloads


    # --- One password ---
    def SinglePassEncrypt(s, payload, passw):
        if not isinstance(payload, bytes):
            raise TypeError('invalid payload for pass encrypt')
        salt = s.GetPwSalt()
        pass_key = s.PwToKey(passw, salt)
        xpayload = s.RawKeyEncrypt(pass_key, payload)
        return s.Pack(1, salt, [xpayload])

    # --- 2-password combos for N passwords ---
    def MultiPassEncrypt(s, payload, passes):
        if not isinstance(payload, bytes):  raise TypeError('invalid payload for pass encrypt')
        if not isinstance(passes, list):    raise TypeError('passes must be a list')
        salt = s.GetPwSalt()
        pass_keys = []
        for ia,ib in itertools.combinations(passes, 2):
            concat_pass = ''.join(sorted([ia, ib]))
            pass_keys.append(s.PwToKey(concat_pass, salt))
        xpayloads = [s.RawKeyEncrypt(pass_key, payload) for pass_key in pass_keys]
        return s.Pack(len(passes), salt, xpayloads)

    # UX flow - take buf, call DualPasswordsNeeded, use that to throw up the appropriate user forms
    #           then call SinglePassdecrypt or MultiPassDecrypt accordingly.

    def DualPasswordsNeeded(s, buf):
        num_passes,_,_ = s.Unpack(buf)
        return num_passes > 1

    def SinglePassDecrypt(s, buf, passw):
        nump, salt, xpayloads = s.Unpack(buf)     # only ever 1 payload rly
        pass_key = s.PwToKey(passw, salt)
        payload  = s.RawKeyDecrypt(pass_key, xpayloads[0])
        return payload

    def DualPassDecrypt(s, buf, passes):
        nump, salt, xpayloads = s.Unpack(buf)
        concat_pass = ''.join(sorted(passes))
        pass_key = s.PwToKey(concat_pass, salt)
        # --- try each payload in turn ---
        for xpayload in xpayloads:
            try:
                payload = s.RawKeyDecrypt(pass_key, xpayload)
                return payload
            except Exception as e:
                continue
        raise ValueError('incorrect passwords')

    # --- PyNacl ---

    def RawKeyEncrypt(s, key, data):
        sb = nacl.secret.SecretBox(key)
        return sb.encrypt(data)

    def RawKeyDecrypt(s, key, xdata):
        sb = nacl.secret.SecretBox(key)
        return sb.decrypt(xdata)

    def PwToKey(s, password, salt):
        kdf = nacl.pwhash.argon2i.kdf
        key = kdf(nacl.secret.SecretBox.KEY_SIZE, password.encode(), salt, opslimit=OPSLIMIT_INTERACTIVE, memlimit=MEMLIMIT_INTERACTIVE)
        return key

    def GetPwSalt(s):
        return nacl.utils.random(nacl.pwhash.argon2i.SALTBYTES)

