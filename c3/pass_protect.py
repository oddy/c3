
# This is used by C3 privcrypt, but is seperate and distinct code currently

import sys, os, ctypes, itertools, logging, platform
try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path

from b3 import encode_uvarint, decode_uvarint

# Password protection for private keys (or whatever else)
# WE are payload agnostic - dont care about key_types etc - all that stuff is the Caller's problem
# We're stealing most of this from qsafiles socrypt.


# Binary format: [salt sz][xpayload sz][salt][num-passes][xpayload][xpayload][xpayload]...

class DecryptFailed(Exception):     pass        # can interpret as Incorrect Password

class PassProtect(object):
    def __init__(s, libsodium_dir=''):
        s.log = logging.getLogger('passprot')
        s.sodium = None
        s.LoadSodium(libsodium_dir)
        s.crypto_secretbox_KEYBYTES     = s.sodium.crypto_secretbox_keybytes()
        s.crypto_secretbox_NONCEBYTES   = s.sodium.crypto_secretbox_noncebytes()
        s.crypto_secretbox_ZEROBYTES    = s.sodium.crypto_secretbox_zerobytes()
        s.crypto_secretbox_BOXZEROBYTES = s.sodium.crypto_secretbox_boxzerobytes()
        s.crypto_pwhash_SALTBYTES       = s.sodium.crypto_pwhash_saltbytes()
        s.NONCE_LEN = s.crypto_secretbox_NONCEBYTES


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
        if salt_len != s.crypto_pwhash_SALTBYTES:   raise TypeError('salt is incorrect length')     # sanity
        salt = buf[idx:idx+salt_len]
        idx += salt_len
        xpayloads = [buf[i: i + xpayload_len] for i in range(idx, len(buf), xpayload_len)]
        return num_passes, salt, xpayloads


    # --- One password ---
    def SinglePassEncrypt(s, payload, passw):
        if not isinstance(payload, bytes):  raise TypeError('invalid payload for pass encrypt')
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
        nump,salt,xpayloads = s.Unpack(buf)     # only ever 1 payload rly
        pass_key = s.PwToKey(passw, salt)
        payload  = s.RawKeyDecrypt(pass_key, xpayloads[0])
        return payload

    def DualPassDecrypt(s, buf, passes):
        nump,salt,xpayloads = s.Unpack(buf)
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



    # ====================== BEGIN copy pasta from socrypt ===============================
    # ====================== BEGIN copy pasta from socrypt ===============================

    def LoadSodium(s, libsodium_dir=''):
        # --- Load libsodium dll ---
        base = "libsodium"
        bit_expl = "_64" if sys.maxsize > 2 ** 32 else "_32"
        ext = {"Darwin": "dylib", "Windows": "dll", "Linux": "so"}[platform.system()]
        # todo: ^^ test linux

        # dir is 1) explicit (e.g. apiweb.py bc w3wp.exe), 2) blank->current dir (dev/tool scripts), 3) appdir if frozen exe (prod EXEs)
        if not libsodium_dir and hasattr(sys, "frozen"):
            libsodium_dir = os.path.abspath(os.path.dirname(sys.executable))

        # try for _32 or _64 first, fall back to standard if they are not found.
        try_names = ["%s%s.%s" % (base, bit_expl, ext), "%s.%s" % (base, ext)]

        for try_name in try_names:
            path = Path(libsodium_dir) / try_name  # '' = current dir for libsodium_dir
            s.log.debug(" trying libsodium dll %r", path.as_posix())
            if path.is_file():
                full_path = path.resolve().as_posix()
                s.log.debug("loading libsodium dll path %r", full_path)
                s.sodium = ctypes.CDLL(full_path)
                break
        else:
            raise IOError("No libsodium dll file found")
        s.log.debug("libsodium load ok")

    def RandomBytes(s, size):
        buf = ctypes.create_string_buffer(size)
        s.sodium.randombytes(buf, ctypes.c_ulonglong(size))
        return buf.raw

    def GetPwSalt(s):
        return s.RandomBytes( s.crypto_pwhash_SALTBYTES )

    def RawKeyEncrypt(s, key, data):                    # These wont be available on HSMed CryptoBases, obviously. Currently only the PasswordAccess-er needs them i think.
        # print 'ENC key  ',repr(key)
        # print 'ENC data ',repr(data[:100])
        if not data:                                    raise ValueError('Missing data for secret_box encrypt')

        nonce   = s.RandomBytes(s.NONCE_LEN)
        padded  = (b"\x00" * s.crypto_secretbox_ZEROBYTES) + data
        out_buf = ctypes.create_string_buffer(len(padded))

        ret = s.sodium.crypto_secretbox(out_buf, padded, ctypes.c_ulonglong(len(padded)), nonce, key)

        if ret != 0:                                    raise ValueError('secret_box encrypt failed (%d)' % (ret))
        xdata = out_buf.raw[s.crypto_secretbox_BOXZEROBYTES:]
        return nonce + xdata

    def RawKeyDecrypt(s, key, xdata):
        nonce   = xdata[:s.NONCE_LEN]
        xdata   = xdata[s.NONCE_LEN:]
        if not xdata:                                   raise ValueError('Missing data for secret_box_open decrypt')

        padded  = b"\x00" * s.crypto_secretbox_BOXZEROBYTES + xdata
        out_buf = ctypes.create_string_buffer(len(padded))

        ret = s.sodium.crypto_secretbox_open(out_buf, padded, ctypes.c_ulonglong(len(padded)), nonce, key)

        # if ret != 0:                                    raise ValueError('secret_box_open decrypt failed (%d)' % (ret))
        if ret != 0:                                    raise DecryptFailed('secret_box_open decrypt failed (%d)' % (ret))
        data = out_buf.raw[s.crypto_secretbox_ZEROBYTES:]
        return data

    def PwToKey(s, password, salt):
        if len(salt) != s.crypto_pwhash_SALTBYTES:        raise ValueError("PwToKey invalid salt length")
        password = password.encode('utf-8')               # libsodium itself wants bytes, presumably

        key_out_len     = s.sodium.crypto_auth_keybytes()
        key_out_len_c   = ctypes.c_ulonglong( key_out_len                                           )
        hash_algo_c     = ctypes.c_int(       s.sodium.crypto_pwhash_alg_argon2i13()                )
        ops_limit_c     = ctypes.c_ulonglong( s.sodium.crypto_pwhash_argon2i_opslimit_interactive() )    # interactive, moderate, sensitive
        mem_limit_c     = ctypes.c_size_t(    s.sodium.crypto_pwhash_argon2i_memlimit_interactive() )
        len_password_c  = ctypes.c_ulonglong( len(password)                                         )
        out_buf         = ctypes.create_string_buffer(key_out_len)

        ret = s.sodium.crypto_pwhash(ctypes.byref(out_buf), key_out_len_c, password, len_password_c, salt, ops_limit_c, mem_limit_c, hash_algo_c)

        if ret != 0:                                    raise ValueError('crypto_pwhash failed (%d)' % (ret))
        return out_buf.raw


    # ====================== END copy pasta from socrypt ===============================
    # ====================== END copy pasta from socrypt ===============================

# Pretty sure at this point that the encrypted payloads WILL be uniform:
# if not all([plen == len(i) for i in xpayloads]):  raise ValueError('payload lengths not uniform')

def test_1_pass():
    pp = PassProtect()
    passw   = 'hello'
    payload = 'hello world'
    buf  = pp.SinglePassEncrypt(payload, passw)
    pay2 = pp.SinglePassDecrypt(buf, passw)
    assert pay2 == payload

def test_2_pass():
    pp = PassProtect()
    passes  = ['foo','bar','baz','troz','zort']
    passes2 = ['foo','baz']
    payload = 'hello world'
    buf     = pp.MultiPassEncrypt(payload, passes)
    pay2    = pp.DualPassDecrypt(buf, passes2)
    assert pay2 == payload


if __name__ == '__main__':
    #while True:
    test_2_pass()

