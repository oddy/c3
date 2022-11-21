
import ecdsa

# Note that this is python ecdsa library-centric atm, but can easily be extended to support other
#      keys from other libraries

from c3.constants import KT_ECDSA_PRIME256V1, KT_ECDSA_SECP256K1
from c3.errors import SignError

# NIST P-256 aka secp256r1 aka prime256v1
# SECP256k1 aka the bitcoin one

# --- C3 curve constants to python ecdsa library curve objects ---
C3_KT_TO_PY_ECDSA_CURVE = {
    KT_ECDSA_PRIME256V1 : ecdsa.NIST256p,
    KT_ECDSA_SECP256K1  : ecdsa.SECP256k1,
}

def c3keytype_to_ecdsa_curve(keytype, task_msg):
    if keytype not in C3_KT_TO_PY_ECDSA_CURVE:
        raise NotImplementedError("Error %s - unknown keytype" % (task_msg,))
    return C3_KT_TO_PY_ECDSA_CURVE[keytype]


def generate(keytype):
    curve = c3keytype_to_ecdsa_curve(keytype, "generating keypair")
    priv = ecdsa.SigningKey.generate(curve=curve)
    pub = priv.get_verifying_key()
    return priv.to_string(), pub.to_string()

def sign_make_sig(keytype, priv_bytes, payload_bytes):
    curve = c3keytype_to_ecdsa_curve(keytype, "signing payload")
    SK = ecdsa.SigningKey.from_string(priv_bytes, curve)
    sig_bytes = SK.sign(payload_bytes)
    return sig_bytes

def verify(cert, payload_bytes, signature_bytes):
    curve = c3keytype_to_ecdsa_curve(cert.key_type, "verifying payload")
    VK = ecdsa.VerifyingKey.from_string(cert.public_key, curve)
    return VK.verify(signature_bytes, payload_bytes)  # returns True or raises exception

def check_privpub_match(cert, priv_key_bytes):
    curve = c3keytype_to_ecdsa_curve(cert.key_type, "checking keypair match")
    priv = ecdsa.SigningKey.from_string(priv_key_bytes, curve)
    pub = priv.get_verifying_key()
    if pub.to_string() != cert.public_key:
        raise SignError("Private key and public key do not match")
    return True

