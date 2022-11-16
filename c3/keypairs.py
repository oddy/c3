
import ecdsa

from c3.constants import KT_ECDSA_PRIME256V1
from c3.errors import SignError


# NIST P-256 aka secp256r1 aka prime256v1

def generate(keytype):
    if keytype not in (KT_ECDSA_PRIME256V1,):
        raise NotImplementedError("Error generating keypair - unknown keytype")
    curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
    priv = ecdsa.SigningKey.generate(curve=curve)
    pub = priv.get_verifying_key()
    return priv.to_string(), pub.to_string()

def sign_make_sig(keytype, priv_bytes, payload_bytes):
    if keytype not in (KT_ECDSA_PRIME256V1,):
        raise NotImplementedError("Error signing payload - unknown keytype")
    SK = ecdsa.SigningKey.from_string(priv_bytes, ecdsa.NIST256p)
    sig_bytes  = SK.sign(payload_bytes)
    return sig_bytes

def verify(cert, payload_bytes, signature_bytes):
    if cert.key_type not in (KT_ECDSA_PRIME256V1,):
        print("OH NO " +"* " *120)
        raise NotImplementedError("Error verifying payload - unknown keytype")
    VK = ecdsa.VerifyingKey.from_string(cert.public_key, ecdsa.NIST256p)
    return VK.verify(signature_bytes, payload_bytes)  # returns True or raises exception

def check_privpub_match(cert, priv_key_bytes):
    if cert.key_type not in (KT_ECDSA_PRIME256V1,):
        raise NotImplementedError("Error verifying payload - unknown keytype")
    priv = ecdsa.SigningKey.from_string(priv_key_bytes, ecdsa.NIST256p)
    pub = priv.get_verifying_key()
    if pub.to_string() != cert.public_key:
        raise SignError("Private key and public key do not match")
    return True
