


# --- Errors ---
class C3Error(ValueError):
    pass
class StructureError(C3Error):  # something wrong with the data/binary structure; misparse, corrupt
    pass
class IntegrityError(StructureError):  # the crc32 in the privkey block doesn't match block contents
    pass
class VerifyError(C3Error):     # parent error for failures in the verification process
    pass
class InvalidSignatureError(VerifyError):   # cryptographic signature failed verification
    pass
class CertNotFoundError(VerifyError):   # chain points to a cert name we dont have in Trusted
    pass
class ShortChainError(VerifyError):  # the next cert for verifying is missing off the end
    pass
class UntrustedChainError(VerifyError):  # the chain ends with a self-sign we dont have in Trusted
    pass
class TamperError(VerifyError):     # Friendly Fields are present in the textual file,
    pass                             #   but don't match up with the secure fields
class SignError(C3Error):
    pass
class CertExpired(SignError):       # can't sign, --using's cert has expired.
    pass

