
import pytest, base64, traceback, random
from pprint import pprint

import c3main


# test file saving/loading by round-tripping.


# test verify by exercising each error outcome.

# We're not testing ALL the StructureErrors right now, fuzz testing got a lot of them
# put the fuzzing stuff here


@pytest.fixture
def c3m():
    c3_obj = c3main.C3()
    return c3_obj

# ==================================================================================================

root1 = """
2UKgAelNnAEJAUsZAQVyb290MQkCQDwdIh7DZkYyPcz+W2cBYozFZ38FanSeEHW9sSsZB+uyNiwr
etOgCKGUUzwULJVky5UOoZNaq/n79gpPhGhmVvAJAksJAUDuGhovJ49GsybchICpAa4iv1Z73T3B
03wZn9LWfqwY2PJ/uB0zjnkTt+n9kpiSdVctyyGq3/m3Doo/mzk9HI7wGQIFcm9vdDE=
"""
root1_block = base64.b64decode(root1)

plaintext_payload = b"Hello this is the actual payload\n"

payload_and_chain_wanted_name_root1 = """
2TeQAulNbAkBIUhlbGxvIHRoaXMgaXMgdGhlIGFjdHVhbCBwYXlsb2FkCgkCRQkBQMRZbYZVUowg
EJXqQpu2TiMFdHjkhKtiYSzLzQrcBkMR5LkPdvNfkxOVIp96EensA6FpkXIk+Lr2LCRE/SDF6/sV
AulNnQEJAUwZAQZpbnRlcjMJAkAbE6h1BD8t7d+K2f4tnag0Q6NNlx8MLWWMZKE4aKe3WY9Ilu5W
L+EWWq13xGDUyOp3OK4QhbkS0+1Iw2TswTchCQJLCQFAGJE1krY0/RjkNtp0ETrMr2Kko8Dz+/1s
0axfU2jfwBGf5HkSagtkfWNTDkdBDTShKvQq2qwHeBdhsLHs8jDTthkCBXJvb3Qx"""
public_part = base64.b64decode(payload_and_chain_wanted_name_root1)

# Happy path
def test_verify_success_ext_root1(c3m):
    c3m.add_trusted_certs(root1_block)
    ret = c3m.verify(c3m.load(public_part))
    assert ret == plaintext_payload


# Glitch the payload contents so the signature fails to verify
def test_verify_signature_fail(c3m):
    public_part_glitched = public_part[:100] + b"X" + public_part[101:]
    with pytest.raises(c3main.InvalidSignatureError):
        c3m.verify(c3m.load(public_part_glitched))


# Apart from actual signature fails, there are 3 ways for this to fail:
# 1) "fell off" - unnamed issuer cert and no next cert in line ("short chain")
# 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
# 3) Last cert is self-signed and verified OK but isn't in the trust store.

# cut inter2 off the end of payload_and_chain_with_wanted_name
# to trigger "next cert is the signer but there is no next cert" failure mode
# Don't need root1 loaded because it doesn't get that far
def test_verify_short_chain(c3m):
    public_part_without_inter2 = public_part[:115]
    with pytest.raises(c3main.ShortChainError):
        c3m.verify(c3m.load(public_part_without_inter2))


# Without loading root1 to trusted store first
def test_verify_cert_not_found_error(c3m):
    with pytest.raises(c3main.CertNotFoundError):
        c3m.verify(c3m.load(public_part))



payload_and_chain_with_root_selfsigned_included = """
2TeqA+lNbAkBIUhlbGxvIHRoaXMgaXMgdGhlIGFjdHVhbCBwYXlsb2FkCgkCRQkBQFlmCSMzBHj3
HWLE1wyBPqBPVG7JQZfFShkqkcOCtEjee/Ym75Lnrrv49/QMk3y0TZ382HybAnoKXwBFlF5IkhsV
AulNlwEJAUwZAQZpbnRlcjcJAkAMX0xJJzbctIHyOhMqPBELJY5akzaVcplupxywc0WrR1RISwEe
z2JRLbcHMc3/fepsPtDCr4IRB0VXEq7PXVQuCQJFCQFAj4cmxJWQB2ecnpAscrvRXPHTuqjOlRh0
GIn7+PNEDtDcOYJ7LL/HxQ/V4twpiWBwE/KHKDCMVMeWXHisQsENDBUC6U2cAQkBSxkBBXJvb3Qy
CQJAdOodJNyKdMdsa+ujdomof7CfdNuYd9DjnxnLQObPQdrTx1qS7bopuhNrGkHqrIaSnx+SllM0
5ZJH0zSwTNqiBwkCSwkBQDTSV4tAi1DpIBP98lY1QMoLdAUtjaUa0PwtB/wvQZEyiXYcMA/FCw2g
WSHT72yY49AFS5dQ13v4538RaTD6c5wZAgVyb290Mg=="""

# a fully valid chain with a selfsign at the end, should still fail with UntrustedChainError
def test_verify_untrusted_chain(c3m):
    public_part_selfsign_incl = base64.b64decode(payload_and_chain_with_root_selfsigned_included)
    with pytest.raises(c3main.UntrustedChainError):
        c3m.verify(c3m.load(public_part_selfsign_incl))


# ---- Test load error handling ----

def test_load_empty(c3m):
    with pytest.raises(c3main.StructureError):
        c3m.load(b"")

def test_load_none(c3m):
    with pytest.raises(c3main.StructureError):
        c3m.load(None)

def test_load_nulls(c3m):
    with pytest.raises(c3main.StructureError):
        c3m.load(b"\x00\x00\x00\x00\x00\x00\x00\x00")




# ---- Truncate and glitch loops -----

# Testing what happens if the public_part buffer is incomplete
# (And finding out exactly where to truncate public_part for the short-chain test above)

def truncmain():
    c3m = c3main.C3()
    c3m.add_trusted_certs(root1_block)
    buf = public_part[:]

    for i in range(len(buf)+1, 1, -1):
        buf2 = buf[:i]
        try:
            xx = c3m.load(buf2)
        except Exception as e:
            # print("%4i    load   %20s" % (i,e))
            continue
        try:
            c3m.verify(xx)
        except Exception as e:
            print("%4i  verify   %r" % (i,e))
            continue
        print("%4i   - SUCCESS -" % (i,))


# glitch a byte anywhere? in the chain to trigger signature fails.

def glitchmain():
    c3m = c3main.C3()
    c3m.add_trusted_certs(root1_block)
    buf = public_part[:]

    for i in range(len(buf)):
        buf2 = buf[:i] + b"\x00" + buf[i+1:]
        try:
            xx = c3m.load(buf2)
        except Exception as e:
            print("%4i    load   %20s" % (i,e))
            if "index out of" in str(e):
                print()
                print(traceback.format_exc())
                print()
            continue
        try:
            c3m.verify(xx)
        except Exception as e:
            print("%4i  verify   %r" % (i,e))
            continue
        print("%4i   - SUCCESS -" % (i,))

def smallrandfuzz():
    c3m = c3main.C3()
    z = {}
    i = 0
    while True:
        i += 1
        buf = random.randbytes(40)
        #buf = b"\xdd\x37\x40\xed\x4d\x30\x44" + random.randbytes(60)
        try:
            xx = c3m.load(buf)
            out = "omg SUCCESS omg"
        except Exception as e:
            out = str(e)
        z[out] = z.get(out,0) + 1

        if i % 100000 == 0:
            print()
            pprint(z)
            return





if __name__ == '__main__':
    #truncmain()
    #glitchmain()
    smallrandfuzz()
