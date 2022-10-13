
import pytest, base64, traceback, random, os
from pprint import pprint

from six import int2byte

import b3
import b3.hexdump

import c3main


# test file saving/loading by round-tripping.


# test verify by exercising each error outcome.

# We're not testing ALL the StructureErrors right now, fuzz testing got a lot of them
# put the fuzzing stuff here


@pytest.fixture
def c3m():
    c3_obj = c3main.C3()
    return c3_obj


# ======== Priv Key encrypt Tests ==================================================================

# bare (not encrypted) key roundtrip
def test_privkey_bare(c3m):
    bare_priv = b"hello world"
    priv_block_bytes = c3m.make_encrypt_private_key_block(bare_priv, bare=True)
    #priv_block_bytes = priv_block_bytes[:25] + b"a" + priv_block_bytes[26:]
    privd = c3m.load_priv_block(priv_block_bytes)
    assert privd.privtype == c3main.PRIVTYPE_BARE
    assert privd.keytype == c3main.KEYTYPE_ECDSA_256P
    decrypted_priv = c3m.decrypt_private_key(privd)
    assert decrypted_priv == bare_priv

# encrypted key roundtrip using an environment variable password
def test_privkey_env_var(c3m):
    bare_priv = b"hello world"
    os.environ["C3_PASSWORD"] = "Password01!"
    priv_block_bytes = c3m.make_encrypt_private_key_block(bare_priv)
    #priv_block_bytes = priv_block_bytes[:67] + b"a" + priv_block_bytes[68:]
    privd = c3m.load_priv_block(priv_block_bytes)
    assert privd.privtype == c3main.PRIVTYPE_PASS_PROTECT
    assert privd.keytype == c3main.KEYTYPE_ECDSA_256P
    decrypted_priv = c3m.decrypt_private_key(privd)
    assert decrypted_priv == bare_priv

# glitch a privkey byte to exercise the integrity check
def test_privkey_bare_integrity(c3m):
    bare_priv = b"hello world"
    priv_block_bytes = c3m.make_encrypt_private_key_block(bare_priv, bare=True)
    priv_block_bytes = priv_block_bytes[:16] + b"a" + priv_block_bytes[17:]
    with pytest.raises(c3main.IntegrityError):
        c3m.load_priv_block(priv_block_bytes)










# ======== Verify Tests ============================================================================

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



# ======== Sign Tests ==============================================================================

#               |     no payload                  payload
#  -------------+----------------------------------------------------------
#  using cert   |     make chain signer           sign payload
#               |
#  using self   |     make self signer            ERROR invalid state


#               |     using_name                  no using_name
#  -------------+----------------------------------------------------------
#  using_pub    |     invalid                     append cert, blank name
#               |
#  no using_pub |     no append cert, link name   invalid


def test_make_selfsigned(c3m):
    # make a selfsigned then verify it and check the cert name == the sig name
    pub_part_bytes, priv_part_bytes = c3m.MakeSign(action=c3m.MAKE_SELFSIGNED, name="test1")
    c3m.add_trusted_certs(pub_part_bytes)

    chain = c3m.load(pub_part_bytes)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify
    assert chain[0].cert.name == chain[0].sig.issuer_name    # self-signed


def test_make_supply_neither_inval(c3m):
    with pytest.raises(ValueError):
        inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9")


def test_make_supply_both_inval(c3m):
    with pytest.raises(ValueError):
        inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9", using_pub=b"a", using_name="root9")
        # Note it doen't get to needing the missing using_priv


def test_make_inter_name(c3m):
    # Root cert
    root_pub, root_priv = c3m.MakeSign(c3m.MAKE_SELFSIGNED, name="root9")
    c3m.add_trusted_certs(root_pub)

    inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9", using_name="root9", using_priv=root_priv)

    chain = c3m.load(inter_pub)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify


def test_make_inter_append(c3m):
    # Root cert
    root_pub, root_priv = c3m.MakeSign(c3m.MAKE_SELFSIGNED, name="root9")
    c3m.add_trusted_certs(root_pub)

    inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9", using_pub=root_pub, using_priv=root_priv)

    chain = c3m.load(inter_pub)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify

# Note that this doesn't fail, even though we are *appending* the root9 cert itself into the chain
#      which you're not supposed to do. It succeeds because root9 is in trusted_certs and verify
#      sees that the NAME root9 is in trusted_certs so sets the found_in_trusted flag so that
#      UntrustedChainError doesn't trigger at the end.

# Note this looks like it would open us up to malicious actors appending their own cert with the same
#      NAME, but the actual signature verification step is always done, which defends against this,
#      as shown by the next test.


def test_sign_rootcert_namecollide(c3m):
    # Legit guy
    root_pub, root_priv = c3m.MakeSign(c3m.MAKE_SELFSIGNED, name="root5")
    c3m.add_trusted_certs(root_pub)
    # Attacker guy
    evil_pub, evil_priv = c3m.MakeSign(c3m.MAKE_SELFSIGNED, name="root5")   # NOTE same name
    # evil chain
    inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9", using_pub=evil_pub, using_priv=evil_priv)
    chain = c3m.load(inter_pub)
    with pytest.raises(c3main.InvalidSignatureError):
        ret = c3m.verify(chain)



def test_sign_payload(c3m):
    root_pub, root_priv = c3m.MakeSign(c3m.MAKE_SELFSIGNED, name="root9")
    c3m.add_trusted_certs(root_pub)
    inter_pub, inter_priv = c3m.MakeSign(c3m.MAKE_INTERMEDIATE, name="inter9", using_name="root9", using_priv=root_priv)

    payload = b"How are you gentlemen"
    signed_payload, should_be_none = c3m.MakeSign(c3m.SIGN_PAYLOAD, payload=payload, using_pub=inter_pub, using_priv=inter_priv)
    assert should_be_none is None

    chain = c3m.load(signed_payload)
    ret_payload = c3m.verify(chain)
    assert ret_payload == payload   # successful verify returns payload










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

# glitch a byte in the privkey block processing to ensure the decode integrity checks dont fail

def bare_glitch_loop():
    c3m = c3main.C3()
    bare_priv = b"hello world"
    priv_block_bytes = c3m.make_encrypt_private_key_block(bare_priv, bare=True)

    print("=== Known-good ===")
    print(b3.hexdump.hexdump(priv_block_bytes))
    pd = c3m.load_priv_block(priv_block_bytes)
    pprint(pd)
    print()

    for i in range(len(priv_block_bytes)):
        buf = priv_block_bytes[:i] + b"\x0f" + priv_block_bytes[i+1:]
        try:
            pd = c3m.load_priv_block(buf)
            print(i, " - Success -")
            #print(b3.hexdump.hexdump(buf))
            #pprint(pd)
            #print()
        except Exception as e:
            print(i, str(e))




if __name__ == '__main__':
    #truncmain()
    #glitchmain()
    #smallrandfuzz()
    bare_glitch_loop()



# ---- Basic fuzzing of the initial header check ----
#
# def FuzzEKH():
#     for i in range(0,255):
#         buf = six.int2byte(i) #+ b"\x0f\x55\x55"
#         try:
#             ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, buf, 0)
#             print("%4i %02x - SUCCESS - key = %r" % (i,i, ppkey))
#         except Exception as e:
#             print("%4i %02x -  %s" % (i,i, e))
#             #print(traceback.format_exc())
#
# def FuzzEKH2():
#     i = 0
#     z = {}
#     while True:
#         i += 1
#         buf = random.randbytes(20)
#         try:
#             ppkey, index = expect_key_header([KEY_LIST_PAYLOAD, KEY_LIST_SIGNER], b3.LIST, buf, 0)
#             out = "SUCCESS - key = %r" % ppkey
#         except Exception as e:
#             out = "%r" % e
#
#         #print(out)
#         z[out] = z.get(out,0) + 1
#
#         if i % 100000 == 0:
#             print()
#             print(len(z))
#             pprint(z)
