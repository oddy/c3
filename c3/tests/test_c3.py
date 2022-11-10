
from __future__ import unicode_literals     # for python2

import base64, traceback, random, os, datetime
from pprint import pprint

import pytest

pytestmark = pytest.mark.skipif(True, reason="Skipping old tests")       # skip all tests in here

import b3.hexdump

from c3.constants import *
from c3.errors import *
from c3.signverify import SignVerify
from c3 import structure
from c3 import textfiles

@pytest.fixture
def c3m():
    c3_obj = SignVerify()
    return c3_obj


# ======== Priv Key encrypt Tests ==================================================================

# bare (not encrypted) key roundtrip
def test_privkey_bare(c3m):
    bare_priv = b"hello world"
    priv_block_bytes = structure.make_priv_block(bare_priv, bare=True)
    privd = structure.load_priv_block(priv_block_bytes)
    assert privd.priv_type == PRIVTYPE_BARE
    assert privd.key_type == KT_ECDSA_PRIME256V1
    decrypted_priv = c3m.decrypt_private_key(privd)     # should pass bare through
    assert decrypted_priv == bare_priv

# encrypted key roundtrip using an environment variable password
def test_privkey_env_var(c3m):
    bare_priv = b"hello world"
    os.environ["C3_PASSWORD"] = "Password01!"
    epriv = c3m.encrypt_private_key(bare_priv)
    priv_block_bytes = structure.make_priv_block(epriv)   # bare=False is the default

    privd = structure.load_priv_block(priv_block_bytes)
    assert privd.priv_type == PRIVTYPE_PASS_PROTECT
    assert privd.key_type == KT_ECDSA_PRIME256V1
    decrypted_priv = c3m.decrypt_private_key(privd)
    assert decrypted_priv == bare_priv

# glitch a privkey byte to exercise the integrity check
def test_privkey_bare_integrity(c3m):
    bare_priv = b"hello world"
    priv_block_bytes = structure.make_priv_block(bare_priv, bare=True)
    priv_block_bytes = priv_block_bytes[:16] + b"a" + priv_block_bytes[17:]
    with pytest.raises(IntegrityError):
        structure.load_priv_block(priv_block_bytes)

# Run me from TOP top level with: "python -m c3.tests.test_c3"

def interactive_password_test():        # note: not a pytest test
    c3m = SignVerify()
    bare_priv = b"hello world"
    print("- Encrypt & pack - ")
    epriv = c3m.encrypt_private_key(bare_priv)
    priv_block_bytes = structure.make_priv_block(epriv)
    if not priv_block_bytes:        # or exception?
        print(" - user abort -")
        return
    print("- load & decrypt - ")
    print(repr(priv_block_bytes))

    pd = structure.load_priv_block(priv_block_bytes)
    de_priv = c3m.decrypt_private_key(pd)
    if de_priv == bare_priv:
        print("SUCCESS - roundtripped key matches original")
    else:
        print("FAIL - roundtripped key does not match original")



# ======== Verify Tests ============================================================================

# Made with:  python commandline.py make --name="root1" --using=self --expiry=2022-09-09
root1 = """
2UK6AelNtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQMg/+gyc/F3JZs4rY6ya5d9cPdWd6Sjs
OD3UsENAitTCGrY0fceRKrndJKyXsVwOhwe2lUpmidVytXzAundMMWmpBAQJCcwfqQUEFgrMHwkB
SwkAQOe/rz9mLoBLLRCpFEr+emsHEvcH73vZislzpwqBHxD+tV23QFmTMjsJzKsPOQmmYOxMkH/U
EbKFB4gzSK0aT/EJAQVyb290MQ==
"""
root1_block = base64.b64decode(root1)

plaintext_payload = b"Hello this is the actual payload\n"

payload_and_inter2_wanted_name_root1 = """
2TerAulNbAkAIUhlbGxvIHRoaXMgaXMgdGhlIGFjdHVhbCBwYXlsb2FkCgkBRQkAQH510LkxZEZJ
Az8n/j0GRhSdyrnvudPhZ08GXUkltKZUIP2cMiNfQhiuLDvgbVho5zJZVrIrdSQEJU0xbYsZLWIB
AelNuAEJAGcJAAZpbnRlcjIZAQZpbnRlcjI5AgEBCQNAJnKBsUN6eOud943dJotzVG5RJtxCBfMr
ZUb7lPv9c1dxoMEFWQHBdotULByW1RtZkCZNE5pAx3Ll3gOyBD4keakEBBcJzB+pBQQWCswfCQFL
CQBA2w6v9I6uaICQ5V1d4R8Tsui/pLq45V2Rg7jNx1mypYXHDaQzpvrCbf/lR2Z9OgpTH8vmBafy
DYlgh26lpIO5HAkBBXJvb3Qx
"""
public_part = base64.b64decode(payload_and_inter2_wanted_name_root1)

def test_add_trusted_root1(c3m):
    c3m.add_trusted_certs(root1_block)


# Happy path
def test_verify_success_ext_root1(c3m):
    c3m.add_trusted_certs(root1_block)
    ret = c3m.verify(structure.load_pub_block(public_part))
    assert ret is True

# payload extractor & meta-data chain maker

def test_get_meta_root1(c3m):
    chain = structure.load_pub_block(root1_block)
    assert chain[0].cert.cert_id == b"root1"
    assert chain[0].sig.signing_cert_id == b"root1"
    # Meta is just chain without all the big-bytesy things so it's nicer to pprint()
    meta = structure.get_meta(chain)
    assert meta[0].cert.cert_id == b"root1"
    assert meta[0].sig.signing_cert_id == b"root1"

def test_get_meta_payload(c3m):
    chain = structure.load_pub_block(public_part)
    meta = structure.get_meta(chain)
    assert len(meta) == 1
    assert meta[0].cert.cert_id == b"inter2"
    assert meta[0].sig.signing_cert_id == b"root1"

def test_get_payload_root1(c3m):
    chain = structure.load_pub_block(root1_block)
    payload = structure.get_payload(chain)
    assert payload == b""

def test_get_payload_payload(c3m):
    chain = structure.load_pub_block(public_part)
    payload = structure.get_payload(chain)
    assert payload == plaintext_payload





# Glitch the payload contents so the signature fails to verify
def test_verify_signature_fail(c3m):
    public_part_glitched = public_part[:100] + b"X" + public_part[101:]
    with pytest.raises(InvalidSignatureError):
        c3m.verify(structure.load_pub_block(public_part_glitched))


# Apart from actual signature fails, there are 3 ways for this to fail:
# 1) "fell off" - unnamed issuer cert and no next cert in line ("short chain")
# 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
# 3) Last cert is self-signed and verified OK but isn't in the trust store.

# cut inter2 off the end of payload_and_chain_with_wanted_name
# to trigger "next cert is the signer but there is no next cert" failure mode
# Don't need root1 loaded because it doesn't get that far
def test_verify_short_chain(c3m):
    public_part_without_inter2 = public_part[:115]
    with pytest.raises(ShortChainError):
        c3m.verify(structure.load_pub_block(public_part_without_inter2))


# Without loading root1 to trusted store first
def test_verify_cert_not_found_error(c3m):
    with pytest.raises(CertNotFoundError):
        c3m.verify(structure.load_pub_block(public_part))



payload_and_chain_with_root_selfsigned_included = """
2TffA+lNbAkAIUhlbGxvIHRoaXMgaXMgdGhlIGFjdHVhbCBwYXlsb2FkCgkBRQkAQEm0pCEzDFCz
ZQ30w/HbGOXAO+VA9h/EzUdE1lZCqpOnRF3yDwjyXukQvUP8nAhBN7u/gRzy0lkS80BqjpFQ74kB
AelNsgEJAGcJAAZpbnRlcjMZAQZpbnRlcjM5AgEBCQNAYL5PIvF/unXMHSQrqtmdYxMS0R2gv5mg
AdViuQxCA8mTU2hlvqLrdlNuFFxNdOQ77z03EOwpyJMeD3TJ8kJM0akEBBcJzB+pBQQWCswfCQFF
CQBAgKHkaHcq4cDgpVhOccTOqouUKCZtF9gbaAESuHu2E7Oyj0rjXBVTiiBqw9zsOi8Gw7JiGWwJ
TiyR0qThWHHowQEB6U22AQkAZQkABXJvb3QxGQEFcm9vdDE5AgEBCQNAyD/6DJz8XclmzitjrJrl
31w91Z3pKOw4PdSwQ0CK1MIatjR9x5Equd0krJexXA6HB7aVSmaJ1XK1fMC6d0wxaakEBAkJzB+p
BQQWCswfCQFLCQBA57+vP2YugEstEKkUSv56awcS9wfve9mKyXOnCoEfEP61XbdAWZMyOwnMqw85
CaZg7EyQf9QRsoUHiDNIrRpP8QkBBXJvb3Qx
"""

# a fully valid chain with a selfsign at the end, should still fail with UntrustedChainError
def test_verify_untrusted_chain(c3m):
    public_part_selfsign_incl = base64.b64decode(payload_and_chain_with_root_selfsigned_included)
    with pytest.raises(UntrustedChainError):
        c3m.verify(structure.load_pub_block(public_part_selfsign_incl))


# ---- Test load error handling ----

def test_load_empty(c3m):
    with pytest.raises(StructureError):
        structure.load_pub_block(b"")

def test_load_none(c3m):
    with pytest.raises(StructureError):
        structure.load_pub_block(None)

def test_load_nulls(c3m):
    with pytest.raises(StructureError):
        structure.load_pub_block(b"\x00\x00\x00\x00\x00\x00\x00\x00")


# ======== visible Fields Tests ===================================================================


def test_make_ff_list(c3m):
    pub_part = base64.b64decode(root1)
    field_names = ("subject_name", "expiry_date")
    lines_str = textfiles.make_visible_fields(pub_part, CERT_SCHEMA, field_names)
    assert lines_str == '[ Subject Name ]  root1\n[ Expiry Date  ]  9 September 2022'

def test_make_ff_map(c3m):
    pub_part = base64.b64decode(root1)
    field_names = (("subject_name", "Subject Name 2"), "expiry_date")
    lines_str = textfiles.make_visible_fields(pub_part, CERT_SCHEMA, field_names)
    assert lines_str == '[ Subject Name 2 ]  root1\n[ Expiry Date    ]  9 September 2022'



ff_root1_pub_text = """
--------------------[ root1 - Payload & Public Certs ]----------------------
[ Subject Name ]  root1
[ Expiry Date  ]  9 September 2022
2UK6AelNtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQMg/+gyc/F3JZs4rY6ya5d9cPdWd6Sjs
OD3UsENAitTCGrY0fceRKrndJKyXsVwOhwe2lUpmidVytXzAundMMWmpBAQJCcwfqQUEFgrMHwkB
SwkAQOe/rz9mLoBLLRCpFEr+emsHEvcH73vZislzpwqBHxD+tV23QFmTMjsJzKsPOQmmYOxMkH/U
EbKFB4gzSK0aT/EJAQVyb290MQ==

this_part_should_be_ignored
"""

ff_root1_b64_block = base64.b64decode('\n'.join(ff_root1_pub_text.splitlines()[4:8]))

def test_ff_check_happy_path(c3m):
    ret = textfiles.text_to_binary_block(ff_root1_pub_text, CERT_SCHEMA)
    assert ret == ff_root1_b64_block

def test_ff_busted_vertical_1(c3m):
    busted_vertical_structure = "\n\n".join(ff_root1_pub_text.splitlines())
    with pytest.raises(StructureError, match="structure is invalid"):
        textfiles.text_to_binary_block(busted_vertical_structure, CERT_SCHEMA)

def test_ff_bad_field(c3m):
    bad_ff = ff_root1_pub_text.replace("Date  ]", "Date]")
    with pytest.raises(TamperError, match="format for visible"):
        textfiles.text_to_binary_block(bad_ff, CERT_SCHEMA)

def test_ff_spurious_field(c3m):
    spurious_field = "[ Spurious Field ]  Hello world"
    bad_ff = ff_root1_pub_text.replace("[ Subject Name ]  root1", spurious_field)
    with pytest.raises(TamperError, match="not present in the secure area"):
        textfiles.text_to_binary_block(bad_ff, CERT_SCHEMA)

def test_ff_field_value_mismatch(c3m):
    spurious_field = "[ Subject Name ]  Harold"
    bad_ff = ff_root1_pub_text.replace("[ Subject Name ]  root1", spurious_field)
    with pytest.raises(TamperError, match="does not match secure"):
        textfiles.text_to_binary_block(bad_ff, CERT_SCHEMA)


ff_root1_with_customs = """
--------------------[ root1 - Payload & Public Certs ]----------------------
[ Subject Name 2  ]  root1
[ Expiry Date XXX ]  9 September 2022
2UK6AelNtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQMg/+gyc/F3JZs4rY6ya5d9cPdWd6Sjs
OD3UsENAitTCGrY0fceRKrndJKyXsVwOhwe2lUpmidVytXzAundMMWmpBAQJCcwfqQUEFgrMHwkB
SwkAQOe/rz9mLoBLLRCpFEr+emsHEvcH73vZislzpwqBHxD+tV23QFmTMjsJzKsPOQmmYOxMkH/U
EbKFB4gzSK0aT/EJAQVyb290MQ==

this_part_should_be_ignored
"""

def test_ff_check_happy_path_custom(c3m):
    # custom_map = [["subject_name", "Subject Name 2"], ["expiry_date", "Expiry Date XXX"]]
    custom_map = (("subject_name", "Subject Name 2"), ("expiry_date", "Expiry Date XXX"))
    ret = textfiles.text_to_binary_block(ff_root1_with_customs, CERT_SCHEMA, custom_map)
    assert ret == ff_root1_b64_block





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
    expiry = datetime.date(2023, 9, 9)

    pub_part_bytes, priv_part_bytes = c3m.make_sign(action=MAKE_SELFSIGNED, name=u"test1", expiry=expiry)
    c3m.add_trusted_certs(pub_part_bytes)

    chain = structure.load_pub_block(pub_part_bytes)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify
    assert chain[0].cert.cert_id == chain[0].sig.signing_cert_id    # self-signed


def test_make_supply_neither_inval(c3m):
    with pytest.raises(ValueError):
        inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9")


def test_make_supply_both_inval(c3m):
    with pytest.raises(ValueError):
        inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_pub=b"a", using_name="root9")
        # Note it doen't get to needing the missing using_priv or expiry


def test_make_inter_name(c3m):
    expir = datetime.date(2023, 9, 9)
    # Root cert
    root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root9", expiry=expir)
    c3m.add_trusted_certs(root_pub)

    inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_priv=root_priv, expiry=expir,
                                          using_pub=root_pub, using_name="root9", link=LINK_NAME)

    chain = structure.load_pub_block(inter_pub)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify


def test_make_inter_append(c3m):
    expir = datetime.date(2023, 9, 9)
    # Root cert
    root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root9", expiry=expir)
    c3m.add_trusted_certs(root_pub)

    inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_priv=root_priv, expiry=expir,
                                          using_pub=root_pub, using_name="root9", link=LINK_APPEND)

    chain = structure.load_pub_block(inter_pub)
    ret = c3m.verify(chain)
    assert ret is True      # no payload, successful verify


def test_make_inter_append_expired_root(c3m):
    expir_root = datetime.date(2021, 9, 9)
    expir = datetime.date(2023, 9, 9)
    # Root cert
    root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root9", expiry=expir_root)
    c3m.add_trusted_certs(root_pub)
    with pytest.raises(CertExpired):
        c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_pub=root_pub, using_priv=root_priv, expiry=expir)


# Note that this doesn't fail, even though we are *appending* the root9 cert itself into the chain
#      which you're not supposed to do. It succeeds because root9 is in trusted_ces and verify
#      sees that the NAME root9 is in trusted_ces so sets the found_in_trusted flag so that
#      UntrustedChainError doesn't trigger at the end.

# Note this looks like it would open us up to malicious actors appending their own cert with the same
#      NAME, but the actual signature verification step is always done, which defends against this,
#      as shown by the next test.


def test_sign_rootcert_namecollide(c3m):
    expir = datetime.date(2023, 9, 9)
    # Legit guy
    root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root5", expiry=expir)
    c3m.add_trusted_certs(root_pub)
    # Attacker guy
    evil_pub, evil_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root5", expiry=expir)   # NOTE same name
    # evil chain
    inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_pub=evil_pub, using_priv=evil_priv, expiry=expir)
    chain = structure.load_pub_block(inter_pub)
    with pytest.raises(InvalidSignatureError):
        ret = c3m.verify(chain)



def test_sign_payload(c3m):
    expir = datetime.date(2023, 9, 9)
    root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root9", expiry=expir)

    inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_pub=root_pub, using_name="root9", using_priv=root_priv, expiry=expir, link=LINK_NAME)

    payload = b"How are you gentlemen"
    signed_payload, should_be_none = c3m.make_sign(SIGN_PAYLOAD, payload=payload, using_pub=inter_pub, using_priv=inter_priv)
    assert should_be_none is None

    chain = structure.load_pub_block(signed_payload)
    c3m.add_trusted_certs(root_pub)
    verify_ok = c3m.verify(chain)
    assert verify_ok is True



def test_keypair_matching(c3m):
    expir = datetime.date(2023, 9, 9)
    r1_pub, r1_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root1", expiry=expir)
    r2_pub, r2_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root1", expiry=expir)  # note simulating same name error

    with pytest.raises(SignError, match="key do not match"):
        c3m.make_sign(MAKE_INTERMEDIATE, name="inter2", using_pub=r1_pub,
                      using_name="root1", using_priv=r2_priv, expiry=expir,
                      link=LINK_NAME)


# ---- Truncate and glitch loops -----

# Testing what happens if the public_part buffer is incomplete
# (And finding out exactly where to truncate public_part for the short-chain test above)

def truncmain():
    c3m = SignVerify()
    c3m.add_trusted_certs(root1_block)
    buf = public_part[:]

    for i in range(len(buf)+1, 1, -1):
        buf2 = buf[:i]
        try:
            xx = c3m.load_pub_block(buf2)
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
    c3m = SignVerify()
    c3m.add_trusted_certs(root1_block)
    buf = public_part[:]

    for i in range(len(buf)):
        buf2 = buf[:i] + b"\x00" + buf[i+1:]
        try:
            xx = c3m.load_pub_block(buf2)
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
    c3m = SignVerify()
    z = {}
    i = 0
    while True:
        i += 1
        buf = random.randbytes(40)
        #buf = b"\xdd\x37\x40\xed\x4d\x30\x44" + random.randbytes(60)
        try:
            xx = c3m.load_pub_block(buf)
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
    c3m = SignVerify()
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
    #bare_glitch_loop()
    interactive_password_test()



# ---- Basic fuzzing of the initial header check ----
#
# def FuzzEKH():
#     for i in range(0,255):
#         buf = six.int2byte(i) #+ b"\x0f\x55\x55"
#         try:
#             ppkey, index = expect_key_header([PUB_PAYLOAD, PUB_CERTCHAIN], b3.LIST, buf, 0)
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
#             ppkey, index = expect_key_header([PUB_PAYLOAD, PUB_CERTCHAIN], b3.LIST, buf, 0)
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
