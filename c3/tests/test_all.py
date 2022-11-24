
from __future__ import unicode_literals     # for python2

import base64, traceback, random, os, datetime
from pprint import pprint

import pytest

import b3.hexdump

from c3.constants import *
from c3.errors import *
from c3.signverify import SignVerify
from c3 import structure
from c3 import commandline

@pytest.fixture
def c3m():
    c3_obj = SignVerify()
    return c3_obj

@pytest.fixture
def csr_nopass(c3m):
    ce1 = c3m.make_csr(name="harry", expiry="24 october 2024")
    ce1.private_key_set_nopassword()
    return ce1

@pytest.fixture
def ce1(c3m, csr_nopass):
    c3m.sign(csr_nopass, csr_nopass)
    return csr_nopass

@pytest.fixture
def ce1_pub_buf(c3m, ce1):
    return ce1.pub.as_binary()

@pytest.fixture
def ce1_txt(c3m, ce1):
    return ce1.both.as_text()


CERT_VIS_MAP = dict(schema=CERT_SCHEMA, field_map=["subject_name", "expiry_date", "issued_date"])
STRIP_VF = "[ Subject Name ]  harry\n[ Expiry Date  ]  24 October 2024\n[ Issued Date  ]  14 November 2022\n"

# Binary roundtrip just a CSR (pub block isn't a chain, just a cert by itself)
# turn CSR into binary, then load that, then turn THAT into binary, then check the binaries match.

def test_csr_roundtrip_binary(c3m, csr_nopass):
    ce1_bin = csr_nopass.both.as_binary()
    ce2 = c3m.load(block=ce1_bin)
    ce2_bin = ce2.both.as_binary()
    assert ce1_bin == ce2_bin

# Text roundtrip a CSR

def test_csr_roundtrip_text(c3m, csr_nopass):
    ce1_txt = csr_nopass.both.as_text()
    assert "October 2024" in ce1_txt    # ensure default Visible Fields are generated also.
    ce2 = c3m.load(text=ce1_txt)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt

# Remove the visible fields, ensure ce2 still loads properly and generates them.

def test_csr_roundtrip_text_strip_vf(c3m, csr_nopass):
    ce1_txt = csr_nopass.both.as_text()
    ce1_txt_noVF = ce1_txt.replace(STRIP_VF, "")
    ce2 = c3m.load(text=ce1_txt_noVF)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt

def test_csr_optional_cert_type(c3m, csr_nopass):
    csr = csr_nopass
    txt1 = csr.pub.as_text()
    assert "[ Cert Type" not in txt1
    csr.cert["cert_type"] = "Special cert"
    txt2 = csr.pub.as_text()
    assert "[ Cert Type"  in txt2


def test_selfsign_roundtrip_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry="24 october 2024")
    ce1.private_key_set_nopassword()
    assert ce1.pub_type == PUB_CSR
    c3m.sign(ce1, ce1)      # self sign
    assert ce1.pub_type == PUB_CERTCHAIN
    ce1_bin = ce1.both.as_binary()

    ce2 = c3m.load(block=ce1_bin)
    ce2_bin = ce2.both.as_binary()
    assert ce1_bin == ce2_bin


def test_ss_verify_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry="24 october 2024")
    ce1.private_key_set_nopassword()
    c3m.sign(ce1, ce1)
    ce1_bin = ce1.both.as_binary()

    c3m.load_trusted_cert(block=ce1_bin)
    ce2 = c3m.load(block=ce1_bin)
    assert c3m.verify(ce2) is True

def test_ss_verify_text(c3m):
    ce1 = c3m.make_csr(name="harry", expiry="24 october 2024")
    ce1.private_key_set_nopassword()
    c3m.sign(ce1, ce1)
    ce1_txt = ce1.both.as_text()
    assert "Expiry Date  ]" in ce1_txt

    c3m.load_trusted_cert(text=ce1_txt)
    ce2 = c3m.load(text=ce1_txt)
    assert c3m.verify(ce2) is True

# --- Try to sign with expired cert ---
def test_sign_expired(c3m):
    expi = c3m.make_csr(name="expi", expiry="24 oct 2002")
    with pytest.raises(CertExpired):
        c3m.sign(expi, expi)

# ----- Inter cert signing / verifying ----

# Note: CEs must come in via load() for full chain-unpacking, dont use them directly.

def test_inter_sign_verify(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)

    inter = c3m.make_csr(name="inter2", expiry="24 oct 2024")
    assert inter.pub_type == PUB_CSR
    c3m.sign(inter, selfsigned)
    assert inter.pub_type == PUB_CERTCHAIN

    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    inter2 = c3m.load(block=inter.pub.as_binary())
    assert c3m.verify(inter2) is True

# ----- verify-chain metadata functions ----

def test_inter_namechain(c3m):
    root1 = c3m.make_csr(name="root1", expiry="24 october 2024", cert_type="rootcert")
    c3m.sign(root1, root1)
    inter2 = c3m.make_csr(name="inter2", expiry="24 oct 2024", cert_type="inter")
    c3m.sign(inter2, root1, link_by_name=True)
    inter3 = c3m.make_csr(name="inter3", expiry="24 oct 2024", cert_type="inter")
    c3m.sign(inter3, inter2, link_by_name=False)
    inter4 = c3m.make_csr(name="inter4", expiry="24 oct 2024", cert_type="inter")
    c3m.sign(inter4, inter3, link_by_name=False)
    pay = c3m.make_payload(b"hello world")
    c3m.sign(pay, inter4, link_by_name=False)
    # --- Verify ---
    pay_block = pay.pub.as_binary()
    pay2 = c3m.load(block=pay_block)

    c3m.load_trusted_cert(block=root1.pub.as_binary())
    # c3m.load_trusted_cert(block=inter2.pub.as_binary())
    # c3m.load_trusted_cert(block=inter3.pub.as_binary())
    c3m.verify(pay2)
    assert pay2.vtypes() == "/rootcert/inter/inter/inter"
    assert pay2.vnames() == "/root1/inter2/inter3/inter4"


# ----- Payload signing / verifying ----

def test_payload_sign_verify(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)

    payload = b"Hello i am a payload"
    pce = c3m.make_payload(payload)
    assert pce.pub_type == BARE_PAYLOAD
    c3m.sign(pce, selfsigned)
    assert pce.pub_type == PUB_PAYLOAD

    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    pce2 = c3m.load(block=pce.pub.as_binary())
    assert c3m.verify(pce2) is True

# ---- Sign using intermediate ----

def test_payload_sign_intermediate(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    inter = c3m.make_csr(name="inter2", expiry="24 oct 2024")
    c3m.sign(inter, selfsigned)
    payload = b"Hello i am a payload"
    pce = c3m.make_payload(payload)
    c3m.sign(pce, inter)
    pce_bin = pce.pub.as_binary()
    # --------------------------------------------------------------
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    pce2 = c3m.load(block=pce_bin)
    assert c3m.verify(pce2) is True




# --- load-to-sign (instead of make_csr-to-sign ---

def test_load_to_sign(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    selfsigned.private_key_set_nopassword()
    ss2 = c3m.load(block=selfsigned.both.as_binary())
    inter = c3m.make_csr(name="inter2", expiry="24 oct 2024")
    c3m.sign(inter, ss2)

# --- Didn't set the priv key bare (or encrypt) ---

def test_load_to_sign_priv_key_unset(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    with pytest.raises(OutputError):
        ss_bin = selfsigned.both.as_binary()


# ---- Private key encrypt/decrypt (password in code) ---

def test_privkey_encrypt(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    selfsigned.private_key_encrypt("hunter3")

    ss2 = c3m.load(block=selfsigned.both.as_binary())
    ss2.private_key_decrypt("hunter3")
    inter = c3m.make_csr(name="inter2", expiry="24 oct 2024")

    c3m.sign(inter, ss2)


def test_privkey_encrypt_env_var(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    os.environ["C3_PASSWORD"] = "Password01!"   # Note: this side-effects the rest of the tests!
    selfsigned.private_key_encrypt_user()

    ss2 = c3m.load(block=selfsigned.both.as_binary())
    ss2.private_key_decrypt_user()
    inter = c3m.make_csr(name="inter2", expiry="24 oct 2024")

    c3m.sign(inter, ss2)

# glitch a privkey byte to exercise the integrity check
def test_privkey_bare_integrity(c3m):
    bare_priv = b"hello world"
    priv_block_bytes = structure.make_priv_block(bare_priv, bare=True)
    priv_block_bytes = priv_block_bytes[:16] + b"a" + priv_block_bytes[17:]
    with pytest.raises(IntegrityError):
        structure.load_priv_block(priv_block_bytes)


# ----- Verification errors -----

# Glitch the payload contents so the signature fails to verify
def test_verify_signature_fail(c3m, ce1_pub_buf):
    c3m.load_trusted_cert(block=ce1_pub_buf)
    buf = ce1_pub_buf[:150] + b"X" + ce1_pub_buf[151:]
    ce2 = c3m.load(block=buf)
    with pytest.raises(InvalidSignatureError):
        c3m.verify(ce2)

# Apart from actual signature fails, there are 3 ways for this to fail:
# 1) "fell off" - unnamed issuer cert and no next cert in line ("short chain")
# 2) Cant Find Named Cert - in the cert store / trust store / certs_by_name etc
# 3) Last cert is self-signed and verified OK but isn't in the trust store.


# cut the signing cert off of the end of intermediate cert public block
# to trigger "next cert is the signer but there is no next cert" failure mode
# note: Don't need trusted root1 loaded because it doesn't get that far
inter_text = """
2Q7uAukZsAEJAGUJAAVpbnRlchkBBWludGVyOQIBAQkDQJqwMvo4wnp9Auz93zKrscBlbu8mihvz
RARudJyYDumHVutovutOUEaPiJuQjMpI/vOG+hxn6uhZv7/aTM+B+e+pBAQYCtAfqQUEFQvMHwkB
RQkAQMmN9FKivxybOhv+dkqU2qhhcr3DSSvKqdFF4jBBp3yjV4mT3JJ1mdJ2m8sJq9cIyeRAhzgF
kBJD7wBH/RnwrNQBAekZtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQDiZmemfIXf+5WpBaAJY
OlgqitfC4txC5kBdGEgaA0A+jblvdn5LdxdO0heNDDNBh9nYDZUJUwo+nOpyd/H05kWpBAQYCtAf
qQUEFQvMHwkBSwkAQEbrVdKzH6YpeQiKo9bKmHWUV0yIu6H4tsOfrGJhEnARutowDamrPlcBdT9k
xqzUkauFU6Dd+xyEFoYaLEOTrJ4JAQVyb290MQ=="""
inter_block = base64.b64decode(inter_text)

def test_verify_short_chain(c3m):
    buf = inter_block[:]
    buf2 = buf[:184]
    inter = c3m.load(block=buf2)
    with pytest.raises(ShortChainError):
        c3m.verify(inter)

# try verify an intermediate that has a 'by name' cert link (instead of append-it-in),
# to induce CertNotFoundError. (by just not loading a trusted cert first.)
interbyname_text = """
2Q68AekZuAEJAGcJAAZpbnRlcjIZAQZpbnRlcjI5AgEBCQNAoRCrLvSQ/TBs0KBamYcu7j++Mw73
Hfa/9IuF2eQO9HwAibgjnUsuf+U+fGFKzx/hzd1zvWZJD9Dc61nnX/qVRakEBBgK0B+pBQQVC8wf
CQFLCQBAEWjuOWLDXzfkAK1eSUmtSrXsPzGtWfegHSGg/jbr4g92omM4d26rxj4BsslGXSp1ysHX
3vLXaCweTEGYLU82yQkBBXJvb3Qx"""
interbyname_block = base64.b64decode(interbyname_text)

def test_verify_cert_not_found(c3m):
    interbyname = c3m.load(block=interbyname_block)
    with pytest.raises(CertNotFoundError):
        c3m.verify(interbyname)


# Without loading ce1 to trusted store first,
# a fully valid chain with a selfsign at the end, should fail with UntrustedChainError
def test_verify_untrusted_chain_error(c3m, ce1_pub_buf):
    ce2 = c3m.load(block=ce1_pub_buf)
    with pytest.raises(UntrustedChainError):
        c3m.verify(ce2)

# ---- Quick fuzz to exercise all the load errors ----
# just throw all the error strings together then assert the presence of the errors we want

selfsigned_pub_and_priv_b64 = """
6Qv7AQkAvgHZDroB6Rm2AQkAZQkABXJvb3QxGQEFcm9vdDE5AgEBCQNAOJmZ6Z8hd/7lakFoAlg
6WCqK18Li3ELmQF0YSBoDQD6NuW92fkt3F07SF40MM0GH2dgNlQlTCj6c6nJ38fTmRakEBBgK0B
+pBQQVC8wfCQFLCQBARutV0rMfpil5CIqj1sqYdZRXTIi7ofi2w5+sYmEScBG62jANqas+VwF1P
2TGrNSRq4VToN37HIQWhhosQ5OsngkBBXJvb3QxCQE26Q8zOQABATkBAQEJAiDVJDmswBXrxa4P
IuqHpl1H38C5Q1QdssQSxPhUh1ZAIzkDBb3RuKgB
"""
# note: verified there are no \xaa bytes in the above block.
# Note: The above block was created using PRIME256V1 keys not SECP256k1, so it serves as a test for
#       keypairs.py's multi-keytype support also.

# Note: There are some header data_lens which are not actually used by us. So when those get
#       glitched, the verify still succeeds, which is legit and ok.
#       Cross reference printing Success! in here with printing data_len in expect_key_header()
#       in structure.py to prove this out.

def test_load_fuzz(c3m):
    buf = base64.b64decode(selfsigned_pub_and_priv_b64)
    c3m.load_trusted_cert(block=buf)
    fails = set()
    for i in range(len(buf)):
        buf2 = buf[:i] + b"\xaa" + buf[i+1:]
        try:
            ce = c3m.load(block=buf2)
            c3m.verify(ce)
            # print("Success! i=", i)
        except Exception as e:
            fails.add(str(e))

    errs = "\n".join(fails)
    # print(errs)
    assert "List item header structure is invalid" in errs
    assert "List item header key invalid" in errs
    # assert "invalid - no data" in errs
    # assert "data is missing" in errs
    assert "Mandatory field" in errs
    # assert "Required schema field" in errs
    assert "Private key block failed data integrity check" in errs
    assert "Signature failed to verify" in errs
    assert "not found" in errs
    assert "Next issuer cert is missing" in errs
    assert "Incorrect key in header" in errs



# ---- Test keypair matching ----

# We have to hack inner CE structures, thanks to the CE system, mismatches cant happen as a result
# of api misuse / user error.

def test_keypair_matching(c3m):
    ce1 = c3m.make_csr(name="root1", expiry="24 oct 2024")
    ce2 = c3m.make_csr(name="root1", expiry="24 oct 2024")  # note simulating same name
    ce2.priv_key_bytes = ce1.priv_key_bytes   # overwrite ce2 priv with ce1 priv.
    with pytest.raises(SignError, match="Private key and public key do not match"):
        c3m.sign(ce2, ce2)



# ---- Test load error handling ----

def test_load_empty(c3m):
    with pytest.raises(ValueError):
        c3m.load(block=b"")     # fails highlander_check

def test_load_none(c3m):
    with pytest.raises(ValueError):
        c3m.load(block=None)    # fail highlander_check

def test_load_nulls(c3m):
    with pytest.raises(StructureError):     # fails initial expect_header
        c3m.load(block=b"\x00\x00\x00\x00\x00\x00\x00\x00")



# --- Visible fields tamper checks ---
def test_vis_busted_vertical(c3m, ce1_txt):
    busted_vertical_structure = "\n\n".join(ce1_txt.splitlines())
    with pytest.raises(StructureError, match="structure is invalid"):
        c3m.load(text=busted_vertical_structure)

def test_vis_bad_field(c3m, ce1_txt):
    bad_vf = ce1_txt.replace("Date  ]", "Date]")
    with pytest.raises(TamperError, match="format for visible"):
        c3m.load(text=bad_vf)

def test_vis_spurious_field(c3m, ce1_txt):
    spurious_field = "[ Spurious Field ]  Hello world"
    bad_vf = ce1_txt.replace("[ Subject Name ]  harry", spurious_field)
    with pytest.raises(TamperError, match="not present in the secure area"):
        c3m.load(text=bad_vf)

def test_vis_value_mismatch(c3m, ce1_txt):
    spurious_field = "[ Subject Name ]  Harold"
    bad_vf = ce1_txt.replace("[ Subject Name ]  harry", spurious_field)
    with pytest.raises(TamperError, match="does not match secure"):
        c3m.load(text=bad_vf)



# ----- Visible fields for custom payloads -----
LI_SCHEMA = (
    (b3.UTF8, "typ", 0, True),   # "License type"
    (b3.UTF8, "org", 4, False),  # "Organization"
    (b3.UTF8, "hostnames", 5, False),  # "Hostnames"
)
LI_VISFIELDS = [ ["org", "Organization"], "hostnames", ["typ", "License Type"] ]
LI_VISMAP = dict(schema=LI_SCHEMA, field_map=LI_VISFIELDS)

def test_payload_verify_text(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text()
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    pce2 = c3m.load(text=pce_txt)
    assert c3m.verify(pce2) is True
    assert pce2.payload == payload


def test_payload_verify_text_visfields_noschema(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text(vis_map=LI_VISMAP)
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    # Load needs to be supplied the vis_map, if there are visible fields incoming,
    # otherwise load can't tamper-check the visible fields.
    with pytest.raises(StructureError, match="schema unknown"):
        c3m.load(text=pce_txt)


def test_payload_verify_text_visfields(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text(vis_map=LI_VISMAP)
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    pce2 = c3m.load(text=pce_txt, vis_map=LI_VISMAP)
    assert c3m.verify(pce2) is True


def test_payload_verify_text_visfields_tamper(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text(vis_map=LI_VISMAP)
    pce_txt = pce_txt.replace("fred", "albert")      # change visible field value
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    with pytest.raises(TamperError, match="fred"):
        c3m.load(text=pce_txt, vis_map=LI_VISMAP)



# --- Commandline testing ---

# Note: this writes files to folder!
PAYLOAD = "Hello i am a payload\n"
COMMAND_LINES = """
c3 make        --name=root1  --expiry="24 oct 2024" --parts=split
c3 signcert    --name=root1  --using=self           --parts=split
c3 make        --name=inter1 --expiry="24 oct 2024" --parts=combine
c3 signcert    --name=inter1 --using=root1          --parts=combine
c3 signpayload --payload=payload.txt --using=inter1
c3 verify      --name=payload.txt --trusted=root1
"""

@pytest.mark.skip(reason="writes files - enable in code for more coverage")
def test_commandline_full():
    os.environ["C3_PASSWORD"] = "Password01!"
    with open("payload.txt", "wt") as f:
        f.write(PAYLOAD)
    for line in COMMAND_LINES.splitlines():
        if not line.strip():
            continue
        commandline.CommandlineMain(line)
    # not really a proper test, should assert something.




# ---------- ID collision ---------------

# todo: port this test at some point. It's slightly dependend on ID behaviour.

# Note signing doesnt fail when we *append* the root9 cert itself into the chain
#      which you're not supposed to do. It succeeds because root9 is in trusted_CEs and verify
#      sees that the NAME root9 is in trusted_CEs so sets the found_in_trusted flag so that
#      UntrustedChainError doesn't trigger at the end.

# Note this looks like it would open us up to malicious actors appending their own cert with the same
#      ID, but the actual signature verification step is always done, which defends against this,
#      as shown by the next test.

# def test_sign_rootcert_namecollide(c3m):
#     expir = datetime.date(2023, 9, 9)
#     # Legit guy
#     root_pub, root_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root5", expiry=expir)
#     c3m.add_trusted_certs(root_pub)
#     # Attacker guy
#     evil_pub, evil_priv = c3m.make_sign(MAKE_SELFSIGNED, name="root5", expiry=expir)   # NOTE same name
#     # evil chain
#     inter_pub, inter_priv = c3m.make_sign(MAKE_INTERMEDIATE, name="inter9", using_pub=evil_pub, using_priv=evil_priv, expiry=expir)
#     chain = structure.load_pub_block(inter_pub)
#     with pytest.raises(InvalidSignatureError):
#         ret = c3m.verify(chain)
#
