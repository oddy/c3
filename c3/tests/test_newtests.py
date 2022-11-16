
from __future__ import unicode_literals     # for python2

import base64, traceback, random, os, datetime
from pprint import pprint

import pytest

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


CERT_VIS_MAP = dict(schema=CERT_SCHEMA, field_map=["subject_name", "expiry_date", "issued_date"])
STRIP_VF = "[ Subject Name ]  harry\n[ Expiry Date  ]  24 October 2024\n[ Issued Date  ]  14 November 2022\n"

# Can we binary roundtrip just a CSR (pub block isn't a chain, just a cert by itself)
# turn CSR into binary, then load that, then turn THAT into binary, then check the binaries match.

def test_csr_roundtrip_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    ce1_bin = ce1.both.as_binary()
    ce2 = c3m.load(block=ce1_bin)
    ce2_bin = ce2.both.as_binary()
    assert ce1_bin == ce2_bin


def test_csr_roundtrip_text(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    ce1_txt = ce1.both.as_text()
    ce2 = c3m.load(text=ce1_txt)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt

# Remove the visible fields, ensure ce2 still loads properly and generates them.

def test_csr_roundtrip_text_strip_vf(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    ce1_txt = ce1.both.as_text()
    ce1_txt_noVF = ce1_txt.replace(STRIP_VF, "")
    ce2 = c3m.load(text=ce1_txt_noVF)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt



def test_ss_roundtrip_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    assert ce1.pub_type == PUB_CSR
    c3m.sign(ce1, ce1)
    assert ce1.pub_type == PUB_CERTCHAIN
    ce1_bin = ce1.both.as_binary()
    ce2 = c3m.load(block=ce1_bin)
    ce2_bin = ce2.both.as_binary()
    assert ce1_bin == ce2_bin


def test_ss_verify_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    c3m.sign(ce1, ce1)
    ce1_bin = ce1.both.as_binary()

    c3m.load_trusted_cert(block=ce1_bin)
    ce2 = c3m.load(block=ce1_bin)
    assert c3m.verify(ce2) is True

# Confirmed here that default CERT visfields are saving and loading
def test_ss_verify_text(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1.private_key_set_nopassword()
    c3m.sign(ce1, ce1)
    ce1_txt = ce1.both.as_text()
    c3m.load_trusted_cert(text=ce1_txt)
    ce2 = c3m.load(text=ce1_txt)
    assert c3m.verify(ce2) is True

# ----- Inter cert signing / verifying ----

# Note: CEs must come in via load() for full chain-unpacking, dont use them directly.

def test_inter_sign_verify(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)

    inter = c3m.make_csr(name="inter2", expiry_text="24 oct 2024")
    assert inter.pub_type == PUB_CSR
    c3m.sign(inter, selfsigned)
    assert inter.pub_type == PUB_CERTCHAIN

    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    inter2 = c3m.load(block=inter.pub.as_binary())
    assert c3m.verify(inter2) is True

# ----- Payload signing / verifying ----

def test_payload_sign_verify(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
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
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    inter = c3m.make_csr(name="inter2", expiry_text="24 oct 2024")
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
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    selfsigned.private_key_set_nopassword()
    ss2 = c3m.load(block=selfsigned.both.as_binary())
    inter = c3m.make_csr(name="inter2", expiry_text="24 oct 2024")
    c3m.sign(inter, ss2)

# --- Didn't set the priv key bare (or encrypt) ---

def test_load_to_sign_priv_key_unset(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    with pytest.raises(OutputError):
        ss_bin = selfsigned.both.as_binary()


# ---- Private key encrypt/decrypt (password in code) ---

def test_privkey_encrypt(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    selfsigned.private_key_encrypt("hunter3")
    # selfsigned.private_key_set_nopassword()

    ss2 = c3m.load(block=selfsigned.both.as_binary())
    ss2.private_key_decrypt("hunter3")
    inter = c3m.make_csr(name="inter2", expiry_text="24 oct 2024")

    c3m.sign(inter, ss2)



# ----- Visible fields for custom payloads -----
LI_SCHEMA = (
    (b3.UTF8, "typ", 0, True),   # "License type"
    (b3.UTF8, "org", 4, False),  # "Organization"
    (b3.UTF8, "hostnames", 5, False),  # "Hostnames"
)
LI_VISFIELDS = [ ["org", "Organization"], "hostnames", ["typ", "License Type"] ]
LI_VISMAP = dict(schema=LI_SCHEMA, field_map=LI_VISFIELDS)

def test_payload_verify_text(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text()
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    pce2 = c3m.load(text=pce_txt)
    assert c3m.verify(pce2) is True


def test_payload_verify_text_visfields_noschema(c3m):
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
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
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
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
    selfsigned = c3m.make_csr(name="root1", expiry_text="24 october 2024")
    c3m.sign(selfsigned, selfsigned)
    payload_d = dict(typ="type 1", org="Hello Ltd", hostnames="fred")
    payload = b3.schema_pack(LI_SCHEMA, payload_d)
    pce = c3m.make_payload(payload)
    c3m.sign(pce, selfsigned)
    pce_txt = pce.pub.as_text(vis_map=LI_VISMAP)
    pce_txt = pce_txt.replace("fred","albert")      # change visible field value
    c3m.load_trusted_cert(block=selfsigned.pub.as_binary())
    with pytest.raises(TamperError, match="fred"):
        c3m.load(text=pce_txt, vis_map=LI_VISMAP)


# ----------- Encrypt decrypt private key behaviour ----------------

# We want the user to have to explicitely say they want a bare key.




