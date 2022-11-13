
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
    ce1_bin = ce1.both.as_binary()
    ce2 = c3m.load_make_cert_entry(block=ce1_bin)
    ce2_bin = ce2.both.as_binary()
    assert ce1_bin == ce2_bin


def test_csr_roundtrip_text(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1_txt = ce1.both.as_text()
    ce2 = c3m.load_make_cert_entry(text=ce1_txt)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt

# Remove the visible fields, ensure ce2 still loads properly and generates them.

def test_csr_roundtrip_text_strip_vf(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    ce1_txt = ce1.both.as_text()
    ce1_txt_noVF = ce1_txt.replace(STRIP_VF, "")
    ce2 = c3m.load_make_cert_entry(text=ce1_txt_noVF)
    ce2_txt = ce2.both.as_text()
    assert ce1_txt == ce2_txt




def test_selfsign_roundtrip_binary(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    c3m.sign(ce1, ce1)
    dual_bytes = ce1.both.as_binary()

    c3m.load_trusted_cert(block=dual_bytes)
    ce2 = c3m.load_make_cert_entry(block=dual_bytes)
    assert c3m.verify2(ce2) is True


# def test_selfsign_text_roundtrip(c3m):
#     ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
#     c3m.sign(ce1, ce1)
#     dual_bytes = ce1.both.as_binary()
#
#     c3m.load_trusted_cert(block=dual_bytes)
#     ce2 = c3m.load_make_cert_entry(block=dual_bytes)
#     assert c3m.verify2(ce2) is True
