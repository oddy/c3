
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


def test_roundtrip_selfsign(c3m):
    ce1 = c3m.make_csr(name="harry", expiry_text="24 octover 2024")
    c3m.sign(ce1, ce1)
    dual_bytes = c3m.to_binary_dual(ce1)

    c3m.load_trusted_cert(block=dual_bytes)
    print("\n\n  ---- lod trusted certs done ----\n\n")
    ce2 = c3m.load_make_cert_entry(block=dual_bytes)
    assert c3m.verify2(ce2) is True




