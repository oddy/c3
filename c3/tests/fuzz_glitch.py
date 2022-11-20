
from __future__ import unicode_literals     # for python2

import base64, traceback, random, os, datetime
from pprint import pprint

from c3.signverify import SignVerify


# ---- Truncate and glitch loops -----
# A 2-cert chain here.
root1_pub = """
2Q66AekZtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQDiZmemfIXf+5WpBaAJYOlgqitfC4txC
5kBdGEgaA0A+jblvdn5LdxdO0heNDDNBh9nYDZUJUwo+nOpyd/H05kWpBAQYCtAfqQUEFQvMHwkB
SwkAQEbrVdKzH6YpeQiKo9bKmHWUV0yIu6H4tsOfrGJhEnARutowDamrPlcBdT9kxqzUkauFU6Dd
+xyEFoYaLEOTrJ4JAQVyb290MQ==
"""
root1_block = base64.b64decode(root1_pub)
inter_pub = """
2Q7uAukZsAEJAGUJAAVpbnRlchkBBWludGVyOQIBAQkDQJqwMvo4wnp9Auz93zKrscBlbu8mihvz
RARudJyYDumHVutovutOUEaPiJuQjMpI/vOG+hxn6uhZv7/aTM+B+e+pBAQYCtAfqQUEFQvMHwkB
RQkAQMmN9FKivxybOhv+dkqU2qhhcr3DSSvKqdFF4jBBp3yjV4mT3JJ1mdJ2m8sJq9cIyeRAhzgF
kBJD7wBH/RnwrNQBAekZtgEJAGUJAAVyb290MRkBBXJvb3QxOQIBAQkDQDiZmemfIXf+5WpBaAJY
OlgqitfC4txC5kBdGEgaA0A+jblvdn5LdxdO0heNDDNBh9nYDZUJUwo+nOpyd/H05kWpBAQYCtAf
qQUEFQvMHwkBSwkAQEbrVdKzH6YpeQiKo9bKmHWUV0yIu6H4tsOfrGJhEnARutowDamrPlcBdT9k
xqzUkauFU6Dd+xyEFoYaLEOTrJ4JAQVyb290MQ=="""
inter_block = base64.b64decode(inter_pub)

# Testing what happens if the public_part buffer is incomplete
# (And finding out exactly where to truncate public_part for the short-chain test above)

# Run me from TOP top level with: "python -m c3.tests.test_c3"

# Because the public block as a whole has a size, we need to adjust that size also, otherwise
# B3 just errors out across the entire buffer (as it should).

def truncmain():
    c3m = SignVerify()
    #c3m.load_trusted_cert(block=root1_block)
    buf = inter_block[:]

    for i in range(len(buf)+1, 1, -1):
        buf2 = buf[:i]
        try:
            xx = c3m.load(block=buf2)
        except Exception as e:
            print("%4i    load  %r" % (i,  e))
            #print(traceback.format_exc())
            continue
        try:
            c3m.verify(xx)
        except Exception as e:
            print("%4i  verify  %r" % (i, e))
            continue
        print("%4i   - SUCCESS -" % (i,))


# glitch a byte anywhere? in the chain to trigger signature fails.

def glitchmain():
    c3m = SignVerify()
    c3m.load_trusted_cert(block=root1_block)
    buf = inter_block[:]

    for i in range(len(buf)):
        buf2 = buf[:i] + b"\x00" + buf[i+1:]
        try:
            xx = c3m.load(block=buf2)
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



if __name__ == '__main__':
    truncmain()
    #glitchmain()
    #smallrandfuzz()
    #interactive_password_test()



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
