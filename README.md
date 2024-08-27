
# C3 = Compact Crypto Certs

Compact Crypto Certs (C3) is a mini-PKI signer/verifier with full chain functionality and compact binary and friendly text cert formats

(Note: a libsodium DLL/so/dylib is needed for the private key password encryption)

## Command line tool

```
Usage:
    c3 make        --name=root1  --expiry="24 oct 2024"
    c3 signcert    --name=root1  --using=self  --link=[name|append]
    c3 make        --name=inter1 --expiry="24 oct 2024"
    c3 signcert    --name=inter1 --using=root1
    c3 signpayload --payload=payload.txt --using=inter1
    c3 verify      --name=payload.txt    --trusted=root1  --trusted=inter1
    make options   --type=rootcert --parts=split/combine --nopassword=y
    Note: if multiple --trusted specified for verify, ensure root is first.
```



