
# C3 Signing and verifying actions, and a little in-ram trust store for verify().

import datetime

import ecdsa

from c3.constants import *
from c3.errors import *
from c3 import structure
from c3 import getpassword
from c3 import pass_protect
from c3.structure import AttrDict

# Policy: verify() only reads from self.trusted_certs, it doesnt write anything into there.
#         Caller/User must call add_trusted_certs() to add theirs.

# Note: the priv key encrypt/decrypt functions are here too, just to keep things to 1 class for now.

class SignVerify(object):
    def __init__(self):
        self.trusted_certs = {}   # by name. For e.g. root certs etc.

        # We need to load libsodium on startup if it is there. But also support cases where it's
        # not available (e.g.bare keys)
        self.load_error = None
        self.pass_protect = None
        try:
            self.pass_protect = pass_protect.PassProtect()
        except OSError as e:         # No libsodium dll found
            self.load_error = "Starting pass_protect: "+str(e)

    # ============ Verify ==========================================================================

    # In: Data-And-Sigs items list
    # Out: payload bytes or an Exception

    # Apart from actual signature fails, there are 3 other ways for this to fail:
    # 1) unnamed issuer cert and no next cert in line aka "fell off the end" (ShortChainError)
    # 2) Named cert not found - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verifies OK but isn't in the trust store. (Untrusted Chain)

    def verify(self, chain):
        certs_by_id = {das.cert.cert_id : das.cert for das in chain if "cert" in das}
        found_in_trusted = False         # whether we have established a link to the trusted_certs

        for i, das in enumerate(chain):
            signing_cert_id = das.sig.signing_cert_id
            # --- Find the 'next cert' ie the one which verifies our signature ---
            if not signing_cert_id:
                # --- no signing-id means "next cert in the chain" ---
                if i + 1 >= len(chain):      # have we fallen off the end?
                    raise ShortChainError(structure.ctnm(das)+"Next issuer cert is missing")
                next_cert = chain[i + 1].cert
            else:
                # --- got a name, look in trusted for it, then in ourself (self-signed) ---
                if signing_cert_id in self.trusted_certs:
                    next_cert = self.trusted_certs[signing_cert_id]
                    found_in_trusted = True
                elif signing_cert_id in certs_by_id:
                    next_cert = certs_by_id[signing_cert_id]
                else:
                    raise CertNotFoundError(structure.ctnm(das)+"wanted cert %r not found" % signing_cert_id)

            # --- Actually verify the signature ---
            try:
                VK = ecdsa.VerifyingKey.from_string(next_cert.public_key, ecdsa.NIST256p)
                VK.verify(das.sig.signature, das.data_part)  # returns True or raises exception
            except Exception:       # wrap theirs with our own error class
                raise InvalidSignatureError(structure.ctnm(das)+"Signature failed to verify")
            # --- Now do next das in line ---

        # Chain verifies completed without problems. Make sure we got to a trust store cert.
        # If there is a payload, return it otherwise return True. (So bool-ness works.)
        # Even tho all errors are exceptions.
        if found_in_trusted:
            return True
        raise UntrustedChainError("Chain does not link to trusted certs")

    # --- in-ram trust store for Verify's trust anchors. ---

    def add_trusted_certs(self, certs_bytes, force=False):
        cert_chain = structure.load_pub_block(certs_bytes)
        if not force:
            try:
                self.verify(cert_chain)
            except UntrustedChainError:   # ignore this one failure mode because we havent installed
                pass                      # this/these certs yet!
        for das in cert_chain:
            if "cert" not in das:         # skip payload if there is one
                continue
            self.trusted_certs[das.cert.cert_id] = das.cert
        return


    # ============ Signing =========================================================================

    #               |     no payload             payload
    #  -------------+-------------------------------------------------
    #  using cert   |     make chain signer      sign payload
    #               |
    #  using self   |     make self signer       ERROR invalid state

    # The way sign combines things, we get bytes out.
    # Cannot be seperated like load and verify are, nor do we want to.

    # In: a cert name and/or payload, and a cert/keypair to use to sign with (if applicable)
    # Out: public_part BLOCK, private key BYTES
    # Note: incoming and outgoing privs are vare, caller must encrypt/decrypt.

    def make_sign(self, action, name="", payload=b"", using_priv=b"", using_pub=b"", using_name="", expiry=None, link=LINK_APPEND):
        # using_pub must now always be present unless MAKE_SELFSIGNED
        if action != MAKE_SELFSIGNED:
            if not using_pub:
                raise ValueError("please supply public part of --using")
            # Make sure the signing cert hasn't expired!
            structure.ensure_not_expired(using_pub)
            # Make sure the keypair really is a keypair
            self.check_privpub_match_ecdsanist256p(using_priv, using_pub)

        # sanity check expiry, needed for selfsign and intermediate
        if action in (MAKE_INTERMEDIATE, MAKE_SELFSIGNED):
            if not expiry:
                raise ValueError("creating cert: please provide expiry date")

        # Policy: for now, cert_id and subject name are the same.  Consider ULID in future.
        cert_id = name.encode("ascii")
        using_id = using_name.encode("ascii")
        new_key_priv = None

        # --- Key gen if applicable ---
        if action in (MAKE_SELFSIGNED, MAKE_INTERMEDIATE):
            # make keys
            new_key_priv, new_key_pub = self.gen_keys_ECDSA_nist256p()
            # make pub cert for pub key

            today = datetime.date.today()
            new_pub_cert = AttrDict(
                public_key=new_key_pub, subject_name=name, cert_id=cert_id, issued_date=today,
                key_type=KEYTYPE_ECDSA_256P, expiry_date=expiry
            )
            new_pub_cert_bytes = b3.schema_pack(CERT_SCHEMA, new_pub_cert)
            payload_bytes = new_pub_cert_bytes
        # --- Load payload if not key-genning ---
        else:
            payload_bytes = payload

        if action == MAKE_SELFSIGNED:
            # --- Sign the cert using its own private key ---
            SK = ecdsa.SigningKey.from_string(new_key_priv, ecdsa.NIST256p)
            sig_d = AttrDict(signature=SK.sign(payload_bytes), signing_cert_id=cert_id)

        else:
            # --- Sign the thing (cert or payload) using Using, if not selfsign ----
            SK = ecdsa.SigningKey.from_string(using_priv, ecdsa.NIST256p)
            sig_d = AttrDict(signature=SK.sign(payload_bytes), signing_cert_id=using_id)
            # note  ^^^ signing_cert_id can be blank, in which case using_pub should have bytes to append

        sig_part = b3.schema_pack(SIG_SCHEMA, sig_d)

        # --- Make data-and-sig structure ---
        das = AttrDict(data_part=payload_bytes, sig_part=sig_part)
        das_bytes = b3.schema_pack(DATA_AND_SIG, das)

        # --- prepend header for das itself so straight concatenation makes a list-of-das ---
        das_bytes_with_hdr = b3.encode_item_joined(KEY_DAS, b3.DICT, das_bytes)

        # --- Append Using's public_part (the chain) if applicable ---
        if link == LINK_APPEND and action != MAKE_SELFSIGNED:
            # we need to:
            # 1) strip using_public_part's public_part header,
            # (This should also ensure someone doesn't try to use a payload cert chain instead of a signer cert chain to sign things)
            _, index = structure.expect_key_header([KEY_LIST_CERTS], b3.LIST, using_pub, 0)
            using_pub = using_pub[index:]
            # 2) concat our data + using_public_part's data
            out_public_part = das_bytes_with_hdr + using_pub
        else:
            out_public_part = das_bytes_with_hdr

        # --- Prepend a new overall public_part header & return pub & private bytes ---
        if action == SIGN_PAYLOAD:
            key_type = KEY_LIST_PAYLOAD
        else:
            key_type = KEY_LIST_CERTS
        out_public_with_hdr = b3.encode_item_joined(key_type, b3.LIST, out_public_part)

        return out_public_with_hdr, new_key_priv


    # In: nothing
    # Out: key pair as priv bytes and pub bytes

    def gen_keys_ECDSA_nist256p(self):
        curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
        priv = ecdsa.SigningKey.generate(curve=curve)
        pub = priv.get_verifying_key()
        return priv.to_string(), pub.to_string()

    # In: priv key bytes, pub chain block
    # Out: true or exception

    def check_privpub_match_ecdsanist256p(self, priv_key_bytes, using_pub_block):
        using_pub_key = structure.extract_first_dict(using_pub_block, CERT_SCHEMA).public_key
        priv = ecdsa.SigningKey.from_string(priv_key_bytes, ecdsa.NIST256p)
        pub = priv.get_verifying_key()
        if pub.to_string() != using_pub_key:
            raise SignError("private key and public key do not match")
        return True


    # ============== Private key encrypt/decrypt ===================================================

    # NOTE that these interact with the user (password entry)
    #         and use a pass_protect object which needs startup initialisation (load libsodium)

    # In:  private key bytes  (and possibly user entering a password interactively)
    # Out: encrypted private key bytes

    def encrypt_private_key(self, priv_bytes):
        if not self.pass_protect:
            raise RuntimeError(self.load_error)
        prompt1 = "Private  key encryption password: "
        prompt2 = "Re-enter key encryption password: "
        passw = getpassword.get_double_enter_setting_password(prompt1, prompt2)
        if not passw:
            raise ValueError("No password supplied, exiting")
        epriv_bytes = self.pass_protect.SinglePassEncrypt(priv_bytes, passw)
        return epriv_bytes

    # In: dict from load_priv_block
    # Out: private key bytes for make_sign to use

    def decrypt_private_key(self, privd):
        if privd.priv_type == PRIVTYPE_BARE:
            return privd.priv_data
        if privd.priv_type != PRIVTYPE_PASS_PROTECT:
            raise StructureError \
                ("Unknown privtype %d in priv block (wanted %r)" % (privd.priv_type, KNOWN_PRIVTYPES))
        if not self.pass_protect:       # usually because could not find libsodium DLL
            raise RuntimeError(self.load_error)
        if self.pass_protect.DualPasswordsNeeded \
                (privd.priv_data):  # todo: we dont support this here yet
            raise NotImplementedError("Private key wants dual passwords")

        # --- Try password from environment variables ---
        passw = getpassword.get_env_password()
        if passw:
            priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            # Note exceptions are propagated right out here, its an exit if this decrypt fails.
            return priv_ret

        # --- Try password from user ---
        prompt = "Password to unlock private key: "
        priv_ret = b""
        while not priv_ret:
            passw = getpassword.get_enter_password(prompt)
            if not passw:
                raise ValueError("No password supplied, exiting")

            try:
                priv_ret = self.pass_protect.SinglePassDecrypt(privd.priv_data, passw)
            except Exception as e:
                print("Failed decrypting private key: ", str(e))
                continue        # let user try again
        return priv_ret

