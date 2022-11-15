
# C3 Signing and verifying actions, and a little in-ram trust store for verify().

import datetime, functools, operator, weakref

import ecdsa

from c3.constants import *
from c3.errors import *
from c3 import structure
from c3 import getpassword
from c3 import pass_protect
from c3 import textfiles
from c3 import commandline
from c3.structure import AttrDict

# TODO TODO TODO
# Ok, SignVerify spawns the CEs. So the user can treat CEs as just an opaque handle if they want.
# So load, make_csr and make_payload all belong to signverify and create CEs.
# So no fancy CE constructor.

# Apart from that, put as much as possible into the CE and out of Signverify.
# then we still have to port user_encrypt and decrypt priv key.
# then port commandline.
# then the tests.
# Then we're done.
# TODO TODO TODO


# Consider the "Store everything in a smart object" approach so that we can get the **APIs usable**
# Because the library user not losing their mind trying to use us, is more important than some
# memory usage double-ups, and just adding fields to a smart-object stops us *bogging down on that front*
# user-facing API usability is a lot more important than memory performance, especially for smallscale stuff like this.
# Licensing's "Entry and Registry-of-Entries" model seems to work quite well
# IF we're optimising for "give the user an opaque handle" operations, which we SHOULD ALWAYS be.

# ALWAYS copy-paste THEN DRY. Do NOT try to DRY in-flight!

# The smart-ish object that holds all the related info for a keypair and its cert and possibly cert chain
# The "smart hold-everything" object for a keypair and cert.
# Policy: anything with "block" in the name is bytes.
#         File, Txt, Block

# Policy: public binary structure - sticking with "chain[0].data_part can be payload or cert"
#         rather than "seperate payload & sig top level structure" because it makes verify simpler
#         & its too much change at this point.
#         (Also makes verify a lot simpler to implement in *other* languages quickly)


# data-output classes
# so we can go e.g. ce.pub.as_text(),  ce.both.as_binary(),

class CeOutPub(object):
    def __init__(self, ce_parent):
        self.ce = ce_parent

    def as_binary(self):
        return self.ce.pub_block

    def as_text(self, vis_map=None, desc=""):
        return textfiles.make_pub_txt_str_ce(self.ce, desc, vis_map)

    def write_text_file(self, filename, vis_map=None, desc=""):
        txt = self.as_text(vis_map, desc)
        with open(filename, "wt") as f:
            f.write(txt)
        return


class CeOutPriv(object):
    def __init__(self, ce_parent):
        self.ce = ce_parent

    def as_binary(self):
        if not self.ce.epriv_block:
            raise OutputError("Please encrypt() or nopassword() the private key")
        return self.ce.epriv_block

    def as_text(self, vis_map=None, desc=""):
        if not self.ce.epriv_block:
            raise OutputError("Please encrypt() or nopassword() the private key")
        return textfiles.make_priv_txt_str_ce(self.ce, desc, vis_map)

    def write_text_file(self, filename, vis_map=None, desc=""):
        txt = self.as_text(vis_map, desc)
        with open(filename, "wt") as f:
            f.write(txt)


class CeOutBoth(object):
    def __init__(self, ce_parent):
        self.ce = ce_parent

    def as_binary(self):
        print("jhel")
        if not self.ce.epriv_block:
            raise OutputError("Please encrypt() or nopassword() the private key")
        return structure.combine_binary_pub_priv(self.ce.pub_block, self.ce.epriv_block)

    def as_text(self, vis_map=None, desc=""):
        if not self.ce.epriv_block:
            raise OutputError("Please encrypt() or nopassword() the private key")
        pub_str = textfiles.make_pub_txt_str_ce(self.ce, desc, vis_map)
        priv_str = textfiles.make_priv_txt_str_ce(self.ce, desc)
        return "\n" + pub_str + "\n" + priv_str + "\n"

    def write_text_file(self, filename, vis_map=None, desc=""):
        txt = self.as_text(vis_map, desc)
        with open(filename, "wt") as f:
            f.write(txt)




class CertEntry(object):
    def __init__(self, parent):
        self.parent = weakref.ref(parent)   # pointer to the SignVerify object whose registry(s) we live in
        self.pub_type = 0                   # tag value e.g. PUB_CSR
        self.name = ""

        self.pub_text = ""
        self.epriv_text = ""

        self.pub_block = b""
        self.epriv_block = b""          # bytes of packed PRIV_CRCWRAPPED structure

        self.priv_d = {}                # unpacked PRIV_CRCWRAPPED structure
        self.priv_key_bytes = b""       # actual private key bytes (priv_d.priv_data)

        self.payload = b""              # this or cert, depending on pub_type
        self.cert = {}                  # aka chain[0]
        self.sig = b""

        self.chain = []

        self.vis_map = {}
        self.default_vismap = dict(schema=CERT_SCHEMA,
                                    field_map=["subject_name", "expiry_date", "issued_date"])
        # Output class instances, so user can go ce.pub.as_text(), ce.both.as_binary() etc.
        self.pub = CeOutPub(self)
        self.priv = CeOutPriv(self)
        self.both = CeOutBoth(self)


# Policy: verify() only reads from self.trusted_ces, it doesnt write anything into there.
#         Caller/User must call add_trusted_certs() to add theirs.

# Note: the priv key encrypt/decrypt functions are here too, just to keep things to 1 class for now.

class SignVerify(object):
    def __init__(self):
        self.trusted_ces = {}   # by name. Used by verify().
        self.signers = {}         # by name. Used by sign().

        # We need to load libsodium on startup if it is there. But also support cases where it's
        # not available (e.g.bare keys)
        self.load_error = None
        self.pass_protect = None
        try:
            self.pass_protect = pass_protect.PassProtect()
        except OSError as e:         # No libsodium dll found
            self.load_error = "Starting pass_protect: "+str(e)


    # ============ Load  ==================================================================

    # Policy: The overall policy governing Source of Truth is this:
    #         The binary blocks are fully self-describing, and are the canonical source of truth
    #         for everything. With one exception: the "PRIVATE" in the text header lines
    #         Controls which piece of base64 is decoded to priv_block and which to pub_block

    # Todo: consider reload+caching with password parameter, so passwords can be desynced.

    # Note: vis_map is ONLY for text-stuff, the binary stuff doesn't actually care _ever_ about the
    #       user's schema. The USER does, after the user get_payloads.

    # I think the file loaders can now be really basic.
    # Because all the smarts is in the text processor right here below.
    # Just open the files and read them and dump them into a single text variable. The filenames
    # dont actually matter to us, what drives public/private is the "PRIVATE" in the header line.
    # (that's also the only text part that controls anything, everything else is in the binary blocks.)

    # Policy: not supporting Visible Fields for the private block atm.
    #         The private block doesn't have a subject name anyway, we're relying on keypair crosscheck

    def load_make_cert_entry(self, text_filename="", text="", block=b"", vis_map=None):
        highlander_check(text_filename, text, block)  # there can be only one of these 3
        ce = CertEntry(self)
        pub_vf_lines = ""
        payload_dict = {}

        # Note: this if-flow works because text_file, text, and block are mutually exclusive
        # --- LOAD from aguments ---
        if text_filename:
            text = textfiles.load_files2(text_filename)

        if text:  # Text is EITHER, public text, private text, or both texts concatenated.
            ce.pub_text, ce.epriv_text = textfiles.split_text_pub_priv(text)
            if ce.pub_text:
                ce.pub_block, pub_vf_lines = textfiles.text_to_binary_block(ce.pub_text)
            if ce.epriv_text:
                ce.epriv_block, _ = textfiles.text_to_binary_block(ce.epriv_text)
                # Note: ignoreing vf_lines for private text atm.

        if block:
            ce.pub_block, ce.epriv_block = structure.split_binary_pub_priv(block)

        # --- Unpack binary blocks ---
        if not ce.pub_block:            # only bare-payload "CE"s dont have a public part, and they
            raise ValueError("Load: public block is missing")  # dont come through here, so.

        if ce.epriv_block:
            ce.priv_d = structure.load_priv_block(ce.epriv_block)
            if ce.priv_d.priv_type == PRIVTYPE_BARE:    # load automatically if the supplier
                ce.priv_key_bytes = ce.priv_d.priv_data  # didnt care about securing it.
            # if it IS encrypted, do nothing. Caller must call decrypt(), otherwise sign() will fail.

        # todo: merge this with load_pub_block2
        ce.pub_type, thingy = structure.load_pub_block2(ce.pub_block)
        if ce.pub_type == PUB_CSR:      # CSRs are just a cert
            ce.cert = thingy                # we're mixing cert-level stuff with CE-level stuff
            ce.name = ce.cert.subject_name      # noqa a bit here, so there are double-ups.
            if pub_vf_lines:        # tamper check public Visible Fields if any
                textfiles.crosscheck_visible_fields(pub_vf_lines, ce.default_vismap, ce.cert)
        if ce.pub_type == PUB_CERTCHAIN:
            ce.chain = thingy
            ce.name = ce.chain[0].cert.subject_name
            ce.cert = ce.chain[0].cert
            if pub_vf_lines:        # tamper check public Visible Fields if any
                textfiles.crosscheck_visible_fields(pub_vf_lines, ce.default_vismap, ce.cert)
        if ce.pub_type == PUB_PAYLOAD:          # note: no name, no cert
            ce.chain = thingy
            ce.payload = ce.chain[0].data_part
            # tamper check user Visible Fields if any. User-supplied schema is required.
            if pub_vf_lines:
                if not vis_map or "schema" not in vis_map or not vis_map["schema"]:
                    helpm = ". (please supply vis_map= to load() function)"
                    raise StructureError("Payload has visible fields but schema unknown" + helpm)
                payload_dict = AttrDict(b3.schema_unpack(vis_map["schema"], ce.payload))
                textfiles.crosscheck_visible_fields(pub_vf_lines, vis_map, payload_dict)

        return ce

    def load_signer(self, *args, **kw):
        ce = self.load_make_cert_entry(*args, **kw)
        # Signers must have a private key
        if not ce.priv_key_bytes:
            raise ValueError("Specified signer does not have a private key component")
        # add to registry
        self.signers[ce.name] = ce

    def load_trusted_cert(self, *args, **kw):
        ce = self.load_make_cert_entry(*args, **kw)
        force = "force" in kw and kw["force"] is True
        if not force:
            try:
                self.verify2(ce)
            except UntrustedChainError:  # ignore this one failure mode because we havent installed
                pass                     # this/these certs yet
        # add to registry
        self.trusted_ces[ce.cert.cert_id] = ce            # Note: by ID
        return

    # ============ Makers ===============

    # Note: CSRs are exportable, they have their own binary format which is just the cert.
    #       so not a chain like all the others.
    #       bare_payloads are NOT exportable, they are intended to be signed immediately.
    #       we want CSR loads to be different to "just sign a payload" because we want to have the
    #       option of e.g. adjusting the wanted expiry date, etc.

    def make_csr(self, name, expiry_text):
        expiry = commandline.ParseBasicDate(expiry_text)
        ce = CertEntry(self)
        ce.pub_type = PUB_CSR
        ce.name = name

        cert_id = name.encode("ascii")
        today = datetime.date.today()
        key_priv, key_pub = self.keys_generate(keytype=KT_ECDSA_PRIME256V1)

        ce.cert = AttrDict(public_key=key_pub, subject_name=name, cert_id=cert_id, issued_date=today,
                           key_type=KT_ECDSA_PRIME256V1, expiry_date=expiry)

        ce.priv_key_bytes = key_priv
        # Note: we don't set ce.epriv_block here, user must call encrypt() or nopassword() to make
        #       that happen, and we wont save without one of them happening.

        # All the exportable (as_binary etc) pub_blocks are serializations of ce.chain, except for
        # CSRs, which are serializations of ce.cert.
        cert_block = b3.schema_pack(CERT_SCHEMA, ce.cert)
        ce.pub_block = b3.encode_item_joined(PUB_CSR, b3.DICT, cert_block)
        return ce

    def make_payload(self, payload_bytes):
        ce = CertEntry(self)
        ce.pub_type = BARE_PAYLOAD
        ce.payload = payload_bytes
        return ce


    # =========== New Sign ==================

    # so self-sign is make_csr, sign, encrypt_priv, save
    # non-self-sign is load, load_signer, sign, encrypt_priv if not already, save

    def sign(self, ce, signer, link_by_name=False):        # link_name
        bytes_to_sign = b""
        payload = b""
        self_signing = (ce == signer)
        # Take cert, turn into bytes, get privkey from signing, sign bytes, make sig.
        # Then repatch to_sign's pub_block with signing_ce's pub_block.

        if datetime.date.today() > signer.cert.expiry_date:
            raise CertExpired("Signing cert has expired")

        # First param needs to always be a ce if we are in-place transforming it.
        # Either we are signing payload bytes, or we are signing cert bytes.
        if ce.cert:
            payload = b3.schema_pack(CERT_SCHEMA, ce.cert)
        if ce.payload:
            payload = ce.payload
        if not payload:
            raise SignError("No cert or payload found to sign")
        if not signer.priv_key_bytes:
            raise SignError("Please decrypt the signer's private key first")
        # Note: we can't gate on existence of epriv_block first, because e.g. selfsigned CSRs dont have one.


        # perform sign with key, get signature bytes
        key_type = signer.cert.key_type
        sig_bytes = self.keys_sign_make_sig(key_type, signer.priv_key_bytes, payload)

        # build our chain with 'payload'&sig + signers chain
        signer_cert_id = signer.cert.cert_id if link_by_name or self_signing else b""
        datasig = self.make_datasig(payload, sig_bytes, signer_cert_id)

        ce.chain = [datasig] + signer.chain

        if ce.pub_type == PUB_CSR:
            ce.pub_type = PUB_CERTCHAIN
        if ce.pub_type == BARE_PAYLOAD:
            ce.pub_type = PUB_PAYLOAD

        self.make_chain_pub_block(ce)     # serialize the chain

    def make_datasig(self, payload_bytes, sig_bytes, signer_cert_id):
        sig_d = AttrDict(signature=sig_bytes, signing_cert_id=signer_cert_id)
        sig_part = b3.schema_pack(SIG_SCHEMA, sig_d)
        datasig = AttrDict(data_part=payload_bytes, sig_part=sig_part)
        return datasig

    def make_chain_pub_block(self, ce):
        # We need to pack the datasigs, then join those blocks, prepend the header, and that's pub_block
        chain_blocks = []
        for das in ce.chain:
            das_bytes = b3.schema_pack(DATASIG_SCHEMA, das)
            das_bytes_with_hdr = b3.encode_item_joined(HDR_DAS, b3.DICT, das_bytes)
            chain_blocks.append(das_bytes_with_hdr)
        ce.pub_block = b3.encode_item_joined(ce.pub_type, b3.LIST, b"".join(chain_blocks))



    # after sign() the pub_block is made, and if ce_encrypt is called, the priv block is made too?
    # The test can

    # ============ Verify ==========================================================================

    # In: Data-And-Sigs items list
    # Out: payload bytes or an Exception

    # Apart from actual signature fails, there are 3 other ways for this to fail:
    # 1) unnamed issuer cert and no next cert in line aka "fell off the end" (ShortChainError)
    # 2) Named cert not found - in the cert store / trust store / certs_by_name etc
    # 3) Last cert is self-signed and verifies OK but isn't in the trust store. (Untrusted Chain)

    # Note: CEs to verify MUST come from load() (ie not directly from make_csr+sign when testing)
    #       because load() fully unpacks the chain for verify to inspect.

    def verify2(self, ce):
        chain = ce.chain
        if not chain:
            raise ValueError("Cannot verify - no cert chain present")
        if "sig" not in chain[0]:
            raise ValueError("Cannot verify - CE must be load()ed first")
        return self.verify__w(chain)

    def verify__w(self, chain):
        certs_by_id = {das.cert.cert_id : das.cert for das in chain if "cert" in das}
        found_in_trusted = False         # whether we have established a link to the trusted_ces

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
                if signing_cert_id in self.trusted_ces:
                    next_cert = self.trusted_ces[signing_cert_id].cert
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


    # ========== Signing Key stuff ====================

    # In: nothing
    # Out: key pair as priv bytes and pub bytes

    # NIST P-256 aka secp256r1 aka prime256v1

    def keys_generate(self, keytype):
        if keytype not in (KT_ECDSA_PRIME256V1,):
            raise NotImplementedError("Error generating keypair - unknown keytype")
        curve = [i for i in ecdsa.curves.curves if i.name == 'NIST256p'][0]
        priv = ecdsa.SigningKey.generate(curve=curve)
        pub = priv.get_verifying_key()
        return priv.to_string(), pub.to_string()

    def keys_sign_make_sig(self, keytype, priv_bytes, payload_bytes):
        if keytype not in (KT_ECDSA_PRIME256V1,):
            raise NotImplementedError("Error signing payload - unknown keytype")
        SK = ecdsa.SigningKey.from_string(priv_bytes, ecdsa.NIST256p)
        sig_bytes  = SK.sign(payload_bytes)
        return sig_bytes

    def keys_verify(self, keytype, public_key_bytes, payload_bytes, signature_bytes):
        if keytype not in (KT_ECDSA_PRIME256V1,):
            raise NotImplementedError("Error verifying payload - unknown keytype")
        VK = ecdsa.VerifyingKey.from_string(public_key_bytes, ecdsa.NIST256p)
        return VK.verify(signature_bytes, payload_bytes)  # returns True or raises exception

    # In: priv key bytes, pub chain block
    # Out: true or exception

    def keys_check_privpub_match(self, priv_key_bytes, using_pub_block):
        using_pub_key = structure.extract_first_dict(using_pub_block, CERT_SCHEMA).public_key
        priv = ecdsa.SigningKey.from_string(priv_key_bytes, ecdsa.NIST256p)
        pub = priv.get_verifying_key()
        if pub.to_string() != using_pub_key:
            raise SignError("private key and public key do not match")
        return True


    # ============== Private key encrypt/decrypt ===================================================


    # Encrypt-side
    def private_key_encrypt_sanity_checks(self, ce):
        if not ce.priv_key_bytes:
            raise ValueError("CE has no private key bytes")
        if not self.pass_protect:
            raise RuntimeError(self.load_error)

    def private_key_encrypt(self, ce, password):
        self.private_key_encrypt_sanity_checks(ce)
        epriv_bytes = self.pass_protect.SinglePassEncrypt(ce.priv_key_bytes, password)
        ce.epriv_block = structure.make_priv_block(epriv_bytes, bare=False)
        return

    def private_key_encrypt_user(self, ce):
        self.private_key_encrypt_sanity_checks(ce)
        prompt1 = "Enter password to set on private key > "
        prompt2 = "Re-enter private key password        > "
        passw = getpassword.get_double_enter_setting_password(prompt1, prompt2)
        if not passw:
            raise ValueError("No password supplied, exiting")
        epriv_bytes = self.pass_protect.SinglePassEncrypt(ce.priv_key_bytes, passw)
        ce.epriv_block = structure.make_priv_block(epriv_bytes, bare=False)

    def private_key_set_nopassword(self, ce):
        self.private_key_encrypt_sanity_checks(ce)
        ce.epriv_block = structure.make_priv_block(ce.priv_key_bytes, bare=True)


    # sanity checks first. Then user activity. Then execute decrypt.

    # out: True - dealt with it (BARE), False= password still needs doing.
    def private_key_decrypt_sanity_checks(self, ce):
        # already have priv_d from load() calling structure.load_priv_block
        if ce.priv_d.priv_type == PRIVTYPE_BARE:    # just in case the user calls us when they're not
            ce.priv_key_bytes = ce.priv_d.priv_data  # supposed to (e.g. a bare key was loaded)
            return True   # be good about it anyway so the user doesn't have to special case things.

        if ce.priv_d.priv_type != PRIVTYPE_PASS_PROTECT:
            raise StructureError("Private key is encrypted with an unknown encryption")
        if not self.pass_protect:       # usually because could not find libsodium DLL
            raise RuntimeError(self.load_error)
        if self.pass_protect.DualPasswordsNeeded(ce.priv_d.priv_data):  # todo: we dont support this here yet
            raise NotImplementedError("Private key wants dual passwords")
        return False


    def private_key_decrypt(self, ce, password):
        if self.private_key_decrypt_sanity_checks(ce):    # true = we're done (e.g BARE)
            return
        priv_ret = self.pass_protect.SinglePassDecrypt(ce.priv_d.priv_data, password)
        ce.priv_key_bytes = priv_ret


    def private_key_decrypt_user(self, ce):
        if self.private_key_decrypt_sanity_checks(ce):     # true = we're done (e.g BARE)
            return
        # --- Try password from environment variables ---
        passw = getpassword.get_env_password()
        if passw:
            priv_ret = self.pass_protect.SinglePassDecrypt(ce.priv_d.priv_data, passw)
            # Note exceptions are propagated right out here, its an exit if this decrypt fails.
            ce.priv_key_bytes = priv_ret
            return

        # --- Try password from user ---
        prompt = "Password to unlock private key: "
        priv_ret = b""
        while not priv_ret:
            passw = getpassword.get_enter_password(prompt)
            if not passw:
                raise ValueError("No password supplied, exiting")

            try:
                priv_ret = self.pass_protect.SinglePassDecrypt(ce.priv_d.priv_data, passw)
            except Exception as e:
                print("Failed decrypting private key: ", str(e))
                continue        # let user try again
        ce.priv_key_bytes = priv_ret
        return

    # Note: there is no inverse for private_key_nopassword because
    #       incoming BARE keys are handled directly by load()



# Policy: Arguments are mutually-exclusive,
#         not more and not less than one argument must have a value.
def highlander_check(*args):
    ibool_args = [int(bool(i)) for i in args]
    num_true = functools.reduce(operator.add, ibool_args, 0)
    if num_true == 0:
        raise ValueError("Please specify one mandatory argument (none were specified)")
    if num_true > 1:
        raise ValueError("Please specify only one mandatory argument (multiple were specified)")
    return True

