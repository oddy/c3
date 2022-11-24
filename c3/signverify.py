
# C3 Signing and verifying actions, and a little in-ram trust store for verify().

import datetime, functools, operator

from c3.constants import *
from c3.errors import *
from c3 import certentry, keypairs
from c3 import structure, textfiles
from c3 import pass_protect, parsedate
from c3.structure import AttrDict

# Policy: anything with "block" in the name is bytes.
#         File, Txt, Block

# Policy: public binary structure - sticking with "chain[0].data_part can be payload or cert"
#         rather than "seperate payload & sig top level structure" because it makes verify simpler
#         & its too much change at this point.
#         (Also makes verify a lot simpler to implement in *other* languages quickly)

# Policy: verify() only reads from self.trusted_ces, it doesnt write anything into there.
#         Caller/User must call add_trusted_certs() to add theirs.

# Note: the priv key encrypt/decrypt functions are here too, just to keep things to 1 class for now.

class SignVerify(object):
    def __init__(self):
        self.trusted_ces = {}   # by name. Used by verify().

        # This uses libsodium so we load set it up at startup so the DLL can load at startup
        self.pass_protect = pass_protect.PassProtect()


    # ============ Load  ==================================================================

    # Note: vis_map is ONLY for text-stuff, the binary stuff doesn't actually care _ever_ about the
    #       user's schema. The USER does, after the user get_payloads.

    # I think the file loaders can now be really basic.
    # Because all the smarts is in the text processor right here below.
    # Just open the files and read them and dump them into a single text variable. The filenames
    # dont actually matter to us, what drives public/private is the "PRIVATE" in the header line.
    # (that's also the only text part that controls anything, everything else is in the binary blocks.)

    # Policy: not supporting Visible Fields for the private block atm.
    #         The private block doesn't have a subject name anyway, we're relying on keypair crosscheck

    def load(self, filename="", text="", block=b"", vis_map=None):
        highlander_check(filename, text, block)  # there can be only one of these 3
        ce = certentry.CertEntry(self)
        pub_vf_lines = ""
        payload_dict = {}

        # Note: this if-flow works because text_file, text, and block are mutually exclusive
        # --- LOAD from aguments ---
        if filename:
            text = textfiles.load_files(filename)

        if text:  # Text is EITHER, public text, private text, or both texts concatenated.
            ce.pub_text, ce.epriv_text = textfiles.split_text_pub_priv(text)
            if ce.pub_text:
                ce.pub_block, pub_vf_lines = textfiles.text_to_binary_block(ce.pub_text)
            if ce.epriv_text:
                ce.epriv_block, _ = textfiles.text_to_binary_block(ce.epriv_text)
                # Note: ignoring vf_lines for private text atm.

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

        ce.pub_type, thingy = structure.load_pub_block(ce.pub_block)

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

    def load_trusted_cert(self, *args, **kw):
        ce = self.load(*args, **kw)
        force = "force" in kw and kw["force"] is True
        if not force:
            try:
                self.verify(ce)
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

    def make_csr(self, name, expiry, cert_type=None):
        expiry = parsedate.ParseBasicDate(expiry)
        ce = certentry.CertEntry(self)
        ce.pub_type = PUB_CSR
        ce.name = name

        #cert_id = name.encode("ascii")  # if we want deterministic cert_ids e.g. for testing
        cert_id = structure.gen_ulid()
        today = datetime.date.today()
        key_priv, key_pub = keypairs.generate(keytype=KT_ECDSA_SECP256K1)

        ce.cert = AttrDict(public_key=key_pub, subject_name=name, cert_id=cert_id, issued_date=today,
                           key_type=KT_ECDSA_SECP256K1, expiry_date=expiry, cert_type=cert_type)

        ce.priv_key_bytes = key_priv
        # Note: we don't set ce.epriv_block here, user must call encrypt() or nopassword() to make
        #       that happen, and we wont save without one of them happening.

        # All the exportable (as_binary etc) pub_blocks are serializations of ce.chain, except for
        # CSRs, which are serializations of ce.cert.
        cert_block = b3.schema_pack(CERT_SCHEMA, ce.cert)
        ce.pub_block = b3.encode_item_joined(PUB_CSR, b3.DICT, cert_block)
        return ce

    def make_payload(self, payload_bytes):
        ce = certentry.CertEntry(self)
        ce.pub_type = BARE_PAYLOAD
        ce.payload = payload_bytes
        return ce


    # =========== Sign ==================

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
        keypairs.check_privpub_match(signer.cert, signer.priv_key_bytes)
        self.ensure_not_expired(signer)
        # Note: we can't gate on existence of epriv_block first, because e.g. selfsigned CSRs dont have one.

        # perform sign with key, get signature bytes
        key_type = signer.cert.key_type
        sig_bytes = keypairs.sign_make_sig(key_type, signer.priv_key_bytes, payload)

        # build our chain with 'payload'&sig + signers chain
        signer_cert_id = signer.cert.cert_id if (link_by_name or self_signing) else b""
        datasig = self.make_datasig(payload, sig_bytes, signer_cert_id)

        ce.chain = [datasig]
        if not (link_by_name or self_signing):
            ce.chain += signer.chain

        if ce.pub_type == PUB_CSR:
            ce.pub_type = PUB_CERTCHAIN
        if ce.pub_type == BARE_PAYLOAD:
            ce.pub_type = PUB_PAYLOAD

        self.make_chain_pub_block(ce)     # serialize the chain

    def ensure_not_expired(self, signer_ce):
        expiry = signer_ce.cert["expiry_date"]
        if datetime.date.today() > expiry:
            raise CertExpired("Signing cert has expired")
        return True

    # --- Binary operations for sign() ---

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

    def verify(self, ce):
        chain = ce.chain
        ce.vcerts = []      # Computed trail, includes trusted_certs
        if not chain:
            raise StructureError("Cannot verify - no cert chain present")
        if "sig" not in chain[0]:
            raise StructureError("Cannot verify - CE must be load()ed first")

        certs_by_id = {das.cert.cert_id : das.cert for das in chain if "cert" in das}
        found_in_trusted = False         # whether we have established a link to the trusted_ces

        for i, das in enumerate(chain):
            if "cert" in das:
                ce.vcerts = [das.cert] + ce.vcerts

            # --- Find the 'next cert' ie the one which verifies our signature ---
            signing_cert_id = das.sig.signing_cert_id
            if not signing_cert_id:
                # --- no signing-id means "next cert in the chain" ---
                if i + 1 >= len(chain):      # have we fallen off the end?
                    raise ShortChainError(structure.ctnm(das)+"Next issuer cert is missing")
                next_cert = chain[i + 1].cert
            else:
                # --- got a name, look in trusted for it ---
                if signing_cert_id in self.trusted_ces:
                    tr_ce = self.trusted_ces[signing_cert_id]
                    next_cert = tr_ce.cert
                    ce.vcerts = tr_ce.vcerts + ce.vcerts
                    found_in_trusted = True
                # --- otherwise look in our own supplied chain ---
                elif signing_cert_id in certs_by_id:
                    next_cert = certs_by_id[signing_cert_id]
                else:
                    raise CertNotFoundError(structure.ctnm(das)+"signing cert not found (id %r)" % signing_cert_id)

            # --- Actually verify the signature ---
            try:
                keypairs.verify(next_cert, das.data_part, das.sig.signature)
            except Exception:       # wrap theirs with our own error class
                raise InvalidSignatureError(structure.ctnm(das)+"Signature failed to verify")

            # --- Now do next das in line ---

        # Chain verifies completed without problems. Make sure we got to a trust store cert.
        # If there is a payload, return it otherwise return True. (So bool-ness works.)
        # Even tho all errors are exceptions.
        if found_in_trusted:
            return True

        raise UntrustedChainError("Chain does not link to trusted certs")




# Policy: Arguments are mutually-exclusive,
#         not more and not less than one argument must have a value.
def highlander_check(*args):
    ibool_args = [int(bool(i)) for i in args]
    num_true = functools.reduce(operator.add, ibool_args, 0)
    if num_true == 0:
        raise ValueError("Please specify one mandatory argument (none or empty specified)")
    if num_true > 1:
        raise ValueError("Please specify only one mandatory argument (multiple were specified)")
    return True

# Policy:
# Using the "Store everything in a smart object" approach so that we can get the **APIs usable**
# Because the library user not losing their mind trying to use us, is more important than some
# memory usage double-ups, and just adding fields to a smart-object stops us *bogging down on that front*
# user-facing API usability is a lot more important than memory performance, especially for smallscale stuff like this.
# Licensing's "Entry and Registry-of-Entries" model seems to work quite well
# IF we're optimising for "give the user an opaque handle" operations, which we SHOULD ALWAYS be.

# ALWAYS copy-paste THEN DRY. Do NOT try to DRY in-flight!

