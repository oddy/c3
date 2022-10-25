
# C3 private & public text-file format saving, loading & validation

import os, base64, re, functools, datetime

import b3

from c3 import structure
from c3.constants import CERT_SCHEMA, PRIV_CRCWRAPPED
from c3.errors import StructureError, TamperError

# ============================== File Saving/Loading ===========================================

# Policy: look for name.PRIVATE and name.PUBLIC (.b64.txt)
# Policy: split trumps combined.
# Policy: Return "" for private_part if there is none, callers can validate

def asc_header(msg):
    m2 = "[ %s ]" % msg
    offs = 37 - len(m2) // 2
    line = "-" * offs
    line += m2
    line += "-" * (76 - len(line))
    return line


def write_files(name, public_part, private_part=b"", combine=True, desc="", pub_ff_lines="", priv_ff_lines=""):
    pub_desc = desc if desc else (name + " - Payload & Public Certs")
    priv_desc = (desc or name) + " - PRIVATE Key"
    if pub_ff_lines:
        pub_ff_lines += "\n"
    pub_str = asc_header(pub_desc) + "\n" + pub_ff_lines + base64.encodebytes \
        (public_part).decode()
    if priv_ff_lines:
        priv_ff_lines += "\n"
    priv_str = asc_header(priv_desc) + "\n" + priv_ff_lines + base64.encodebytes \
        (private_part).decode()

    print()
    print(pub_str)
    print()
    print(priv_str)
    if combine:
        fname = name + ".b64.txt"
        with open(fname, "w") as f:
            f.write("\n " +pub_str)
            f.write("\n")
            f.write(priv_str + "\n")
        print("Wrote combined file: " ,fname)
    else:
        fname = name + ".public.b64.txt"
        with open(fname, "w") as f:
            f.write("\n " + pub_str + "\n")
        print("Wrote public file:  ", fname)

        if not private_part:
            return

        fname = name + ".PRIVATE.b64.txt"
        with open(fname, "w") as f:
            f.write("\n " + priv_str + "\n")
        print("Wrote PRIVATE file: ", fname)



def load_files(name):
    header_rex = r"^-+\[ (.*?) \]-+$"
    pub_text_block = ""
    priv_text_block = ""

    combine_name = name + ".b64.txt"
    if os.path.isfile(combine_name):
        print("Loading combined file ", combine_name)
        both_strs = open(combine_name, "r").read()

        # regex cap the header lines
        hdrs = list(re.finditer(header_rex, both_strs, re.MULTILINE))
        if len(hdrs) != 2:
            print(" Warning: number of headers in combined file is not 2")

        # Structure: first header, first data, second header, second data, end of file
        # data offsets are start-of-first-header : start-of-second-header,
        # because check_friendly_fields wants to see the headers too if they are there.
        block0_text = both_strs[hdrs[0].start() : hdrs[1].start()]
        block1_text = both_strs[hdrs[1].start( ):]

        # normally the second block is the private block, but if a user has shuffled things around
        # we cater for that by checking which block has 'PRIVATE' in its header description
        if "PRIVATE" in hdrs[0].group(1):       # Private block comes first (not the normal case)
            pub_text_block, priv_text_block = block1_text, block0_text
        else:   # Otherwise assume the public block comes first.
            pub_text_block, priv_text_block = block0_text, block1_text

    # Enable more-specific files to override the combined file, if both exist

    pub_only_name = name + ".public.b64.txt"
    if os.path.isfile(pub_only_name):
        print("Loading public file ", pub_only_name)
        pub_text_block = open(pub_only_name, "r").read()
        hdrs = list(re.finditer(header_rex, pub_text_block, re.MULTILINE))
        if len(hdrs) != 1:
            print(" Warning: too %s headers in public file" % ("many" if len(hdrs ) >1 else "few"))

    priv_only_name = name + ".PRIVATE.b64.txt"
    if os.path.isfile(priv_only_name):
        print("Loading private file ", priv_only_name)
        priv_text_block = open(priv_only_name, "r").read()
        hdrs = list(re.finditer(header_rex, priv_text_block, re.MULTILINE))
        if len(hdrs) != 1:
            print(" Warning: too %s headers in public file" % ("many" if len(hdrs) > 1 else "few"))

    # Ensure friendly (visible) text-fields (if any) match the secure binary info.
    # This also extracts and converts the base64 secure block parts.
    pub_block = check_friendly_fields(pub_text_block, CERT_SCHEMA)
    priv_block = check_friendly_fields(priv_text_block, PRIV_CRCWRAPPED)


    return pub_block, priv_block


# ============================== Friendly Fields ===============================================

# In: block_part bytes, schema for first dict, field names to output in friendly format
# Out: field names & values as text lines (or exceptions)

def make_friendly_fields(block_part, schema, friendly_field_names):
    # --- get to that first dict ---
    # Assume standard pub_bytes structure (chain with header)
    # We can't use load() here because load() does mandatory schema checks and we
    dx0 = structure.extract_first_dict(block_part, schema)

    # --- Cross-check whether wanted fields exist (and map names to types) ---
    # This is because we're doing this with payloads as well as certs
    # The rest of the SignVerify system is fully payload-agnostic but we aren't.
    types_by_name = {}
    for typ, name in [i[:2] for i in schema]:
        if name in dx0 and name in friendly_field_names:
            types_by_name[name] = typ
    if not types_by_name:
        raise ValueError("No wanted friendly fields found in the secure block")
        # note: should this just be a warning & continue?

    # --- Convert wanted fields to a textual representation where possible ---
    # order by the friendly_field_names parameter
    line_items = []
    for name in friendly_field_names:
        if name not in types_by_name:
            continue
        fname = name.title().replace("_" ," ")
        typ = types_by_name[name]
        val = dx0[name]     # in
        fval = ""   # out
        # --- Value converters ---
        if typ in (b3.BYTES, b3.LIST, b3.DICT, 11, 12):  # cant be str-converted
            raise TypeError("Visible field '%s' cannot be text-converted (type %s), skipping" %
            (name, b3.b3_type_name(typ)))
        elif typ == b3.SCHED:
            fval = "%s, %s" % (val.strftime("%-I:%M%p").lower(), val.strftime("%-d %B %Y"))
        elif typ == b3.BASICDATE:
            fval = val.strftime("%-d %B %Y")
        else:
            fval = str(val)
        line_items.append((fname, fval))

    # --- Make stuff line up nicely ---
    longest_name_len = functools.reduce(max, [len(i[0]) for i in line_items], 0)
    lines = ["[ %s ]  %s" % (str.ljust(fname, longest_name_len), fval) for fname, fval in
             line_items]
    return '\n'.join(lines)


# Note: unlike make_friendly_fields, we raise exceptions when something is wrong
# In: text with header line, friendly-fields lines, followed by the base64 of the secure public or private block.
# Out: exceptions or True.
# We're pretty strict compared to make, any deviations at all will raise an exception.
#   This includes spurious fields, etc.
# We expect there to be an empty line (or end of file) after the base64 block, and NOT more stuff.
#   This means EOF immediately after the base64 block is an error.


def check_friendly_fields(text_part, schema):
    types_by_name = {i[1]: i[0] for i in schema}
    # --- Ensure vertical structure is legit ---
    # 1 or no header line (-), immediately followed by 0 or more FF lines ([),
    # immediately followd by base64 then a mandatory whitespace (e.g empty line).
    lines = text_part.splitlines()
    c0s = ''.join([line[0] if line else ' ' for line in lines]) + ' '
    X = re.match(r"^\s*(-?)(\[*)([a-zA-Z0-9/=+]+) ", c0s)
    if not X:
        raise StructureError("File text vertical structure is invalid")
    ff_lines = lines[X.start(2): X.end(2)]  # extract FF lines
    b64_lines = lines[X.start(3): X.end(3)]  # extract base64 lines
    b64_block = ''.join(b64_lines)
    bytes_part = base64.b64decode(b64_block)

    # --- get to that first dict in the secure block ---
    # Assume standard pub_bytes structure (chain with header)
    # Let these just exception out.
    dx0 = structure.extract_first_dict(bytes_part, schema)

    # --- Cross-check each Friendy Field line ---
    for ff in ff_lines:
        # --- Extract friendly name & value ---
        fX = re.match(r"^\[ (.*) ]  (.*)$", ff)
        if not fX:
            raise TamperError("Invalid format for visible field line %r" % ff[:32])
        fname, fval = fX.groups()

        # --- convert name ---
        # spaces aren't allowed in code schema field names because AttrDict, only underscores so
        # 1:1 conversion back is easy.
        name = fname.strip().lower().replace(" ", "_")
        fval = fval.strip()  # some converters are finicky about trailing spaces

        # --- Check name presence ---
        if name not in types_by_name:
            raise TamperError("Visible field '%s' is not present in the secure area" % (name,))
        typ = types_by_name[name]

        # --- convert value ---
        if typ == b3.UTF8:
            val = str(fval)  # actually the incoming text should already be utf8 anyway
        elif typ == b3.UVARINT:
            val = int(fval)
        elif typ == b3.BOOL:
            val = bool(fval.lower().strip() == "True")
        # elif typ == b3.SCHED:   # todo: this is the wrong way around
        #    val = "%s, %s" % (fval.strftime("%-I:%M%p").lower(), fval.strftime("%-d %B %Y"))
        elif typ == b3.BASICDATE:
            val = datetime.datetime.strptime(fval, "%d %B %Y").date()
        else:
            raise TamperError("Visible field '%s' cannot be type-converted" % (name,))

        # --- Compare value ---
        if name not in dx0:  # could happen if field is optional in the schema
            raise TamperError("Visible field '%s' is not present in the secure area" % (name,))
        secure_val = dx0[name]
        if secure_val != val:
            raise TamperError("Field '%s' visible value %r does not match secure value %r" % (
            name, val, secure_val))

    return bytes_part  # success

