
# C3 private & public text-file format saving, loading & validation

import os, base64, re, functools, datetime

import b3

from c3 import structure
from c3.constants import CERT_SCHEMA, PRIV_CRCWRAP_SCHEMA
from c3.errors import StructureError, TamperError

try:
    b64_encode = base64.encodebytes
except AttributeError:                  # py2
    b64_encode = base64.encodestring    # py2

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

def make_pub_txt_str(public_part, name="", desc="", pub_ff_lines=""):
    pub_desc = desc if desc else (name + " - Payload & Public Certs")
    if pub_ff_lines:
        pub_ff_lines += "\n"
    pub_str = asc_header(pub_desc) + "\n" + pub_ff_lines + b64_encode(public_part).decode()
    return pub_str


def write_files(name, public_part, private_part=b"", combine=True, desc="", pub_ff_lines="", priv_ff_lines=""):
    pub_str = make_pub_txt_str(public_part, name, desc, pub_ff_lines)
    priv_desc = (desc or name) + " - PRIVATE Key"
    if priv_ff_lines:
        priv_ff_lines += "\n"
    priv_str = asc_header(priv_desc) + "\n" + priv_ff_lines + b64_encode(private_part).decode()

    if combine:
        fname = name + ".b64.txt"
        with open(fname, "w") as f:
            f.write("\n" +pub_str)
            f.write("\n")
            f.write(priv_str + "\n")
        print("Wrote combined file: " ,fname)
    else:
        fname = name + ".public.b64.txt"
        with open(fname, "w") as f:
            f.write("\n" + pub_str + "\n")
        print("Wrote public file:  ", fname)

        if not private_part:
            return

        fname = name + ".PRIVATE.b64.txt"
        with open(fname, "w") as f:
            f.write("\n" + priv_str + "\n")
        print("Wrote PRIVATE file: ", fname)



def split_text_pub_priv(text_in):
    # regex cap the header lines
    header_rex = r"^-+\[ (.*?) \]-+$"
    hdrs = list(re.finditer(header_rex, text_in, re.MULTILINE))
    num_hdrs = len(hdrs)
    pub_text_block = ""
    priv_text_block = ""

    if num_hdrs not in (1,2):
        raise ValueError("Text needs to have 1 or 2 ---[Headers]--- present")

    if num_hdrs == 2:
        # structure_check wants to see the headers too if they are there.
        block0_text = text_in[hdrs[0].start(): hdrs[1].start()]
        block1_text = text_in[hdrs[1].start():]

        # normally the second block is the private block, but if a user has shuffled things around
        # we cater for that by checking which block has 'PRIVATE' in its header description
        if "PRIVATE" in hdrs[0].group(1):  # Private block comes first (not the normal case)
            pub_text_block, priv_text_block = block1_text, block0_text
        else:  # Otherwise assume the public block comes first.
            pub_text_block, priv_text_block = block0_text, block1_text
    else:                   # 1 header, its either one or the other but not both
        if "PRIVATE" in hdrs[0].group(1):
            priv_text_block = text_in
        else:
            pub_text_block = text_in

    return pub_text_block, priv_text_block





# So we do the header checks like before, to try and keep public private and combined consistent
# But then we glue things together if need be and return a single combined always,
# because the uniloader then processes the text, does splitting, etc later
# (Because it may and does often get called with text strings directly).

# Policy: both members of split do not have to exist. (often pub no priv)
# Policy: combined and split are mutually exclusive, should raise an error.

def load_files2(name):
    header_rex = r"^-+\[ (.*?) \]-+$"
    both_text_block = ""
    pub_text_block = ""
    priv_text_block = ""

    combine_name = name + ".b64.txt"
    if os.path.isfile(combine_name):
        print("Loading combined file ", combine_name)
        both_text_block = open(combine_name, "r").read()
        hdrs = list(re.finditer(header_rex, both_text_block, re.MULTILINE))
        if len(hdrs) != 2:
            raise ValueError("Number of headers in combined file is not 2")

    pub_only_name = name + ".public.b64.txt"
    if os.path.isfile(pub_only_name):
        if both_text_block:
            raise ValueError("Both combined and public-only files exist, please remove one")
        print("Loading public file ", pub_only_name)
        pub_text_block = open(pub_only_name, "r").read()
        hdrs = list(re.finditer(header_rex, pub_text_block, re.MULTILINE))
        if len(hdrs) != 1:
            print(" Warning: too %s headers in public file" % ("many" if len(hdrs ) >1 else "few"))

    priv_only_name = name + ".PRIVATE.b64.txt"
    if os.path.isfile(priv_only_name):
        if both_text_block:
            raise ValueError("Both combined and public-only files exist, please remove one")
        print("Loading private file ", priv_only_name)
        priv_text_block = open(priv_only_name, "r").read()
        hdrs = list(re.finditer(header_rex, priv_text_block, re.MULTILINE))
        if len(hdrs) != 1:
            print(" Warning: too %s headers in public file" % ("many" if len(hdrs) > 1 else "few"))

    if not both_text_block:
        both_text_block = pub_text_block + "\n\n" + priv_text_block
    return both_text_block


# Like load_files but if the public block part is a string. (e.g. cert stored in code)
# Note: users can pass in their own schema, for check visible fields to run on their stuff.

def pub_block_from_string(pub_text_block, schema=CERT_SCHEMA, field_map=None):
    pub_block = text_to_binary_block(pub_text_block, schema, field_map)
    return pub_block


# ============================== visible Fields ===============================================

# In:  field_names is a list but the members can be 2-tuples mapping dict_key to visible_name
#  e.g ["org", "Organization"], "hostnames", ["typ", "License Type"], "issued_date", ["expires", "Expiry Date"]
#      if the member is just a string then it is name.title().replace("_"," ")'ed.
# Out: key_names list, key_to_visible dict, visible_to_key dict

def map_field_names(field_names):
    if not field_names:
        field_names = []            # normalise if supplied None
    key_names = []
    key_to_visible = {}
    visible_to_key = {}

    # --- field_names may have some visible-name overrides in it ---
    for fn in field_names:
        if isinstance(fn, (tuple, list)):       # (key_name,visible_name) map item
            key_name, visible_name = fn
        else:
            key_name = fn                       # just the key name
            visible_name = fn.title().replace("_", " ")
        key_names.append(key_name)
        key_to_visible[key_name] = visible_name
        visible_to_key[visible_name] = key_name

    return key_names, key_to_visible, visible_to_key


# In: block_part bytes, schema for first dict, field names to output in visible format
# Out: field names & values as text lines (or exceptions)

# field_names isn't optional because we wouldn't be here if we weren't making visible fields

def make_visible_fields(block_part, schema, field_names):
    # --- get to that first dict ---
    # Assume standard pub_bytes structure (chain with header)
    # We can't use load() here because load() does mandatory schema checks and we
    dx0 = structure.extract_first_dict(block_part, schema)
    key_names, key_to_visible, _ = map_field_names(field_names)

    # --- Cross-check whether wanted fields exist (and map names to types) ---
    # This is because we're doing this with payloads as well as certs
    # The rest of the SignVerify system is fully payload-agnostic but we aren't.
    types_by_name = {}
    for typ, name in [i[:2] for i in schema]:
        if name in dx0 and name in key_names:
            types_by_name[name] = typ
    if not types_by_name:
        raise ValueError("No wanted visible fields found in the secure block")
        # note: should this just be a warning & continue?

    # --- Convert wanted fields to a textual representation where possible ---
    # order by the visible_field_names parameter
    line_items = []
    for name in key_names:
        if name not in types_by_name:
            continue
        fname = key_to_visible[name]
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
    lines = ["[ %s ]  %s" % (fname.ljust(longest_name_len), fval) for fname, fval in
             line_items]
    return '\n'.join(lines)



# Note: unlike make_visible_fields, we raise exceptions when something is wrong
# In: text cert or cert-like test (header, vis-fields, base64 block), optional vis fields schema & map
# Out: exceptions or True.
# We're pretty strict compared to make, any deviations at all will raise an exception.
#   This includes spurious fields, etc.

# This does 2 jobs, which unfortunately are somewhat intertwined:
# 1) validate textual structure & extract the base64 part & convert it to binary
# 2) Tamper-cross-check the Visible Fields (if any) with their binary block counterparts.

# Policy: if no vis_map schema assume CERT_SCHEMA.
# Todo: PRIV_CRCWRAP_SCHEMA etc - peek bytes_part's tag & select schema from that.

def text_to_binary_block(text_part, vis_map=None):
    # --- Ensure vertical structure is legit ---
    # 1 or no header line (-), immediately followed by 0 or more VF lines ([),
    # immediately followd by base64 then: a mandatory whitespace (e.g empty line)
    # (or a line starting with a -)
    lines = text_part.splitlines()
    c0s = ''.join([line[0] if line else ' ' for line in lines]) + ' '
    X = re.match(r"^\s*(-?)(\[*)([a-zA-Z0-9/=+]+)[ \-]", c0s)
    if not X:
        raise StructureError("File text vertical structure is invalid")
    vf_lines = lines[X.start(2): X.end(2)]  # extract FF lines
    b64_lines = lines[X.start(3): X.end(3)]  # extract base64 lines
    b64_block = ''.join(b64_lines)
    bytes_part = base64.b64decode(b64_block)

    if not vf_lines:            # No visual-fields, we're done
        return bytes_part

    # --- Check Visible/Text Fields ----
    if vis_map and "schema" in vis_map and vis_map["schema"]:
        schema = vis_map["schema"]
    else:
        schema = CERT_SCHEMA
    types_by_name = {i[1]: i[0] for i in schema}
    _, _, visible_to_key = map_field_names(vis_map["fields_map"])

    # --- get to that first dict in the secure block ---
    # Assume standard pub_bytes structure (chain with header)
    # Let these just exception out.
    dx0 = structure.extract_first_dict(bytes_part, schema)

    # --- Cross-check each Friendy Field line ---
    for ff in vf_lines:
        # --- Extract visible name & value ---
        fX = re.match(r"^\[ (.*) ]  (.*)$", ff)
        if not fX:
            raise TamperError("Invalid format for visible field line %r" % ff[:32])
        fname, fval = fX.groups()

        # --- default convert name ---
        fname = fname.strip()
        name = fname.lower().replace(" ", "_")
        # --- custom-override convert name ---
        if fname in visible_to_key:
            name = visible_to_key[fname]
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


#
#
# def load_files(name):
#     header_rex = r"^-+\[ (.*?) \]-+$"
#     pub_text_block = ""
#     priv_text_block = ""
#     pub_block = b""
#     priv_block = b""
#
#     combine_name = name + ".b64.txt"
#     if os.path.isfile(combine_name):
#         print("Loading combined file ", combine_name)
#         both_strs = open(combine_name, "r").read()
#
#         # regex cap the header lines
#         hdrs = list(re.finditer(header_rex, both_strs, re.MULTILINE))
#         if len(hdrs) != 2:
#             print(" Warning: number of headers in combined file is not 2")
#
#         # Structure: first header, first data, second header, second data, end of file
#         # data offsets are start-of-first-header : start-of-second-header,
#         # because check_visible_fields wants to see the headers too if they are there.
#         block0_text = both_strs[hdrs[0].start() : hdrs[1].start()]
#         block1_text = both_strs[hdrs[1].start( ):]
#
#         # normally the second block is the private block, but if a user has shuffled things around
#         # we cater for that by checking which block has 'PRIVATE' in its header description
#         if "PRIVATE" in hdrs[0].group(1):       # Private block comes first (not the normal case)
#             pub_text_block, priv_text_block = block1_text, block0_text
#         else:   # Otherwise assume the public block comes first.
#             pub_text_block, priv_text_block = block0_text, block1_text
#
#     # Enable more-specific files to override the combined file, if both exist
#
#     pub_only_name = name + ".public.b64.txt"
#     if os.path.isfile(pub_only_name):
#         print("Loading public file ", pub_only_name)
#         pub_text_block = open(pub_only_name, "r").read()
#         hdrs = list(re.finditer(header_rex, pub_text_block, re.MULTILINE))
#         if len(hdrs) != 1:
#             print(" Warning: too %s headers in public file" % ("many" if len(hdrs ) >1 else "few"))
#
#     priv_only_name = name + ".PRIVATE.b64.txt"
#     if os.path.isfile(priv_only_name):
#         print("Loading private file ", priv_only_name)
#         priv_text_block = open(priv_only_name, "r").read()
#         hdrs = list(re.finditer(header_rex, priv_text_block, re.MULTILINE))
#         if len(hdrs) != 1:
#             print(" Warning: too %s headers in public file" % ("many" if len(hdrs) > 1 else "few"))
#
#     # Ensure visible (visible) text-fields (if any) match the secure binary info.
#     # This also extracts and converts the base64 secure block parts.
#     if pub_text_block:
#         print("load_files checking pub_block ")
#         print(repr(pub_text_block))
#         pub_block = check_structure_vis_fields(pub_text_block, CERT_SCHEMA)
#
#     if priv_text_block:
#         print("load_files checking priv_block")
#         print(repr(priv_text_block))
#         priv_block = check_structure_vis_fields(priv_text_block, PRIV_CRCWRAP_SCHEMA)
#
#     return pub_block, priv_block
