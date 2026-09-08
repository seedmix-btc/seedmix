#!/usr/bin/env python3
"""Build PSBT and SeedQR test vectors and their QR codes.

Output layout (under ``tests/vectors/``)::

    psbt/
      raw/     <slug>.hex, <slug>.base64          raw BIP-174 PSBT bytes
      ur/      <slug>.v2.ur, <slug>.v1.ur,        Blockchain Commons URs
               <slug>.multipart.ur (one part/line)
      qr-png/  <slug>.v2.png, <slug>.v1.png,      single-part QR codes
               <slug>.part-NN.png                 one PNG per multipart part
      qr-gif/  <slug>.multipart.gif               animated multipart QR
    seedqr/
      raw/     <slug>.compact.bin                 raw entropy (CompactSeedQR)
               <slug>.standard.txt                BIP-39 index digits (Standard SeedQR)
               <slug>.mnemonic.txt                the mnemonic (for reference)
      qr-png/  <slug>.compact.png, <slug>.standard.png
      bip39_english.txt                           BIP-39 English word list
    descriptor/
      raw/     <slug>.txt                         wallet output descriptor text
      ur/      <slug>.output-descriptor.ur        BCR-2023-010 UR (tag 40308)
               <slug>.crypto-output.ur            BCR-2020-010 UR (tag 308)
      qr-png/  <slug>.output-descriptor.png, <slug>.crypto-output.png

Sources:
  * PSBT URs: Blockchain Commons (BCR-2020-006 / keytool-cli) - see
    ``tests/vectors/psbt.json`` for the exact provenance URLs.
  * SeedQR format: SeedSigner docs/seed_qr/README.md.
  * Output descriptor URs: Blockchain Commons BCR-2023-010 / BCR-2020-010;
    encoded here from scratch (CBOR + minimal Bytewords + CRC-32).

Run (needs ``segno`` and ``pillow``)::

    python scripts/gen_vectors.py
"""

import hashlib
import io
import json
import os
import re
import struct
import zlib

import segno
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "vectors")
PSBT_JSON = os.path.join(OUT, "psbt.json")
WORDLIST = os.path.join(OUT, "bip39_english.txt")


def _slug(name):
    s = name.lower()
    out = []
    for ch in s:
        if ch.isalnum():
            out.append(ch)
        elif out and out[-1] != "-":
            out.append("-")
    return "".join(out).strip("-")


def _qr_png(data, scale=6, border=4, error="m"):
    qr = segno.make(data, error=error)
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=scale, border=border)
    return buf.getvalue()


def _write_qr(path, data):
    with open(path, "wb") as f:
        f.write(_qr_png(data))


def _write_gif(path, datas, delay_ms=1000):
    frames = []
    for d in datas:
        im = Image.open(io.BytesIO(_qr_png(d)))
        frames.append(im.convert("RGB"))
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=delay_ms, loop=0)
    for im in frames:
        im.close()


# --------------------------------------------------------------------------
# PSBT vectors (from Blockchain Commons)
# --------------------------------------------------------------------------
def build_psbt():
    with open(PSBT_JSON) as f:
        vectors = json.load(f)

    for sub in ("raw", "ur", "qr-png", "qr-gif"):
        os.makedirs(os.path.join(OUT, "psbt", sub), exist_ok=True)

    for v in vectors:
        slug = _slug(v["name"])
        raw_dir = os.path.join(OUT, "psbt", "raw")
        ur_dir = os.path.join(OUT, "psbt", "ur")
        png_dir = os.path.join(OUT, "psbt", "qr-png")
        gif_dir = os.path.join(OUT, "psbt", "qr-gif")

        with open(os.path.join(raw_dir, slug + ".hex"), "w") as f:
            f.write(v["hex"] + "\n")
        with open(os.path.join(raw_dir, slug + ".base64"), "w") as f:
            f.write(v["base64"] + "\n")

        with open(os.path.join(ur_dir, slug + ".v2.ur"), "w") as f:
            f.write(v["parts_v2"][0] + "\n")
        with open(os.path.join(ur_dir, slug + ".v1.ur"), "w") as f:
            f.write(v["parts_v1"][0] + "\n")
        with open(os.path.join(ur_dir, slug + ".multipart.ur"), "w") as f:
            for p in v["parts_multipart_v2"]:
                f.write(p + "\n")

        _write_qr(os.path.join(png_dir, slug + ".v2.png"), v["parts_v2"][0])
        _write_qr(os.path.join(png_dir, slug + ".v1.png"), v["parts_v1"][0])
        for i, part in enumerate(v["parts_multipart_v2"], 1):
            _write_qr(os.path.join(png_dir, "%s.part-%02d.png" % (slug, i)), part)
        _write_gif(os.path.join(gif_dir, slug + ".multipart.gif"), v["parts_multipart_v2"])

        print("psbt %-22s parts=%d  (%d bytes)" % (slug, len(v["parts_multipart_v2"]),
                                                   len(v["hex"]) // 2))


# --------------------------------------------------------------------------
# SeedQR vectors (SeedSigner format)
# --------------------------------------------------------------------------
def _bip39_indices(entropy: bytes):
    """Return the BIP-39 word indices for an entropy byte string."""
    n_words = len(entropy) // 4 * 3  # 16 -> 12, 32 -> 24
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    value = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    total = ent_bits + cs_bits
    return [(value >> (total - 11 * (i + 1))) & 0x7FF for i in range(n_words)]


def build_seedqr():
    for sub in ("raw", "qr-png"):
        os.makedirs(os.path.join(OUT, "seedqr", sub), exist_ok=True)

    with open(WORDLIST) as f:
        wordlist = [w.strip() for w in f if w.strip()]

    # entropy test vectors: (slug, entropy hex)
    vectors = [
        ("zero-12", "00" * 16),
        ("sequential-12", "".join("%02x" % i for i in range(16))),
        # SeedSigner docs/seed_qr/README.md Test Vector 4 (12 words)
        ("spec-vector-4-12", "5bbd9d71a8ec7990831aff359d426545"),
        ("zero-24", "00" * 32),
        ("sequential-24", "".join("%02x" % i for i in range(32))),
    ]

    for slug, hexstr in vectors:
        entropy = bytes.fromhex(hexstr)
        indices = _bip39_indices(entropy)
        digits = "".join("%04d" % i for i in indices)
        words = " ".join(wordlist[i] for i in indices)

        with open(os.path.join(OUT, "seedqr", "raw", slug + ".compact.bin"), "wb") as f:
            f.write(entropy)
        with open(os.path.join(OUT, "seedqr", "raw", slug + ".standard.txt"), "w") as f:
            f.write(digits + "\n")
        with open(os.path.join(OUT, "seedqr", "raw", slug + ".mnemonic.txt"), "w") as f:
            f.write(words + "\n")

        _write_qr(os.path.join(OUT, "seedqr", "qr-png", slug + ".compact.png"), entropy)
        _write_qr(os.path.join(OUT, "seedqr", "qr-png", slug + ".standard.png"), digits)

        print("seedqr %-18s words=%2d compact=%dB standard=%d digits"
              % (slug, len(indices), len(entropy), len(digits)))


# --------------------------------------------------------------------------
# Output descriptor UR vectors (Blockchain Commons BCR-2023-010 / BCR-2020-010)
# --------------------------------------------------------------------------
def _bytewords():
    """Read the 256-word minimal Bytewords table from main/crypto/ur.c."""
    urc = os.path.join(ROOT, "main", "crypto", "ur.c")
    with open(urc) as f:
        src = f.read()
    m = re.search(r"BYTEWORDS\[256 \* 4 \+ 1\] = (.*?);", src, re.S)
    words = re.findall(r'"([a-z]{4})"', m.group(1))
    assert len(words) == 256
    return words


_BYTEWORDS = _bytewords()


def _cbor_head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25, (value >> 8) & 0xFF, value & 0xFF])
    return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")


def _cbor_uint(v):
    return _cbor_head(0, v)


def _cbor_bool(v):
    return bytes([(7 << 5) | (21 if v else 20)])


def _cbor_bytes(b):
    return _cbor_head(2, len(b)) + b


def _cbor_text(s):
    b = s.encode()
    return _cbor_head(3, len(b)) + b


def _cbor_array(items):
    return _cbor_head(4, len(items)) + b"".join(items)


def _cbor_map(pairs):
    return _cbor_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _cbor_tag(t, item):
    return _cbor_head(6, t) + item


def _ur_encode(typ, cbor):
    msg = cbor + struct.pack(">I", zlib.crc32(cbor) & 0xFFFFFFFF)
    return "ur:%s/%s" % (typ, "".join(_BYTEWORDS[b][0] + _BYTEWORDS[b][3] for b in msg))


def _eckey(pub_hex, v2):
    tag = 40306 if v2 else 306
    return _cbor_tag(tag, _cbor_map([(_cbor_uint(3), _cbor_bytes(bytes.fromhex(pub_hex)))]))


def _path_index(idx, hardened):
    return _cbor_array([_cbor_uint(idx), _cbor_bool(hardened)])


def _path_wildcard():
    return _cbor_array([_cbor_array([]), _cbor_bool(False)])


def _path_pair(a, b):
    return _cbor_array([_path_index(a, False), _path_index(b, False)])


def _multikey(threshold, keys):
    return _cbor_map([(_cbor_uint(1), _cbor_uint(threshold)), (_cbor_uint(2), _cbor_array(keys))])


def _keypath(components, srcfp=None, v2=True):
    tag = 40304 if v2 else 304
    pairs = [(_cbor_uint(1), _cbor_array(components))]
    if srcfp is not None:
        pairs.append((_cbor_uint(2), _cbor_uint(srcfp)))
    return _cbor_tag(tag, _cbor_map(pairs))


def _hdkey(keydata_hex, chaincode_hex, origin=None, children=None, v2=True):
    tag = 40303 if v2 else 303
    pairs = [
        (_cbor_uint(3), _cbor_bytes(bytes.fromhex(keydata_hex))),
        (_cbor_uint(4), _cbor_bytes(bytes.fromhex(chaincode_hex))),
    ]
    if origin is not None:
        pairs.append((_cbor_uint(6), origin))
    if children is not None:
        pairs.append((_cbor_uint(7), children))
    return _cbor_tag(tag, _cbor_map(pairs))


def build_descriptor():
    for sub in ("raw", "ur", "qr-png"):
        os.makedirs(os.path.join(OUT, "descriptor", sub), exist_ok=True)

    xpub = (
        "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5"
        "JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    )
    xpub_keydata = "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0"
    xpub_chain = "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29"

    vectors = []

    # Static P2WPKH from a raw public key (v3 uses an @0 placeholder).
    pub1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    desc1 = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"
    v3_1 = _cbor_map(
        [(_cbor_uint(1), _cbor_text("wpkh(@0)")), (_cbor_uint(2), _cbor_array([_eckey(pub1, True)]))]
    )
    v1_1 = _cbor_tag(404, _eckey(pub1, False))
    vectors.append(("wpkh-static", desc1, v3_1, v1_1))

    # Nested sh(wpkh(...)) exercises the v1 expression tree recursion.
    pub2 = "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"
    desc2 = "sh(wpkh(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
    v3_2 = _cbor_map(
        [(_cbor_uint(1), _cbor_text("sh(wpkh(@0))")), (_cbor_uint(2), _cbor_array([_eckey(pub2, True)]))]
    )
    v1_2 = _cbor_tag(400, _cbor_tag(404, _eckey(pub2, False)))
    vectors.append(("sh-wpkh-static", desc2, v3_2, v1_2))

    # Ranged P2PKH from an xpub with key origin and children.
    desc3 = "pkh([d34db33f/44'/0'/0']" + xpub + "/0/*)"
    origin = _keypath(
        [_path_index(44, True), _path_index(0, True), _path_index(0, True)], srcfp=0xD34DB33F
    )
    children = _keypath([_path_index(0, False), _path_wildcard()])
    v3_3 = _cbor_map(
        [(_cbor_uint(1), _cbor_text("pkh(@0)")), (_cbor_uint(2), _cbor_array([_hdkey(xpub_keydata, xpub_chain, origin=origin, children=children)]))]
    )
    origin_v1 = _keypath(
        [_path_index(44, True), _path_index(0, True), _path_index(0, True)], srcfp=0xD34DB33F, v2=False
    )
    children_v1 = _keypath([_path_index(0, False), _path_wildcard()], v2=False)
    v1_3 = _cbor_tag(403, _hdkey(xpub_keydata, xpub_chain, origin=origin_v1, children=children_v1, v2=False))
    vectors.append(("pkh-xpub-range", desc3, v3_3, v1_3))

    # sh(multi(...)) exercises sh + multi with several keys.
    pub3 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    desc5 = (
        "sh(multi(2,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,"
        "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))"
    )
    v3_5 = _cbor_map(
        [
            (_cbor_uint(1), _cbor_text("sh(multi(2,@0,@1))")),
            (_cbor_uint(2), _cbor_array([_eckey(pub1, True), _eckey(pub2, True)])),
        ]
    )
    v1_5 = _cbor_tag(400, _cbor_tag(406, _multikey(2, [_eckey(pub1, False), _eckey(pub2, False)])))
    vectors.append(("sh-multi-static", desc5, v3_5, v1_5))

    # wsh(sortedmulti(...)) exercises wsh + sortedmulti with three keys.
    desc6 = (
        "wsh(sortedmulti(2,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,"
        "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,"
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))"
    )
    v3_6 = _cbor_map(
        [
            (_cbor_uint(1), _cbor_text("wsh(sortedmulti(2,@0,@1,@2))")),
            (_cbor_uint(2), _cbor_array([_eckey(pub1, True), _eckey(pub2, True), _eckey(pub3, True)])),
        ]
    )
    v1_6 = _cbor_tag(
        401, _cbor_tag(407, _multikey(2, [_eckey(pub1, False), _eckey(pub2, False), _eckey(pub3, False)]))
    )
    vectors.append(("wsh-sortedmulti-static", desc6, v3_6, v1_6))

    # Taproot key-path-only descriptor (x-only internal key).
    xonly = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    desc7 = "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    v3_7 = _cbor_map(
        [(_cbor_uint(1), _cbor_text("tr(@0)")), (_cbor_uint(2), _cbor_array([_eckey(xonly, True)]))]
    )
    v1_7 = _cbor_tag(409, _eckey(xonly, False))
    vectors.append(("tr-static", desc7, v3_7, v1_7))

    # Ranged P2PKH with a <0;1> multi-path (receive + change) child.
    desc8 = "pkh([d34db33f/44'/0'/0']" + xpub + "/<0;1>/*)"
    children8 = _keypath([_path_pair(0, 1), _path_wildcard()])
    v3_8 = _cbor_map(
        [(_cbor_uint(1), _cbor_text("pkh(@0)")), (_cbor_uint(2), _cbor_array([_hdkey(xpub_keydata, xpub_chain, origin=origin, children=children8)]))]
    )
    children8_v1 = _keypath([_path_pair(0, 1), _path_wildcard()], v2=False)
    v1_8 = _cbor_tag(403, _hdkey(xpub_keydata, xpub_chain, origin=origin_v1, children=children8_v1, v2=False))
    vectors.append(("pkh-pair-range", desc8, v3_8, v1_8))

    for slug, desc, v3, v1 in vectors:
        raw_dir = os.path.join(OUT, "descriptor", "raw")
        ur_dir = os.path.join(OUT, "descriptor", "ur")
        png_dir = os.path.join(OUT, "descriptor", "qr-png")

        with open(os.path.join(raw_dir, slug + ".txt"), "w") as f:
            f.write(desc + "\n")

        v3_ur = _ur_encode("output-descriptor", v3)
        v1_ur = _ur_encode("crypto-output", v1)
        with open(os.path.join(ur_dir, slug + ".output-descriptor.ur"), "w") as f:
            f.write(v3_ur + "\n")
        with open(os.path.join(ur_dir, slug + ".crypto-output.ur"), "w") as f:
            f.write(v1_ur + "\n")

        _write_qr(os.path.join(png_dir, slug + ".output-descriptor.png"), v3_ur)
        _write_qr(os.path.join(png_dir, slug + ".crypto-output.png"), v1_ur)

        print("descriptor %-18s v3=%dB v1=%dB" % (slug, len(v3), len(v1)))


def main():
    os.makedirs(OUT, exist_ok=True)
    build_psbt()
    build_seedqr()
    build_descriptor()
    print("wrote vectors to", OUT)


if __name__ == "__main__":
    main()
