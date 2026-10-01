#!/usr/bin/env python3
"""Build PSBT, SeedQR and descriptor test vectors and their QR codes.

Output layout (under ``tests/vectors/``)::

    psbt/
      raw/     <slug>.hex, <slug>.base64          raw BIP-174 PSBT bytes
      ur/      <slug>.v2.ur, <slug>.v1.ur,        Blockchain Commons URs
               <slug>.multipart.ur (one part/line)
      qr-png/  <slug>.v2.png, <slug>.v1.png,      single-part QR codes
               <slug>.part-NN.png                 one PNG per multipart part
      qr-gif/  <slug>.multipart.gif               animated multipart QR
      qr-jpg/  <slug>.v2.jpg                      baseline JPEG (color)
               <slug>.v2.gray.jpg                 baseline JPEG (grayscale)
               <slug>.v2.progressive.jpg          progressive JPEG (rejected)
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
    gif/
      <name>.gif                                  decoder fixtures: frame
                                                  disposal, interlacing,
                                                  transparency, broken files
    bmp/
      rgb565.bmp                                  16 bpp (RGB565) decoder
      argb8888.bmp                                fixture, 8x8 pixels each
                                                  32 bpp (ARGB8888)
    png/
      gray-<depth>bit.png                         decoder fixtures: one per
      rgb-<depth>bit.png                          colour type and bit depth,
      rgba-<depth>bit.png                         one per row filter, Adam7,
      gray-alpha-<depth>bit.png                   the edge sizes, and the
      rgba-alpha-<depth>bit.png                   broken files (bad signature,
      palette-<depth>bit.png                      CRC, depth, colour type,
      palette-alpha.png                           palette, chunk length, ...)
      filters.png
      adam7-*.png, wide-16x1-1bit.png, tiny-1x1.png
      broken-*.png

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


def _write_img(path, data, fmt, scale=6, mode="RGB", **kwargs):
    """Write one QR code in another image format (JPEG)."""
    im = Image.open(io.BytesIO(_qr_png(data, scale=scale))).convert(mode)
    im.save(path, fmt, **kwargs)
    im.close()


# --------------------------------------------------------------------------
# GIF decoder fixtures (tests/vectors/gif/)
# --------------------------------------------------------------------------
# Tiny GIFs for the desktop decoder's other paths: the QR animations under
# psbt/qr-gif/ cover the happy path, these cover frame disposal, transparency,
# interlacing and the broken-file cases it has to survive.  Small enough
# (2x2 and 4x4) that the test can spell the expected pixels out itself.
def _gif_frames(data):
    """Yield the offset of every image descriptor in a GIF byte string.

    Walking the blocks (rather than searching for 0x2C) matters: that byte also
    occurs inside compressed data.
    """
    pos = 13
    packed = data[10]
    if packed & 0x80:  # global color table
        pos += 3 * (2 << (packed & 0x07))
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:  # trailer
            return
        if block == 0x21:  # extension: label + sub-block chain
            pos += 2
            while pos < len(data) and data[pos]:
                pos += 1 + data[pos]
            pos += 1
        elif block == 0x2C:  # image descriptor
            yield pos
            packed_frame = data[pos + 9]
            pos += 10
            if packed_frame & 0x80:  # local color table
                pos += 3 * (2 << (packed_frame & 0x07))
            pos += 1  # LZW minimum code size
            while pos < len(data) and data[pos]:
                pos += 1 + data[pos]
            pos += 1
        else:  # not a block GIF defines
            return


def _gif_patch_gce(data, frame, disposal=None, transparency=None):
    """Rewrite the graphic control extension of the given 0-based frame."""
    marker = b"\x21\xf9\x04"
    pos    = -1
    for _ in range(frame + 1):
        pos = data.index(marker, pos + 1)
    if disposal is not None:
        data[pos + 3] = (data[pos + 3] & 0xE3) | ((disposal & 0x07) << 2)
    if transparency is not None:
        data[pos + 3] |= 0x01
        data[pos + 6] = transparency
    return data


def _gif_patch_interlace(data, frame):
    """Set the interlace flag of the given 0-based frame."""
    for i, at in enumerate(_gif_frames(data)):
        if i == frame:
            data[at + 9] |= 0x40
            return data
    raise ValueError("no such frame: %d" % frame)


def _gif_save(path, frames, disposal=None):
    """Save tiny palette frames as one GIF and return its bytes."""
    frames[0].save(path, save_all=True, append_images=frames[1:], duration=100, loop=0)
    with open(path, "rb") as f:
        data = bytearray(f.read())
    for i, d in enumerate(disposal or []):
        if d:
            _gif_patch_gce(data, i, disposal=d)
    return data


def _gif_lzw_literals(pixels, min_code):
    """Pack one literal code per pixel, with a clear code on either side.

    The code size is ``min_code + 1`` and stays there for the whole stream as
    long as no new dictionary entry reaches the next power of two, which a
    handful of pixels never does - so the packing is exact and trivial.
    """
    width = min_code + 1
    codes = [1 << min_code] + [p & (1 << min_code) - 1 for p in pixels] + [(1 << min_code) + 1]
    out   = bytearray()
    acc   = 0
    bits  = 0
    for code in codes:
        acc |= code << bits
        bits += width
        while bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            bits -= 8
    if bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _gif_sub_blocks(data):
    """Wrap a byte string in GIF data sub-blocks."""
    out = bytearray()
    for at in range(0, len(data), 255):
        chunk = data[at : at + 255]
        out.append(len(chunk))
        out += chunk
    out.append(0)
    return bytes(out)


def _gif_write(path, size, palette, bg, frames):
    """Write a GIF by hand: palette, background index and frames verbatim.

    Pillow reorders the palette and rewrites frame indices when it saves, which
    makes it impossible to say which colour a disposal restores to; these
    fixtures need that to be exact, so they are packed here instead.
    ``frames`` is a list of ``(left, top, width, height, indices, disposal,
    transparent_index or None)``.
    """
    width, height = size
    bits          = max(1, (len(palette) - 1).bit_length())
    entries       = palette + [(0, 0, 0)] * ((1 << bits) - len(palette))
    out           = bytearray(b"GIF89a")
    out          += bytes([width & 0xFF, width >> 8, height & 0xFF, height >> 8])
    out.append(0x80 | 0x70 | (bits - 1))
    out.append(bg)
    out.append(0)
    for rgb in entries:
        out += bytes(rgb)
    for left, top, w, h, indices, disposal, transparent in frames:
        packed = (disposal & 0x07) << 2
        if transparent is not None:
            packed |= 0x01
        out += bytes([0x21, 0xF9, 0x04, packed, 0x0A, 0x00, transparent or 0, 0x00])
        out += bytes([0x2C, left & 0xFF, left >> 8, top & 0xFF, top >> 8,
                      w & 0xFF, w >> 8, h & 0xFF, h >> 8, 0x00])
        out.append(8)  # LZW minimum code size
        out += _gif_sub_blocks(_gif_lzw_literals(indices, 8))
    out.append(0x3B)
    with open(path, "wb") as f:
        f.write(out)
    return bytes(out)


def build_gif_fixtures():
    out = os.path.join(OUT, "gif")
    os.makedirs(out, exist_ok=True)

    def palette(*colors):
        """A 2/4-colour palette: black, white, mid greys."""
        flat = [c for rgb in colors for c in rgb]
        return flat + [0] * (768 - len(flat))

    def frame(size, index, pal):
        im = Image.new("P", size, index)
        im.putpalette(pal)
        return im

    black = palette((0, 0, 0), (255, 255, 255), (100, 100, 100), (200, 200, 200))

    # Frame disposal.  Frame 1 is all white, frame 2 paints the right half black
    # and asks for the canvas to be put back - to the background (disposal 2) or
    # to what frame 1 left (disposal 3) - and frame 3 is fully transparent, so it
    # shows exactly that.  The background is a grey no frame paints, which is
    # what tells the two disposal methods apart.
    disposal_pal = [(0, 0, 0), (255, 255, 255), (100, 100, 100), (200, 200, 200)]
    for name, method in (("disposal2.gif", 2), ("disposal3.gif", 3)):
        _gif_write(
            os.path.join(out, name),
            (4, 4),
            disposal_pal,
            2,  # background: the grey palette entry
            [
                (0, 0, 4, 4, [1] * 16, 0, None),
                (2, 0, 2, 4, [0] * 8, method, None),
                (0, 0, 4, 4, [3] * 16, 0, 3),  # fully transparent
            ],
        )

    # Four rows, four grey levels, and the interlace flag set: the decoder has to
    # put the stored rows back in the order GIF stores them in (row 0 stays, row
    # 1 goes to y=2, row 2 to y=1, row 3 stays at y=3).
    graded = palette((0, 0, 0), (255, 255, 255), (100, 100, 100), (200, 200, 200))
    inter = Image.new("P", (4, 4), 0)
    inter.putpalette(graded)
    for y in range(4):
        for x in range(4):
            inter.putpixel((x, y), y)
    data = _gif_save(os.path.join(out, "interlaced.gif"), [inter])
    _gif_patch_interlace(data, 0)
    with open(os.path.join(out, "interlaced.gif"), "wb") as f:
        f.write(data)

    # A plain two-frame animation to check ordinary compositing.
    plain = os.path.join(out, "plain.gif")
    p1 = frame((2, 2), 1, black)
    p2 = frame((2, 2), 0, black)
    _gif_save(plain, [p1, p2])

    # Broken files: sorted so the decoder meets each failure mode in turn.
    with open(plain, "rb") as f:
        good = bytearray(f.read())

    frames = list(_gif_frames(good))
    first_frame = frames[0]
    image_end   = good.index(b"\x3b", first_frame)  # the trailer

    def write(name, data):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)

    write("broken-short-header.gif", good[:10])                    # no room for the LSD
    write("broken-truncated-palette.gif", good[:20])               # global color table cut short
    write("broken-no-trailer.gif", good[:image_end])               # frame decodes, animation has no end
    write("broken-bad-block.gif", good[:first_frame] + b"\x42")    # neither extension nor frame
    write("broken-padding.gif", good[:first_frame] + b"\x00" + good[first_frame:])
    write("broken-comment-subblocks.gif",
          good[:first_frame] + b"\x21\xfe\x05\x41\x42")            # sub-block longer than the chain
    write("broken-gce-size.gif", good[:first_frame] + b"\x21\xf9\x02\x00\x00")
    write("broken-truncated-data.gif", good[: first_frame + 20])   # image data cut in half

    print("gif fixtures      %d files" % len(os.listdir(out)))


# --------------------------------------------------------------------------
# BMP fixtures for the LVGL-backed decoder
# --------------------------------------------------------------------------
def _bmp_write(path, width, height, bpp, rows):
    """Write a bottom-up BMP by hand and return its bytes.

    Pillow cannot write 16- or 32-bit BMPs, and the desktop build wants one of
    each to be driven through the pixel formats LVGL's BMP decoder reports (16
    bpp comes back as RGB565, 32 bpp as ARGB8888), so the headers are packed
    here.  ``rows`` are the image rows top to bottom, each a list of ``bpp / 8``
    byte strings; BMP itself stores them the other way round.
    """
    stride = ((bpp * width + 31) // 32) * 4
    pixels = bytearray()
    for row in reversed(rows):
        line = b"".join(row)
        pixels += line + b"\x00" * (stride - len(line))

    header = bytearray(b"BM")
    header += (14 + 40 + len(pixels)).to_bytes(4, "little")  # file size
    header += bytes(4)                                       # reserved
    header += (14 + 40).to_bytes(4, "little")                # offset to the pixels
    header += (40).to_bytes(4, "little")                     # BITMAPINFOHEADER
    header += width.to_bytes(4, "little")
    header += height.to_bytes(4, "little")                   # positive: bottom-up
    header += (1).to_bytes(2, "little")                      # planes
    header += bpp.to_bytes(2, "little")
    header += bytes(4)                                       # BI_RGB, uncompressed
    header += len(pixels).to_bytes(4, "little")
    header += (2835).to_bytes(4, "little") * 2               # 72 dpi, twice
    header += bytes(8)                                       # palette, important colors

    out = bytes(header + pixels)
    with open(path, "wb") as f:
        f.write(out)
    return out


def build_bmp_fixtures():
    """Tiny BMPs, one per pixel format the desktop decoder has to handle.

    The JPEG vectors already cover 24 bpp (RGB888); these are 16 bpp (RGB565)
    and 32 bpp (ARGB8888), small enough that the test checks every single pixel
    and the row order, which BMP stores bottom-up.
    """
    out = os.path.join(OUT, "bmp")
    os.makedirs(out, exist_ok=True)

    black = (0, 0, 0)
    white = (255, 255, 255)
    green = (0, 255, 0)
    navy  = (0, 0, 255)

    def rgb565(rgb):
        r, g, b = rgb
        return (((r * 31) // 255) << 11 | ((g * 63) // 255) << 5 | ((b * 31) // 255)).to_bytes(2, "little")

    def argb8888(rgb):
        r, g, b = rgb
        return bytes((b, g, r, 255))

    # Every colour twice, eight pixels across; the top row is all black, so a
    # decoder that gets the flip wrong is caught.
    for name, bpp, encode, colors in (
        ("rgb565.bmp", 16, rgb565, (black, white, green, navy)),
        ("argb8888.bmp", 32, argb8888, (black, white, (100, 150, 200), (200, 100, 50))),
    ):
        stripes = [encode(c) for c in colors for _ in range(2)]
        rows    = [[encode(black)] * 8] + [stripes] * 7
        _bmp_write(os.path.join(out, name), 8, 8, bpp, rows)

    print("bmp fixtures      %d files" % len(os.listdir(out)))


# --------------------------------------------------------------------------
# PNG fixtures for the desktop PNG decoder
# --------------------------------------------------------------------------
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_ADAM7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2),
             (0, 1, 1, 2))
PNG_GRAY, PNG_RGB, PNG_PALETTE, PNG_GRAY_A, PNG_RGBA = 0, 2, 3, 4, 6


def _png_channels(color):
    return {PNG_RGB: 3, PNG_GRAY_A: 2, PNG_RGBA: 4}.get(color, 1)


def _png_pack_row(color, depth, pixels):
    """Pack one row of samples into the bytes PNG stores (MSB first)."""
    samples = [s for px in pixels for s in px]
    if depth == 8:
        return bytes(samples)
    if depth == 16:
        return b"".join(s.to_bytes(2, "big") for s in samples)

    out   = bytearray()
    acc   = 0
    bits  = 0
    for s in samples:
        acc = (acc << depth) | (s & ((1 << depth) - 1))
        bits += depth
        while bits >= 8:
            out.append((acc >> (bits - 8)) & 0xFF)
            bits -= 8
    if bits:
        out.append((acc << (8 - bits)) & 0xFF)  # pad the row to a byte
    return bytes(out)


def _png_paeth(a, b, c):
    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _png_filter(row, prev, filt, bpp):
    """Apply one PNG row filter (the inverse of what the decoder undoes)."""
    out = bytearray(len(row))
    for i, v in enumerate(row):
        a = row[i - bpp] if i >= bpp else 0
        c = prev[i - bpp] if i >= bpp else 0
        if filt == 0:
            out[i] = v
        elif filt == 1:
            out[i] = (v - a) & 0xFF
        elif filt == 2:
            out[i] = (v - prev[i]) & 0xFF
        elif filt == 3:
            out[i] = (v - (a + prev[i]) // 2) & 0xFF
        elif filt == 4:
            out[i] = (v - _png_paeth(a, prev[i], c)) & 0xFF
        else:
            raise ValueError("bad filter: %d" % filt)
    return bytes(out)


def _png_chunk(tag, data):
    return len(data).to_bytes(4, "big") + tag + data + zlib.crc32(tag + data).to_bytes(4, "big")


def _png_scanlines(width, height, color, depth, rows, interlace, filters):
    """The filtered scanline stream: a filter byte plus a row, per pass row."""
    bpp    = max(1, (_png_channels(color) * depth) // 8)
    passes = []
    if interlace:
        for x0, y0, dx, dy in PNG_ADAM7:
            pass_rows = [[rows[y][x] for x in range(x0, width, dx)] for y in range(y0, height, dy)]
            pass_rows = [row for row in pass_rows if row]  # a pass can hold no columns
            if pass_rows:
                passes.append(pass_rows)
    else:
        passes.append(rows)

    raw = bytearray()
    for pass_rows in passes:
        prev = None
        for i, pixels in enumerate(pass_rows):
            packed = _png_pack_row(color, depth, pixels)
            filt   = filters[i % len(filters)] if filters else 0
            raw += bytes([filt])
            raw += _png_filter(packed, prev if prev is not None else bytes(len(packed)), filt, bpp)
            prev = packed
    return bytes(raw)


def _png_write(path, width, height, color, depth, rows, palette=None, trns=None, interlace=0,
               filters=None):
    """Write a PNG by hand and return its bytes.

    ``rows`` are the image rows top to bottom, each a list of per-pixel sample
    tuples (one sample for grayscale and palette indexes, three for RGB, and so
    on); ``filters`` lists the row filter to use, cycling over the rows of each
    pass.  ``rows=None`` writes the headers only, without any image data.

    Packed here rather than with Pillow because the fixtures need control Pillow
    does not offer (a chosen filter per row, a palette index past the end of the
    table, an invalid depth) and because Pillow cannot save 16-bit or 1/2/4-bit
    images at all.
    """
    chunks = [
        PNG_SIG,
        _png_chunk(b"IHDR", width.to_bytes(4, "big") + height.to_bytes(4, "big") +
                            bytes([depth, color, 0, 0, interlace]))
    ]
    if palette is not None:
        chunks.append(_png_chunk(b"PLTE", bytes(s for rgb in palette for s in rgb)))
    if trns is not None:
        chunks.append(_png_chunk(b"tRNS", bytes(trns)))
    if rows is not None:
        raw = _png_scanlines(width, height, color, depth, rows, interlace, filters)
        chunks.append(_png_chunk(b"IDAT", zlib.compress(raw, 9)))
    chunks.append(_png_chunk(b"IEND", b""))

    out = b"".join(chunks)
    with open(path, "wb") as f:
        f.write(out)
    return out


def _png_verify(path, width, height, want, samples=None):
    """Read a hand-packed PNG back with Pillow and compare it to ``want``.

    A second, independent decoder reading the file is what catches a mistake in
    the packing or the filtering above: Pillow unfilters every row again and
    checks the chunk CRCs while it does.  ``samples`` is the 16-bit grayscale
    case, where Pillow keeps the samples and clips (rather than scales) them on
    conversion, so the raw values are compared instead.
    """
    im = Image.open(path)
    if im.size != (width, height):
        raise ValueError("%s: Pillow sees %s" % (path, im.size))

    if samples is not None:
        for y in range(height):
            for x in range(width):
                if im.getpixel((x, y)) != samples[y][x][0]:
                    raise ValueError("%s: (%d,%d) is %s, wanted %s" %
                                     (path, x, y, im.getpixel((x, y)), samples[y][x][0]))
        return

    got = im.convert("RGBA")
    for y in range(height):
        for x in range(width):
            if got.getpixel((x, y)) != want[y][x]:
                raise ValueError("%s: (%d,%d) is %s, wanted %s" %
                                 (path, x, y, got.getpixel((x, y)), want[y][x]))


def _png_expected(color, depth, px, palette=None, trns=None):
    """The 8-bit RGBA Pillow should see for one pixel, from the samples written."""
    if color == PNG_PALETTE:
        rgb = palette[px[0]]
        return (rgb[0], rgb[1], rgb[2], trns[px[0]] if trns else 255)
    if color == PNG_GRAY:
        v = px[0] if depth == 8 else px[0] >> 8 if depth == 16 \
            else px[0] * 255 // ((1 << depth) - 1)
        return (v, v, v, 255)
    if color == PNG_RGB:
        r, g, b = px[:3] if depth == 8 else (s >> 8 for s in px[:3])
        return (r, g, b, 255)
    if color == PNG_GRAY_A:
        v, a = px[:2] if depth == 8 else (px[0] >> 8, px[1] >> 8)
        return (v, v, v, a)
    r, g, b, a = px[:4] if depth == 8 else (s >> 8 for s in px[:4])
    return (r, g, b, a)


def _png_rgba_rows(color, depth, rows, palette=None, trns=None):
    return [[_png_expected(color, depth, px, palette, trns) for px in row] for row in rows]


def build_png_fixtures():
    """PNGs for every colour type and bit depth the decoder supports.

    Four pixels wide, so the packed rows of the 1/2/4-bit images straddle byte
    boundaries, and every fixture's grayscale output is small enough to write
    down by hand in the C test - which is why the pixels are grey (the luminance
    of a grey (v, v, v) is exactly v) and the alpha levels are 0, 128 and 255.
    """
    out = os.path.join(OUT, "png")
    os.makedirs(out, exist_ok=True)

    g4      = [[(85 * ((x + y) % 4),) for x in range(4)] for y in range(4)]
    written = []

    def write(name, color, depth, rows, size=(4, 4), **kw):
        path = os.path.join(out, name)
        _png_write(path, size[0], size[1], color, depth, rows, **kw)
        want = _png_rgba_rows(color, depth, rows, kw.get("palette"), kw.get("trns"))
        raw16 = rows if color == PNG_GRAY and depth == 16 else None
        _png_verify(path, size[0], size[1], want, raw16)
        written.append(name)
        return path

    # Grayscale at all five depths.  The samples are the output for depth 8, and
    # 1/2/4-bit levels are spaced so they scale to exact 8-bit values.
    write("gray-1bit.png", PNG_GRAY, 1, [[((x + y) % 2,) for x in range(4)] for y in range(4)])
    write("gray-2bit.png", PNG_GRAY, 2, [[((x + y) % 4,) for x in range(4)] for y in range(4)])
    write("gray-4bit.png", PNG_GRAY, 4, [[((x * 5 + y) % 16,) for x in range(4)] for y in range(4)])
    write("gray-8bit.png", PNG_GRAY, 8, g4)
    write("gray-16bit.png", PNG_GRAY, 16,
          [[(g4[y][x][0] * 257,) for x in range(4)] for y in range(4)])

    # RGB and RGBA, both depths; greys again, so the luminance is the sample.
    write("rgb-8bit.png", PNG_RGB, 8, [[g4[y][x] * 3 for x in range(4)] for y in range(4)])
    write("rgb-16bit.png", PNG_RGB, 16,
          [[tuple(s * 257 for s in g4[y][x] * 3) for x in range(4)] for y in range(4)])
    write("rgba-8bit.png", PNG_RGBA, 8,
          [[g4[y][x] * 3 + (255,) for x in range(4)] for y in range(4)])
    write("rgba-16bit.png", PNG_RGBA, 16,
          [[tuple(s * 257 for s in g4[y][x] * 3 + (255,)) for x in range(4)] for y in range(4)])

    # Alpha is composited over white, so a black pixel stays 255 at alpha 0 and
    # comes out as 127 at alpha 128 (127.5 truncated).
    alpha = [[(0, 255), (0, 128), (0, 0), (255, 255)]] * 4
    write("gray-alpha-8bit.png", PNG_GRAY_A, 8, [[(v, a) for v, a in row] for row in alpha])
    write("gray-alpha-16bit.png", PNG_GRAY_A, 16,
          [[(v * 257, a * 257) for v, a in row] for row in alpha])
    rgba_alpha = [[(0, 0, 0, 255), (0, 0, 0, 128), (0, 0, 0, 0), (255, 255, 255, 255)]] * 4
    write("rgba-alpha-8bit.png", PNG_RGBA, 8, rgba_alpha)
    write("rgba-alpha-16bit.png", PNG_RGBA, 16,
          [[tuple(s * 257 for s in px) for px in row] for row in rgba_alpha])

    # Palette at all four depths, plus a tRNS table that makes one entry half
    # transparent.
    palettes = ((1, [(0, 0, 0), (255, 255, 255)]),
                (2, [(0, 0, 0), (85, 85, 85), (170, 170, 170), (255, 255, 255)]),
                (4, [(0, 0, 0), (51, 51, 51), (119, 119, 119), (255, 255, 255)]),
                (8, [(0, 0, 0), (85, 85, 85), (170, 170, 170), (255, 255, 255)]))
    for depth, entries in palettes:
        write("palette-%dbit.png" % depth, PNG_PALETTE, depth,
              [[((x + y) % len(entries),) for x in range(4)] for y in range(4)], palette=entries)
    write("palette-alpha.png", PNG_PALETTE, 8,
          [[((x + y) % 2,) for x in range(4)] for y in range(4)],
          palette=[(0, 0, 0), (0, 0, 0)], trns=[255, 128])

    # One row per filter: none, sub, up, average, paeth.
    write("filters.png", PNG_GRAY, 8, [[(85 * ((x + y) % 4),) for x in range(4)] for y in range(5)],
          size=(4, 5), filters=[0, 1, 2, 3, 4])

    # Adam7: 4x4 fills every pass, 1x1 leaves six of the seven empty.
    write("adam7-gray-8bit.png", PNG_GRAY, 8, g4, interlace=1)
    write("adam7-rgba-16bit.png", PNG_RGBA, 16,
          [[tuple(s * 257 for s in g4[y][x] * 3 + (255,)) for x in range(4)] for y in range(4)],
          interlace=1)
    write("adam7-1x1.png", PNG_GRAY, 8, [[(255,)]], size=(1, 1), interlace=1)

    # One row that is not a whole number of bytes, and the smallest image there
    # is.
    write("wide-16x1-1bit.png", PNG_GRAY, 1, [[((x % 2),) for x in range(16)]], size=(16, 1))
    write("tiny-1x1.png", PNG_GRAY, 8, [[(0,)]], size=(1, 1))

    # Broken files: every one of these has to fail cleanly.  The good file they
    # are cut from is the 4x4 gray one.
    good = open(os.path.join(out, "gray-8bit.png"), "rb").read()

    def broken(name, data):
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        written.append(name)

    scan = len(PNG_SIG) + 25 + 4  # signature + IHDR chunk
    broken("broken-signature.png", b"\x88PNG\r\n\x1a\n" + good[8:])
    broken("broken-crc.png", good[: scan + 8 + 1] + bytes([good[scan + 8 + 1] ^ 0xFF]) +
           good[scan + 8 + 2:])
    broken("broken-truncated.png", good[: len(good) // 2])

    # Header fields a PNG cannot use.  Their CRCs have to be correct, or the file
    # would be rejected before the values are ever looked at.
    def bad_ihdr(name, width, height, depth, color, interlace):
        broken(name,
               PNG_SIG + _png_chunk(b"IHDR", width.to_bytes(4, "big") + height.to_bytes(4, "big") +
                                    bytes([depth, color, 0, 0, interlace])) +
               _png_chunk(b"IDAT",
                          zlib.compress(_png_scanlines(4, 4, PNG_GRAY, 8, g4, 0, None), 9)) +
               _png_chunk(b"IEND", b""))

    bad_ihdr("broken-zero-size.png", 0, 4, 8, PNG_GRAY, 0)
    bad_ihdr("broken-huge.png", 1 << 18, 1 << 18, 8, PNG_GRAY, 0)
    bad_ihdr("broken-depth.png", 4, 4, 4, PNG_RGB, 0)
    bad_ihdr("broken-colour-type.png", 4, 4, 8, 5, 0)
    bad_ihdr("broken-interlace.png", 4, 4, 8, PNG_GRAY, 2)

    broken("broken-no-palette.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (4).to_bytes(4, "big") +
                                bytes([8, PNG_PALETTE, 0, 0, 0])) +
           _png_chunk(b"IDAT", zlib.compress(_png_scanlines(4, 4, PNG_PALETTE, 8, g4, 0, None),
                                              9)) +
           _png_chunk(b"IEND", b""))
    # An image whose first chunk is not IHDR, one without any IDAT, and one whose
    # first scanline carries a filter type that does not exist.
    broken("broken-no-ihdr.png",
           PNG_SIG + _png_chunk(b"PLTE", bytes([0, 0, 0])) +
           _png_chunk(b"IDAT", zlib.compress(_png_scanlines(4, 4, PNG_GRAY, 8, g4, 0, None),
                                              9)) +
           _png_chunk(b"IEND", b""))
    broken("broken-no-idat.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (4).to_bytes(4, "big") +
                                bytes([8, PNG_GRAY, 0, 0, 0])) + _png_chunk(b"IEND", b""))
    broken("broken-bad-filter.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (4).to_bytes(4, "big") +
                                bytes([8, PNG_GRAY, 0, 0, 0])) +
           _png_chunk(b"IDAT", zlib.compress(b"\x05\x00\x00\x00\x00" * 4, 9)) +
           _png_chunk(b"IEND", b""))

    # A palette whose index runs past the end of the table: the decoder renders
    # that pixel as black instead of reading the palette out of bounds.
    _png_write(os.path.join(out, "broken-palette-index.png"), 4, 4, PNG_PALETTE, 8,
               [[((x + y + 5) % 8,) for x in range(4)] for y in range(4)],
               palette=[(0, 0, 0), (255, 255, 255)])
    written.append("broken-palette-index.png")

    # Scanlines that do not match the header: too few for the declared height,
    # and too many.
    broken("broken-short-raw.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (8).to_bytes(4, "big") +
                                bytes([8, PNG_GRAY, 0, 0, 0])) +
           _png_chunk(b"IDAT", zlib.compress(_png_scanlines(4, 8, PNG_GRAY, 8, g4, 0, None), 9)) +
           _png_chunk(b"IEND", b""))
    broken("broken-long-raw.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (4).to_bytes(4, "big") +
                                bytes([8, PNG_GRAY, 0, 0, 0])) +
           _png_chunk(b"IDAT",
                      zlib.compress(_png_scanlines(4, 8, PNG_GRAY, 8, g4 * 2, 0, None), 9)) +
           _png_chunk(b"IEND", b""))

    # Chunk headers that lie: an IDAT whose length field runs past the end of the
    # file, an IHDR that is not 13 bytes long, and a PLTE that is not a whole
    # number of RGB triples.
    idat_len = int.from_bytes(good[33:37], "big")
    broken("broken-chunk-length.png",
           good[:33] + (idat_len + 100).to_bytes(4, "big") + good[37:])
    broken("broken-ihdr-size.png",
           PNG_SIG + _png_chunk(b"IHDR", bytes(12)) + _png_chunk(b"IEND", b""))
    broken("broken-palette-size.png",
           PNG_SIG + _png_chunk(b"IHDR", (4).to_bytes(4, "big") + (4).to_bytes(4, "big") +
                                bytes([8, PNG_PALETTE, 0, 0, 0])) +
           _png_chunk(b"PLTE", b"\x00\x00\x00\x11") +
           _png_chunk(b"IDAT", zlib.compress(_png_scanlines(4, 4, PNG_GRAY, 8, g4, 0, None), 9)) +
           _png_chunk(b"IEND", b""))

    print("png fixtures      %d files" % len(written))


# --------------------------------------------------------------------------
# PSBT vectors (from Blockchain Commons)
# --------------------------------------------------------------------------
def build_psbt():
    with open(PSBT_JSON) as f:
        vectors = json.load(f)

    for sub in ("raw", "ur", "qr-png", "qr-gif", "qr-jpg"):
        os.makedirs(os.path.join(OUT, "psbt", sub), exist_ok=True)

    for v in vectors:
        slug = _slug(v["name"])
        raw_dir = os.path.join(OUT, "psbt", "raw")
        ur_dir = os.path.join(OUT, "psbt", "ur")
        png_dir = os.path.join(OUT, "psbt", "qr-png")
        gif_dir = os.path.join(OUT, "psbt", "qr-gif")
        jpg_dir = os.path.join(OUT, "psbt", "qr-jpg")

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

        # JPEG: the format LVGL decodes for a picked file.  Rendered at a smaller
        # scale than the PNGs (a JPEG of a dense QR is otherwise a large file
        # for a vector).
        single = v["parts_v2"][0]
        _write_img(os.path.join(jpg_dir, slug + ".v2.jpg"), single, "JPEG", scale=4, quality=85)
        _write_img(os.path.join(jpg_dir, slug + ".v2.gray.jpg"), single, "JPEG", scale=4,
                   mode="L", quality=85)
        # Progressive JPEGs are not baseline: kept as a rejected format.
        _write_img(os.path.join(jpg_dir, slug + ".v2.progressive.jpg"), single, "JPEG", scale=4,
                   quality=85, progressive=True)

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
    build_gif_fixtures()
    build_bmp_fixtures()
    build_png_fixtures()
    print("wrote vectors to", OUT)


if __name__ == "__main__":
    main()
