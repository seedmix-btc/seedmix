/**
 * @file main/crypto/ur.c
 * @brief Decode Blockchain Commons Uniform Resource (UR) payloads.
 *
 * Implements the single-part UR format (BCR-2020-005): the message after
 * "ur:<type>/" is minimal-Bytewords (BCR-2020-012) encoded CBOR, followed by
 * a 4-byte big-endian CRC-32 checksum of that CBOR.
 */

#include "ur.h"
#include "fountain.h"

#include <stdlib.h>
#include <string.h>

/* -- Minimal Bytewords (BCR-2020-012) ---------------------------------- */
/* The 256 four-letter Bytewords.  The minimal encoding keeps only the first
 * and last letter of each word (2 chars per byte, case-insensitive). */
static const char BYTEWORDS[256 * 4 + 1] = "able"
                                           "acid"
                                           "also"
                                           "apex"
                                           "aqua"
                                           "arch"
                                           "atom"
                                           "aunt"
                                           "away"
                                           "axis"
                                           "back"
                                           "bald"
                                           "barn"
                                           "belt"
                                           "beta"
                                           "bias"
                                           "blue"
                                           "body"
                                           "brag"
                                           "brew"
                                           "bulb"
                                           "buzz"
                                           "calm"
                                           "cash"
                                           "cats"
                                           "chef"
                                           "city"
                                           "claw"
                                           "code"
                                           "cola"
                                           "cook"
                                           "cost"
                                           "crux"
                                           "curl"
                                           "cusp"
                                           "cyan"
                                           "dark"
                                           "data"
                                           "days"
                                           "deli"
                                           "dice"
                                           "diet"
                                           "door"
                                           "down"
                                           "draw"
                                           "drop"
                                           "drum"
                                           "dull"
                                           "duty"
                                           "each"
                                           "easy"
                                           "echo"
                                           "edge"
                                           "epic"
                                           "even"
                                           "exam"
                                           "exit"
                                           "eyes"
                                           "fact"
                                           "fair"
                                           "fern"
                                           "figs"
                                           "film"
                                           "fish"
                                           "fizz"
                                           "flap"
                                           "flew"
                                           "flux"
                                           "foxy"
                                           "free"
                                           "frog"
                                           "fuel"
                                           "fund"
                                           "gala"
                                           "game"
                                           "gear"
                                           "gems"
                                           "gift"
                                           "girl"
                                           "glow"
                                           "good"
                                           "gray"
                                           "grim"
                                           "guru"
                                           "gush"
                                           "gyro"
                                           "half"
                                           "hang"
                                           "hard"
                                           "hawk"
                                           "heat"
                                           "help"
                                           "high"
                                           "hill"
                                           "holy"
                                           "hope"
                                           "horn"
                                           "huts"
                                           "iced"
                                           "idea"
                                           "idle"
                                           "inch"
                                           "inky"
                                           "into"
                                           "iris"
                                           "iron"
                                           "item"
                                           "jade"
                                           "jazz"
                                           "join"
                                           "jolt"
                                           "jowl"
                                           "judo"
                                           "jugs"
                                           "jump"
                                           "junk"
                                           "jury"
                                           "keep"
                                           "keno"
                                           "kept"
                                           "keys"
                                           "kick"
                                           "kiln"
                                           "king"
                                           "kite"
                                           "kiwi"
                                           "knob"
                                           "lamb"
                                           "lava"
                                           "lazy"
                                           "leaf"
                                           "legs"
                                           "liar"
                                           "limp"
                                           "lion"
                                           "list"
                                           "logo"
                                           "loud"
                                           "love"
                                           "luau"
                                           "luck"
                                           "lung"
                                           "main"
                                           "many"
                                           "math"
                                           "maze"
                                           "memo"
                                           "menu"
                                           "meow"
                                           "mild"
                                           "mint"
                                           "miss"
                                           "monk"
                                           "nail"
                                           "navy"
                                           "need"
                                           "news"
                                           "next"
                                           "noon"
                                           "note"
                                           "numb"
                                           "obey"
                                           "oboe"
                                           "omit"
                                           "onyx"
                                           "open"
                                           "oval"
                                           "owls"
                                           "paid"
                                           "part"
                                           "peck"
                                           "play"
                                           "plus"
                                           "poem"
                                           "pool"
                                           "pose"
                                           "puff"
                                           "puma"
                                           "purr"
                                           "quad"
                                           "quiz"
                                           "race"
                                           "ramp"
                                           "real"
                                           "redo"
                                           "rich"
                                           "road"
                                           "rock"
                                           "roof"
                                           "ruby"
                                           "ruin"
                                           "runs"
                                           "rust"
                                           "safe"
                                           "saga"
                                           "scar"
                                           "sets"
                                           "silk"
                                           "skew"
                                           "slot"
                                           "soap"
                                           "solo"
                                           "song"
                                           "stub"
                                           "surf"
                                           "swan"
                                           "taco"
                                           "task"
                                           "taxi"
                                           "tent"
                                           "tied"
                                           "time"
                                           "tiny"
                                           "toil"
                                           "tomb"
                                           "toys"
                                           "trip"
                                           "tuna"
                                           "twin"
                                           "ugly"
                                           "undo"
                                           "unit"
                                           "urge"
                                           "user"
                                           "vast"
                                           "very"
                                           "veto"
                                           "vial"
                                           "vibe"
                                           "view"
                                           "visa"
                                           "void"
                                           "vows"
                                           "wall"
                                           "wand"
                                           "warm"
                                           "wasp"
                                           "wave"
                                           "waxy"
                                           "webs"
                                           "what"
                                           "when"
                                           "whiz"
                                           "wolf"
                                           "work"
                                           "yank"
                                           "yawn"
                                           "yell"
                                           "yoga"
                                           "yurt"
                                           "zaps"
                                           "zero"
                                           "zest"
                                           "zinc"
                                           "zone"
                                           "zoom";

static uint16_t s_byteword_decode[26 * 26];
static bool     s_byteword_ready = false;

static int to_lower(int c) {
    if (c >= 'A' && c <= 'Z') return c + ('a' - 'A');
    return c;
}

static bool ascii_ci_eq(const char* a, const char* b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (to_lower((unsigned char)a[i]) != to_lower((unsigned char)b[i])) return false;
    }
    return true;
}

static void bytewords_init(void) {
    if (s_byteword_ready) return;
    memset(s_byteword_decode, 0, sizeof(s_byteword_decode));
    for (size_t i = 0; i < 256; i++) {
        int a                                         = BYTEWORDS[i * 4 + 0] - 'a';
        int b                                         = BYTEWORDS[i * 4 + 3] - 'a';
        s_byteword_decode[(size_t)a * 26 + (size_t)b] = (uint16_t)(i + 1);
    }
    s_byteword_ready = true;
}

/* Decode minimal Bytewords (2 chars per byte).  Returns byte count, or -1. */
static int bytewords_decode(const char* s, size_t len, uint8_t* out, size_t out_cap) {
    if (!s || (len & 1u) || out_cap < len / 2) return -1;
    for (size_t i = 0; i < len; i += 2) {
        int a = to_lower((unsigned char)s[i]);
        int b = to_lower((unsigned char)s[i + 1]);
        if (a < 'a' || a > 'z' || b < 'a' || b > 'z') return -1;
        uint16_t v = s_byteword_decode[(size_t)(a - 'a') * 26 + (size_t)(b - 'a')];
        if (v == 0) return -1;
        out[i / 2] = (uint8_t)(v - 1);
    }
    return (int)(len / 2);
}

/* -- CRC-32 (IEEE 802.3, same as zlib) --------------------------------- */
static uint32_t s_crc32_table[256];
static bool     s_crc32_ready = false;

static void crc32_init(void) {
    if (s_crc32_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc32_table[i] = c;
    }
    s_crc32_ready = true;
}

static uint32_t crc32(const uint8_t* data, size_t len) {
    crc32_init();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = s_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

uint32_t ur_crc32(const uint8_t* data, size_t len) { return crc32(data, len); }

/* -- CBOR byte string -------------------------------------------------- */
/* Parse a definite-length CBOR byte string (major type 2).  On success sets
 * *hdr (header length) and *data_len (payload length). */
static int cbor_byte_string(const uint8_t* buf, size_t len, size_t* hdr, size_t* data_len) {
    if (len == 0 || (buf[0] >> 5) != 2) return -1;
    uint8_t ai = buf[0] & 0x1Fu;
    if (ai < 24) {
        *hdr      = 1;
        *data_len = ai;
        return 0;
    }
    if (ai == 24) {
        if (len < 2) return -1;
        *hdr      = 2;
        *data_len = buf[1];
        return 0;
    }
    if (ai == 25) {
        if (len < 3) return -1;
        *hdr      = 3;
        *data_len = ((size_t)buf[1] << 8) | buf[2];
        return 0;
    }
    if (ai == 26) {
        if (len < 5) return -1;
        *hdr = 5;
        *data_len =
            ((size_t)buf[1] << 24) | ((size_t)buf[2] << 16) | ((size_t)buf[3] << 8) | buf[4];
        return 0;
    }
    /* 8-byte length and indefinite-length byte strings are unsupported. */
    return -1;
}

/* -- Decode ------------------------------------------------------------ */
static bool ur_decode_impl(const char* ur, size_t ur_len, const char* type, size_t type_len,
                           uint8_t** out, size_t* out_len) {
    if (!ur || !out || !out_len) return false;
    *out     = NULL;
    *out_len = 0;

    bytewords_init();
    crc32_init();

    /* "ur:" prefix (case-insensitive scheme). */
    if (ur_len < 3 || to_lower((unsigned char)ur[0]) != 'u' ||
        to_lower((unsigned char)ur[1]) != 'r' || ur[2] != ':')
        return false;

    /* Locate the '/' separating the type from the message. */
    size_t slash = 0;
    for (size_t i = 3; i < ur_len; i++) {
        if (ur[i] == '/') {
            slash = i;
            break;
        }
    }
    if (slash == 0 || slash - 3 != type_len || !ascii_ci_eq(ur + 3, type, type_len)) return false;

    const char* msg     = ur + slash + 1;
    size_t      msg_len = ur_len - slash - 1;
    if (msg_len == 0 || (msg_len & 1u)) return false;

    size_t   cap = msg_len / 2;
    uint8_t* bin = malloc(cap ? cap : 1);
    if (!bin) return false;

    int n = bytewords_decode(msg, msg_len, bin, cap);
    if (n < 5) { /* need at least 1 CBOR byte + 4 checksum bytes */
        free(bin);
        return false;
    }

    size_t   cbor_len = (size_t)n - 4;
    uint32_t want     = ((uint32_t)bin[cbor_len] << 24) | ((uint32_t)bin[cbor_len + 1] << 16) |
                    ((uint32_t)bin[cbor_len + 2] << 8) | (uint32_t)bin[cbor_len + 3];
    if (crc32(bin, cbor_len) != want) {
        free(bin);
        return false;
    }

    uint8_t* cbor = malloc(cbor_len);
    if (!cbor) {
        free(bin);
        return false;
    }
    memcpy(cbor, bin, cbor_len);
    free(bin);

    *out     = cbor;
    *out_len = cbor_len;
    return true;
}

bool ur_decode(const char* ur, size_t ur_len, const char* type, uint8_t** out_cbor,
               size_t* out_cbor_len) {
    if (!type) return false;
    return ur_decode_impl(ur, ur_len, type, strlen(type), out_cbor, out_cbor_len);
}

static const uint8_t PSBT_MAGIC[5] = {0x70, 0x73, 0x62, 0x74, 0xff}; /* "psbt\xff" */

bool ur_psbt_decode(const char* ur, size_t ur_len, uint8_t** out_psbt, size_t* out_psbt_len) {
    if (!ur || !out_psbt || !out_psbt_len) return false;
    *out_psbt     = NULL;
    *out_psbt_len = 0;

    uint8_t* cbor     = NULL;
    size_t   cbor_len = 0;
    if (!ur_decode_impl(ur, ur_len, "psbt", 4, &cbor, &cbor_len) &&
        !ur_decode_impl(ur, ur_len, "crypto-psbt", 11, &cbor, &cbor_len))
        return false;

    /* The PSBT UR type wraps the raw PSBT in a single CBOR byte string. */
    size_t hdr = 0, psbt_len = 0;
    if (cbor_byte_string(cbor, cbor_len, &hdr, &psbt_len) != 0 || hdr + psbt_len != cbor_len ||
        psbt_len < sizeof(PSBT_MAGIC) || memcmp(cbor + hdr, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0) {
        free(cbor);
        return false;
    }

    uint8_t* psbt = malloc(psbt_len);
    if (!psbt) {
        free(cbor);
        return false;
    }
    memcpy(psbt, cbor + hdr, psbt_len);
    free(cbor);

    *out_psbt     = psbt;
    *out_psbt_len = psbt_len;
    return true;
}

/* -- Encode ------------------------------------------------------------ */
bool ur_encode(const char* type, const uint8_t* cbor, size_t cbor_len, char** out_ur) {
    if (!type || !type[0] || !cbor || !out_ur) return false;
    *out_ur = NULL;

    bytewords_init();
    crc32_init();

    size_t type_len = strlen(type);
    /* "ur:" + type + "/" + (cbor_len + 4) bytewords + NUL. */
    if (cbor_len > (SIZE_MAX - 4 - type_len - 9) / 2) return false;
    size_t ur_len = 3 + type_len + 1 + (cbor_len + 4) * 2 + 1;
    char*  ur     = malloc(ur_len);
    if (!ur) return false;

    size_t off = 0;
    memcpy(ur + off, "ur:", 3);
    off += 3;
    memcpy(ur + off, type, type_len);
    off += type_len;
    ur[off++] = '/';

    for (size_t i = 0; i < cbor_len; i++) {
        const char* w = BYTEWORDS + (size_t)cbor[i] * 4;
        ur[off++]     = w[0];
        ur[off++]     = w[3];
    }
    uint32_t crc = crc32(cbor, cbor_len);
    for (int shift = 24; shift >= 0; shift -= 8) {
        const char* w = BYTEWORDS + (size_t)((crc >> shift) & 0xFFu) * 4;
        ur[off++]     = w[0];
        ur[off++]     = w[3];
    }
    ur[off] = '\0';

    *out_ur = ur;
    return true;
}

bool ur_psbt_encode(const uint8_t* psbt, size_t psbt_len, char** out_ur) {
    if (!psbt || psbt_len == 0 || !out_ur) return false;
    *out_ur = NULL;

    uint8_t hdr[5];
    size_t  hdr_len = 0;
    if (psbt_len < 24) {
        hdr[0]  = (uint8_t)(0x40 | psbt_len);
        hdr_len = 1;
    } else if (psbt_len <= 0xFF) {
        hdr[0]  = 0x58;
        hdr[1]  = (uint8_t)psbt_len;
        hdr_len = 2;
    } else if (psbt_len <= 0xFFFF) {
        hdr[0]  = 0x59;
        hdr[1]  = (uint8_t)(psbt_len >> 8);
        hdr[2]  = (uint8_t)psbt_len;
        hdr_len = 3;
    } else if (psbt_len <= 0xFFFFFFFFu) {
        hdr[0]  = 0x5A;
        hdr[1]  = (uint8_t)(psbt_len >> 24);
        hdr[2]  = (uint8_t)(psbt_len >> 16);
        hdr[3]  = (uint8_t)(psbt_len >> 8);
        hdr[4]  = (uint8_t)psbt_len;
        hdr_len = 5;
    } else {
        return false;
    }

    size_t   cbor_len = hdr_len + psbt_len;
    uint8_t* cbor     = malloc(cbor_len);
    if (!cbor) return false;
    memcpy(cbor, hdr, hdr_len);
    memcpy(cbor + hdr_len, psbt, psbt_len);

    bool ok = ur_encode("psbt", cbor, cbor_len, out_ur);
    free(cbor);
    return ok;
}

/* -- Multipart UR (fountain) decoding ---------------------------------- */
/* Split the UR path (after "ur:") into up to `max_comps` non-empty '/' parts.
 * Returns the number of components found, or -1 on a malformed scheme. */
static int ur_split(const char* ur, size_t ur_len, const char** comps, size_t* comp_lens,
                    size_t max_comps) {
    if (ur_len < 3 || to_lower((unsigned char)ur[0]) != 'u' ||
        to_lower((unsigned char)ur[1]) != 'r' || ur[2] != ':')
        return -1;

    size_t n = 0;
    size_t i = 3;
    while (i < ur_len) {
        size_t start = i;
        while (i < ur_len && ur[i] != '/') i++;
        if (i > start) {
            if (n < max_comps) {
                comps[n]     = ur + start;
                comp_lens[n] = i - start;
            }
            n++;
        }
        if (i < ur_len) i++; /* skip '/' */
    }
    return (int)n;
}

static bool cbor_read_uint(const uint8_t* buf, size_t len, size_t* pos, uint64_t* out) {
    if (*pos >= len) return false;
    uint8_t ib = buf[(*pos)++];
    if ((ib >> 5) != 0) return false; /* major type 0 */
    uint8_t ai = ib & 0x1Fu;
    if (ai < 24) {
        *out = ai;
        return true;
    }
    if (ai > 27) return false;
    size_t extra = (size_t)1 << (ai - 24);
    if (*pos + extra > len) return false;
    uint64_t v = 0;
    for (size_t k = 0; k < extra; k++) v = (v << 8) | buf[(*pos)++];
    *out = v;
    return true;
}

static bool cbor_read_bytes(const uint8_t* buf, size_t len, size_t* pos, const uint8_t** data,
                            size_t* data_len) {
    if (*pos >= len) return false;
    uint8_t ib = buf[(*pos)++];
    if ((ib >> 5) != 2) return false; /* major type 2 */
    uint8_t  ai = ib & 0x1Fu;
    uint64_t blen;
    if (ai < 24) {
        blen = ai;
    } else if (ai == 24) {
        if (*pos >= len) return false;
        blen = buf[(*pos)++];
    } else if (ai == 25) {
        if (*pos + 2 > len) return false;
        blen = ((uint64_t)buf[*pos] << 8) | buf[*pos + 1];
        *pos += 2;
    } else if (ai == 26) {
        if (*pos + 4 > len) return false;
        blen = ((uint64_t)buf[*pos] << 24) | ((uint64_t)buf[*pos + 1] << 16) |
               ((uint64_t)buf[*pos + 2] << 8) | buf[*pos + 3];
        *pos += 4;
    } else {
        return false;
    }
    if ((uint64_t)(*pos) + blen > len) return false;
    *data     = buf + *pos;
    *data_len = (size_t)blen;
    *pos += (size_t)blen;
    return true;
}

/* Decode the CBOR array [seq_num, seq_len, message_len, checksum, data]. */
static bool cbor_decode_part(const uint8_t* buf, size_t len, uint32_t* seq_num, size_t* seq_len,
                             size_t* message_len, uint32_t* checksum, const uint8_t** data,
                             size_t* data_len) {
    size_t  pos   = 0;
    size_t  count = 0;
    uint8_t ib    = buf[pos++];
    if ((ib >> 5) != 4) return false; /* major type 4 */
    uint8_t ai = ib & 0x1Fu;
    if (ai < 24)
        count = ai;
    else if (ai == 24) {
        if (pos >= len) return false;
        count = buf[pos++];
    } else
        return false;
    if (count != 5) return false;

    uint64_t v;
    if (!cbor_read_uint(buf, len, &pos, &v) || v > UINT32_MAX) return false;
    *seq_num = (uint32_t)v;
    if (!cbor_read_uint(buf, len, &pos, &v) || v > SIZE_MAX) return false;
    *seq_len = (size_t)v;
    if (!cbor_read_uint(buf, len, &pos, &v) || v > SIZE_MAX) return false;
    *message_len = (size_t)v;
    if (!cbor_read_uint(buf, len, &pos, &v) || v > UINT32_MAX) return false;
    *checksum = (uint32_t)v;
    return cbor_read_bytes(buf, len, &pos, data, data_len);
}

static bool parse_seq_component(const char* s, size_t len, uint32_t* seq_num, size_t* seq_len) {
    size_t dash = 0;
    while (dash < len && s[dash] != '-') dash++;
    if (dash == 0 || dash >= len) return false;

    uint64_t n = 0, m = 0;
    for (size_t i = 0; i < dash; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        n = n * 10 + (uint64_t)(s[i] - '0');
        if (n > UINT32_MAX) return false;
    }
    for (size_t i = dash + 1; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        m = m * 10 + (uint64_t)(s[i] - '0');
        if (m > SIZE_MAX) return false;
    }
    if (n < 1 || m < 1) return false;
    *seq_num = (uint32_t)n;
    *seq_len = (size_t)m;
    return true;
}

struct ur_decoder {
    fountain_decoder_t* fountain;
    const char* const*  types;
    size_t              n_types;
};

/* Return the configured type string that matches `type`, or NULL. */
static const char* ur_type_match(const ur_decoder_t* d, const char* type, size_t type_len) {
    for (size_t i = 0; i < d->n_types; i++) {
        if (strlen(d->types[i]) == type_len && ascii_ci_eq(type, d->types[i], type_len))
            return d->types[i];
    }
    return NULL;
}

ur_decoder_t* ur_decoder_new(const char* const* types, size_t n_types) {
    if (!types || n_types == 0) return NULL;
    for (size_t i = 0; i < n_types; i++) {
        if (!types[i] || !types[i][0]) return NULL;
    }

    ur_decoder_t* d = (ur_decoder_t*)calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->fountain = fountain_decoder_new();
    if (!d->fountain) {
        free(d);
        return NULL;
    }
    d->types   = types;
    d->n_types = n_types;
    return d;
}

void ur_decoder_free(ur_decoder_t* d) {
    if (!d) return;
    fountain_decoder_free(d->fountain);
    free(d);
}

size_t ur_decoder_received(const ur_decoder_t* d) {
    return d ? fountain_decoder_received(d->fountain) : 0;
}

size_t ur_decoder_expected(const ur_decoder_t* d) {
    return d ? fountain_decoder_expected(d->fountain) : 0;
}

int ur_decoder_receive(ur_decoder_t* d, const char* ur, size_t ur_len, uint8_t** out_cbor,
                       size_t* out_cbor_len) {
    if (out_cbor) *out_cbor = NULL;
    if (out_cbor_len) *out_cbor_len = 0;
    if (!d) return -1;

    bytewords_init();

    const char* comps[3];
    size_t      comp_lens[3];
    int         ncomp = ur_split(ur, ur_len, comps, comp_lens, 3);
    if (ncomp < 2) return -1;

    const char* type = ur_type_match(d, comps[0], comp_lens[0]);
    if (!type) return -1;

    /* Single-part UR. */
    if (ncomp == 2) {
        uint8_t* msg     = NULL;
        size_t   msg_len = 0;
        if (!ur_decode(ur, ur_len, type, &msg, &msg_len)) return -1;
        if (out_cbor) {
            *out_cbor = msg;
        } else {
            free(msg);
        }
        if (out_cbor_len) *out_cbor_len = msg_len;
        return 1;
    }

    if (ncomp != 3) return -1;

    uint32_t seq_num = 0;
    size_t   seq_len = 0;
    if (!parse_seq_component(comps[1], comp_lens[1], &seq_num, &seq_len)) return -1;

    size_t   frag_cap = comp_lens[2] / 2;
    uint8_t* frag     = (uint8_t*)malloc(frag_cap ? frag_cap : 1);
    if (!frag) return -1;
    int n = bytewords_decode(comps[2], comp_lens[2], frag, frag_cap);
    if (n < 0) {
        free(frag);
        return -1;
    }

    uint32_t       part_seq_num;
    size_t         part_seq_len, part_msg_len;
    uint32_t       part_crc;
    const uint8_t* part_data;
    size_t         part_data_len;
    bool ok = cbor_decode_part(frag, (size_t)n, &part_seq_num, &part_seq_len, &part_msg_len,
                               &part_crc, &part_data, &part_data_len);
    if (!ok || part_seq_num != seq_num || part_seq_len != seq_len) {
        free(frag);
        return -1;
    }

    uint8_t* msg     = NULL;
    size_t   msg_len = 0;
    int      r = fountain_decoder_receive(d->fountain, part_seq_num, part_seq_len, part_msg_len,
                                     part_crc, part_data, part_data_len, &msg, &msg_len);
    free(frag);
    if (r != 1) return r; /* 0 = keep collecting, -1 = invalid */

    if (out_cbor) {
        *out_cbor = msg;
    } else {
        free(msg);
    }
    if (out_cbor_len) *out_cbor_len = msg_len;
    return 1;
}

/* -- PSBT UR decoder (specialisation of the generic decoder) ----------- */
static const char* const UR_PSBT_TYPES[] = {"psbt", "crypto-psbt"};

ur_psbt_decoder_t* ur_psbt_decoder_new(void) {
    return ur_decoder_new(UR_PSBT_TYPES, sizeof(UR_PSBT_TYPES) / sizeof(UR_PSBT_TYPES[0]));
}

void ur_psbt_decoder_free(ur_psbt_decoder_t* d) { ur_decoder_free(d); }

size_t ur_psbt_decoder_received(const ur_psbt_decoder_t* d) { return ur_decoder_received(d); }

size_t ur_psbt_decoder_expected(const ur_psbt_decoder_t* d) { return ur_decoder_expected(d); }

int ur_psbt_decoder_receive(ur_psbt_decoder_t* d, const char* ur, size_t ur_len, uint8_t** out_psbt,
                            size_t* out_psbt_len) {
    if (out_psbt) *out_psbt = NULL;
    if (out_psbt_len) *out_psbt_len = 0;

    uint8_t* msg     = NULL;
    size_t   msg_len = 0;
    int      r       = ur_decoder_receive(d, ur, ur_len, &msg, &msg_len);
    if (r != 1) return r;

    /* The PSBT UR type wraps the raw PSBT in a single CBOR byte string. */
    size_t hdr = 0, psbt_len = 0;
    if (cbor_byte_string(msg, msg_len, &hdr, &psbt_len) != 0 || hdr + psbt_len != msg_len ||
        psbt_len < sizeof(PSBT_MAGIC) || memcmp(msg + hdr, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0) {
        free(msg);
        return -1;
    }

    uint8_t* psbt = (uint8_t*)malloc(psbt_len);
    if (!psbt) {
        free(msg);
        return -1;
    }
    memcpy(psbt, msg + hdr, psbt_len);
    free(msg);
    if (out_psbt) {
        *out_psbt = psbt;
    } else {
        free(psbt);
    }
    if (out_psbt_len) *out_psbt_len = psbt_len;
    return 1;
}
