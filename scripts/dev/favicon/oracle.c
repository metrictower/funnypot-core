/*
 * Independent reference oracle for FP-0230's FaviconHash KAT.
 *
 * Computes  mmh3.hash(base64.encodebytes(bytes))  as a signed int32 — the exact number
 * Shodan/FOFA/lonkero index for http.favicon.hash. This is a straight uint32_t C port of
 * MurmurHash3 x86_32 (Austin Appleby, public domain) — deliberately NOT the PHP 16-bit-split
 * multiply, so it is an INDEPENDENT check on FaviconHash::hash (the KAT cannot be self-consistent
 * on a wrong PHP multiply). base64.encodebytes = standard base64, '\n' every 76 chars + trailing '\n'.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* base64.encodebytes: encode, then insert '\n' after every 76 output chars and one at the end. */
static size_t encodebytes(const uint8_t *in, size_t n, uint8_t *out) {
    /* First produce raw base64 into a temp, then wrap. */
    uint8_t *raw = malloc(((n + 2) / 3) * 4 + 1);
    size_t r = 0;
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = (in[i] << 16) | (in[i+1] << 8) | in[i+2];
        raw[r++] = B64[(v >> 18) & 63];
        raw[r++] = B64[(v >> 12) & 63];
        raw[r++] = B64[(v >> 6) & 63];
        raw[r++] = B64[v & 63];
        i += 3;
    }
    size_t rem = n - i;
    if (rem == 1) {
        uint32_t v = in[i] << 16;
        raw[r++] = B64[(v >> 18) & 63];
        raw[r++] = B64[(v >> 12) & 63];
        raw[r++] = '=';
        raw[r++] = '=';
    } else if (rem == 2) {
        uint32_t v = (in[i] << 16) | (in[i+1] << 8);
        raw[r++] = B64[(v >> 18) & 63];
        raw[r++] = B64[(v >> 12) & 63];
        raw[r++] = B64[(v >> 6) & 63];
        raw[r++] = '=';
    }
    /* Wrap: '\n' after every 76 chars AND a trailing '\n' (chunk_split / encodebytes semantics). */
    size_t o = 0;
    size_t col = 0;
    for (size_t j = 0; j < r; j++) {
        out[o++] = raw[j];
        col++;
        if (col == 76) { out[o++] = '\n'; col = 0; }
    }
    if (col != 0) out[o++] = '\n'; /* trailing '\n' for the final partial line; a 76-aligned line already got one, r==0 gets none — exact chunk_split() semantics */
    free(raw);
    return o;
}

static uint32_t rotl32(uint32_t x, int8_t r) { return (x << r) | (x >> (32 - r)); }

static uint32_t murmur3_x86_32(const uint8_t *data, size_t len, uint32_t seed) {
    uint32_t h1 = seed;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    size_t nblocks = len / 4;
    for (size_t i = 0; i < nblocks; i++) {
        size_t o = i * 4;
        uint32_t k1 = (uint32_t)data[o] | ((uint32_t)data[o+1] << 8) |
                      ((uint32_t)data[o+2] << 16) | ((uint32_t)data[o+3] << 24);
        k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2;
        h1 ^= k1; h1 = rotl32(h1, 13); h1 = h1 * 5 + 0xe6546b64;
    }
    const uint8_t *tail = data + nblocks * 4;
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= (uint32_t)tail[2] << 16; /* fall through */
        case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fall through */
        case 1: k1 ^= (uint32_t)tail[0];
                k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
    }
    h1 ^= (uint32_t)len;
    h1 ^= h1 >> 16; h1 *= 0x85ebca6b; h1 ^= h1 >> 13; h1 *= 0xc2b2ae35; h1 ^= h1 >> 16;
    return h1;
}

static int32_t favhash(const uint8_t *bytes, size_t n) {
    uint8_t *enc = malloc(((n + 2) / 3) * 4 + n / 57 + 8);
    size_t m = encodebytes(bytes, n, enc);
    uint32_t h = murmur3_x86_32(enc, m, 0);
    free(enc);
    return (int32_t)h; /* two's-complement reinterpret == the signed fold */
}

/* Deterministic byte pattern for a given (seed,len): independent of any PHP code. */
static void gen(uint32_t s, size_t len, uint8_t *out) {
    uint32_t x = s * 2654435761u + 12345u;
    for (size_t i = 0; i < len; i++) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;   /* xorshift32 */
        out[i] = (uint8_t)(x & 0xff);
    }
}

static void emit_row(uint32_t s, size_t len) {
    uint8_t buf[4096];
    gen(s, len, buf);
    int32_t h = favhash(buf, len);
    printf("            [");
    for (size_t i = 0; i < len; i++) printf("%s%d", i ? "," : "", buf[i]);
    printf("], %d\n", h);
    /* Note: printed as decimal byte list + expected; a wrapper turns it into PHP. */
}

int main(int argc, char **argv) {
    /* Self-tests against trusted mmh3 anchors (raw string, NOT encodebytes). */
    if (murmur3_x86_32((const uint8_t*)"", 0, 0) != 0) { fprintf(stderr, "SELFTEST FAIL empty\n"); return 2; }
    if ((int32_t)murmur3_x86_32((const uint8_t*)"foo", 3, 0) != -156908512) { fprintf(stderr, "SELFTEST FAIL foo\n"); return 2; }

    if (argc > 1 && strcmp(argv[1], "selftest") == 0) { printf("SELFTEST OK\n"); return 0; }

    if (argc > 1 && strcmp(argv[1], "hexin") == 0) {
        /* Read hex byte-strings from stdin, one per line; emit "<hex> <oracle_signed_int>". */
        char line[65536];
        while (fgets(line, sizeof(line), stdin)) {
            size_t L = strlen(line);
            while (L && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = 0;
            size_t n = L / 2;
            uint8_t *b = malloc(n ? n : 1);
            for (size_t i = 0; i < n; i++) { unsigned v; sscanf(line + i*2, "%2x", &v); b[i] = (uint8_t)v; }
            printf("%s %d\n", line, favhash(b, n));
            free(b);
        }
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "pool") == 0) {
        /* Large favicon-length pool for the buggy/correct divergence hunt (PHP selects the subset). */
        for (uint32_t s = 1; s <= 8000; s++) {
            size_t len = 64 + (s % 400);   /* favicon-ish lengths 64..463 */
            uint8_t buf[4096]; gen(s, len, buf);
            int32_t h = favhash(buf, len);
            printf("%u %zu ", s, len);
            for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
            printf(" %d\n", h);
        }
        return 0;
    }

    /* Default: the varied-length A1a corpus, spanning murmur 4-byte-block edges and the
       base64 76-char wrap. Emitted as PHP-ready "[bytes...], expected" rows. */
    /* len 0 is deliberately omitted: chunk_split('') -> "\n" but base64.encodebytes(b'') -> "",
       the one input where FaviconHash's chunk_split and the scanner reference diverge (moot: no
       favicon is empty). Every KAT vector below is >= 1 byte, where the two are byte-identical. */
    size_t lens[] = {1,2,3,4,5,6,7,8,9,15,16,17,18,19,20,31,32,33,55,56,57,58,59,
                     60,75,76,77,78,113,114,115,118,119,120,121,150,200,255,256,257,
                     300,400,500,512,700,1000,1024};
    uint32_t s = 100;
    for (size_t i = 0; i < sizeof(lens)/sizeof(lens[0]); i++) {
        emit_row(s++, lens[i]);
        emit_row(s++, lens[i]);       /* two distinct seeds per length -> ~96 rows */
    }
    return 0;
}
