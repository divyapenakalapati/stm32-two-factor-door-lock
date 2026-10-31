/* Pure C, no HAL: SHA-1, HMAC-SHA1, Base32, HOTP/TOTP (RFC 4226 / 6238) */
#include "totp.h"
#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_blk(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e, f, k, t;
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
    for (int i = 16; i < 80; i++)
        w[i] = ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (int i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        t = ROL(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void sha1_buf(const uint8_t *d, size_t n, uint8_t out[20])
{
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t i = 0;
    for (; i + 64 <= n; i += 64) sha1_blk(h, d + i);
    uint8_t t[128] = {0};
    size_t r = n - i;
    memcpy(t, d + i, r);
    t[r] = 0x80;
    size_t tl = (r < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)n * 8;
    for (int k = 0; k < 8; k++) t[tl - 1 - k] = (uint8_t)(bits >> (8 * k));
    sha1_blk(h, t);
    if (tl == 128) sha1_blk(h, t + 64);
    for (int k = 0; k < 5; k++) {
        out[4*k]   = (uint8_t)(h[k] >> 24);
        out[4*k+1] = (uint8_t)(h[k] >> 16);
        out[4*k+2] = (uint8_t)(h[k] >> 8);
        out[4*k+3] = (uint8_t)h[k];
    }
}

void hmac_sha1(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t out[20])
{
    uint8_t k[64] = {0}, in[64 + 64], o[64 + 20], ih[20];
    if (ml > 64) ml = 64;                 /* we only ever hash 8-byte counters / short msgs */
    if (kl > 64) sha1_buf(key, kl, k); else memcpy(k, key, kl);
    for (int i = 0; i < 64; i++) { in[i] = k[i] ^ 0x36; o[i] = k[i] ^ 0x5C; }
    memcpy(in + 64, msg, ml);
    sha1_buf(in, 64 + ml, ih);
    memcpy(o + 64, ih, 20);
    sha1_buf(o, 84, out);
}

uint32_t hotp_code(const uint8_t *key, size_t kl, uint64_t counter)
{
    uint8_t m[8], hs[20];
    for (int i = 7; i >= 0; i--) { m[i] = (uint8_t)counter; counter >>= 8; }
    hmac_sha1(key, kl, m, 8, hs);
    int off = hs[19] & 0x0F;
    uint32_t bin = ((uint32_t)(hs[off] & 0x7F) << 24) | ((uint32_t)hs[off+1] << 16) |
                   ((uint32_t)hs[off+2] << 8) | hs[off+3];
    return bin % 1000000UL;
}

int base32_decode(const char *in, uint8_t *out, size_t max)
{
    uint32_t buf = 0; int bits = 0; size_t n = 0;
    for (; *in; in++) {
        char c = *in; int v;
        if (c == ' ' || c == '=' || c == '-') continue;
        if (c >= 'a' && c <= 'z') c -= 32;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return -1;
        buf = (buf << 5) | (uint32_t)v; bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (n >= max) return -1;
            out[n++] = (uint8_t)(buf >> bits);
        }
    }
    return (int)n;
}

int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}
