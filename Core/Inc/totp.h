#ifndef TOTP_H
#define TOTP_H
#include <stdint.h>
#include <stddef.h>

void     sha1_buf(const uint8_t *d, size_t n, uint8_t out[20]);
void     hmac_sha1(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t out[20]);
int      base32_decode(const char *in, uint8_t *out, size_t max);   /* returns bytes, -1 on bad char */
uint32_t hotp_code(const uint8_t *key, size_t kl, uint64_t counter); /* 6-digit code */
int      ct_equal(const uint8_t *a, const uint8_t *b, size_t n);     /* constant-time compare */

#endif
