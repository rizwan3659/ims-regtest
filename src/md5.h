/* SPDX-License-Identifier: MIT */
/* MD5 (RFC 1321). Needed only because SIP digest auth (RFC 2617/3261)
 * uses it; MD5 is not collision resistant and must not be used for new
 * security designs. */
#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

struct md5 {
	uint32_t s[4];
	uint64_t len;
	uint8_t buf[64];
};

void md5_init(struct md5 *c);
void md5_update(struct md5 *c, const void *data, size_t n);
void md5_final(struct md5 *c, uint8_t out[16]);
void md5_hex(const void *data, size_t n, char out[33]);

#endif
