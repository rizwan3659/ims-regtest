/* SPDX-License-Identifier: MIT */
#ifndef DIGEST_H
#define DIGEST_H

#include <stddef.h>

struct challenge {
	char realm[64], nonce[96], opaque[64];
	int qop_auth;  /* server offered qop="auth" */
};

/* Parses the value of a WWW-Authenticate header (Digest scheme only).
 * Returns 0, or -1 if it is not a usable Digest MD5 challenge. */
int digest_parse_challenge(const char *v, size_t n, struct challenge *c);

/* response = MD5(HA1:nonce:nc:cnonce:qop:HA2) with qop=auth, or
 * MD5(HA1:nonce:HA2) without qop (RFC 2617 s.3.2.2.1). */
void digest_response(const char *user, const char *realm, const char *pass,
		     const char *method, const char *uri, const char *nonce,
		     const char *nc, const char *cnonce, int qop_auth, char out[33]);

/* Pulls one parameter (e.g. "nonce") out of a header value. Quotes removed. */
int digest_param(const char *v, size_t n, const char *name, char *out, size_t cap);

#endif
