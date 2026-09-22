/* SPDX-License-Identifier: MIT */
#include "digest.h"
#include "md5.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* Walks "name=value, name="quoted value", ..." left to right, so text inside
 * a quoted value can never be mistaken for another parameter. A leading
 * auth scheme ("Digest ") is skipped. Returns 0 if `name` was found. */
int digest_param(const char *v, size_t n, const char *name, char *out, size_t cap)
{
	const char *p = v, *e = v + n;
	size_t nl = strlen(name);

	/* skip the scheme: a first token followed by a space, with no '=' in it */
	const char *t = p;
	while (t < e && !isspace((unsigned char)*t) && *t != '=')
		t++;
	if (t < e && isspace((unsigned char)*t))
		p = t;

	for (;;) {
		while (p < e && (isspace((unsigned char)*p) || *p == ','))
			p++;
		if (p >= e)
			return -1;
		const char *ns = p;
		while (p < e && *p != '=' && !isspace((unsigned char)*p) && *p != ',')
			p++;
		size_t klen = (size_t)(p - ns);
		while (p < e && isspace((unsigned char)*p))
			p++;
		if (p >= e || *p != '=' || klen == 0)
			return -1; /* malformed list */
		p++;
		while (p < e && isspace((unsigned char)*p))
			p++;

		char val[256];
		size_t len = 0;
		if (p < e && *p == '"') {
			p++;
			while (p < e && *p != '"') {
				if (*p == '\\' && p + 1 < e)
					p++; /* quoted-pair */
				if (len + 1 >= sizeof(val))
					return -1;
				val[len++] = *p++;
			}
			if (p >= e)
				return -1; /* unterminated quote */
			p++;
		} else {
			while (p < e && *p != ',' && !isspace((unsigned char)*p)) {
				if (len + 1 >= sizeof(val))
					return -1;
				val[len++] = *p++;
			}
		}
		if (klen == nl && strncasecmp(ns, name, nl) == 0) {
			if (len >= cap)
				return -1;
			memcpy(out, val, len);
			out[len] = 0;
			return 0;
		}
	}
}

int digest_parse_challenge(const char *v, size_t n, struct challenge *c)
{
	char alg[16], qop[32];
	memset(c, 0, sizeof(*c));
	if (n < 7 || strncasecmp(v, "Digest ", 7) != 0)
		return -1;
	if (digest_param(v, n, "realm", c->realm, sizeof(c->realm)) < 0 ||
	    digest_param(v, n, "nonce", c->nonce, sizeof(c->nonce)) < 0)
		return -1;
	if (digest_param(v, n, "algorithm", alg, sizeof(alg)) == 0 &&
	    strcasecmp(alg, "MD5") != 0)
		return -1; /* AKAv1-MD5 etc. need the ISIM; out of scope */
	digest_param(v, n, "opaque", c->opaque, sizeof(c->opaque));
	if (digest_param(v, n, "qop", qop, sizeof(qop)) == 0)
		for (char *t = strtok(qop, ", "); t; t = strtok(NULL, ", "))
			if (strcasecmp(t, "auth") == 0)
				c->qop_auth = 1;
	return 0;
}

void digest_response(const char *user, const char *realm, const char *pass,
		     const char *method, const char *uri, const char *nonce,
		     const char *nc, const char *cnonce, int qop_auth, char out[33])
{
	char a[512], ha1[33], ha2[33];
	int n = snprintf(a, sizeof(a), "%s:%s:%s", user, realm, pass);
	md5_hex(a, (size_t)n, ha1);
	n = snprintf(a, sizeof(a), "%s:%s", method, uri);
	md5_hex(a, (size_t)n, ha2);
	if (qop_auth)
		n = snprintf(a, sizeof(a), "%s:%s:%s:%s:auth:%s", ha1, nonce, nc, cnonce, ha2);
	else
		n = snprintf(a, sizeof(a), "%s:%s:%s", ha1, nonce, ha2);
	md5_hex(a, (size_t)n, out);
}
