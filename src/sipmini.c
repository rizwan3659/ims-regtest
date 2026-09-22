/* SPDX-License-Identifier: MIT */
#include "sipmini.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

int sip_hdr(const char *msg, size_t len, const char *name, const char *compact,
	    int nth, struct hv *out)
{
	const char *p = memchr(msg, '\n', len), *end = msg + len;
	size_t nl = strlen(name), cl = compact ? strlen(compact) : 0;

	if (!p)
		return 0;
	for (p++; p < end;) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		if (!eol || eol[-1] != '\r' || eol == p + 1)
			return 0; /* end of headers or malformed */
		const char *c = memchr(p, ':', (size_t)(eol - p));
		if (c) {
			const char *ne = c;
			while (ne > p && (ne[-1] == ' ' || ne[-1] == '\t'))
				ne--;
			size_t k = (size_t)(ne - p);
			if ((k == nl && strncasecmp(p, name, nl) == 0) ||
			    (cl && k == cl && strncasecmp(p, compact, cl) == 0)) {
				if (nth-- == 0) {
					const char *v = c + 1, *ve = eol - 1;
					while (v < ve && (*v == ' ' || *v == '\t'))
						v++;
					while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t'))
						ve--;
					out->p = v;
					out->n = (size_t)(ve - v);
					return 1;
				}
			}
		}
		p = eol + 1;
	}
	return 0;
}

int sip_status(const char *msg, size_t len)
{
	if (len < 12 || strncmp(msg, "SIP/2.0 ", 8) != 0)
		return -1;
	int s = atoi(msg + 8);
	return s >= 100 && s <= 699 ? s : -1;
}

long sip_cseq(const char *msg, size_t len)
{
	struct hv v;
	if (!sip_hdr(msg, len, "CSeq", NULL, 0, &v) || !v.n)
		return -1;
	char *end;
	long n = strtol(v.p, &end, 10);
	return end > v.p ? n : -1;
}
