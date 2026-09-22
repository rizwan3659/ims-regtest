/* SPDX-License-Identifier: MIT */
#ifndef SIPMINI_H
#define SIPMINI_H

#include <stddef.h>

struct hv { const char *p; size_t n; };

/* nth (0-based) occurrence of a header, by full or compact name.
 * Only looks inside the header block (stops at the blank line).
 * Returns 1 if found. */
int sip_hdr(const char *msg, size_t len, const char *name, const char *compact,
	    int nth, struct hv *out);

/* Status code of a response ("SIP/2.0 401 ..."), or -1. */
int sip_status(const char *msg, size_t len);

/* CSeq number, or -1. */
long sip_cseq(const char *msg, size_t len);

#endif
