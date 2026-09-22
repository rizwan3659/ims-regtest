/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "registrar.h"
#include "digest.h"
#include "md5.h"
#include "sipmini.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct registrar {
	int fd;
	unsigned drop_pct;
	pthread_t thr;
	unsigned long challenged, registered, forbidden, dropped;
	char secret[33];
	unsigned rng;
};

/* Stateless nonce: bound to the Call-ID and a per-run secret. */
static void nonce_for(struct registrar *r, struct hv callid, char out[33])
{
	char buf[256];
	int n = snprintf(buf, sizeof(buf), "%s:%.*s", r->secret, (int)callid.n, callid.p);
	md5_hex(buf, (size_t)n, out);
}

static int reply(const char *req, size_t len, int code,
		 const char *reason, const char *extra, char *out, size_t cap)
{
	struct hv h;
	int n = snprintf(out, cap, "SIP/2.0 %d %s\r\n", code, reason);
	for (int i = 0; sip_hdr(req, len, "Via", "v", i, &h) && n < (int)cap; i++)
		n += snprintf(out + n, cap - (size_t)n, "Via: %.*s\r\n", (int)h.n, h.p);
	const char *names[][2] = { { "From", "f" }, { "To", "t" }, { "Call-ID", "i" }, { "CSeq", NULL } };
	for (int i = 0; i < 4 && n < (int)cap; i++) {
		if (!sip_hdr(req, len, names[i][0], names[i][1], 0, &h))
			return -1;
		n += snprintf(out + n, cap - (size_t)n, "%s: %.*s%s\r\n", names[i][0],
			      (int)h.n, h.p, i == 1 && !memmem(h.p, h.n, ";tag=", 5) ? ";tag=scscf" : "");
	}
	if (n < (int)cap)
		n += snprintf(out + n, cap - (size_t)n, "%sContent-Length: 0\r\n\r\n", extra);
	return n > 0 && n < (int)cap ? n : -1;
}

static void *serve(void *arg)
{
	struct registrar *r = arg;
	char in[4096], out[4096], extra[512];
	struct sockaddr_storage from;

	for (;;) {
		socklen_t fl = sizeof(from);
		ssize_t n = recvfrom(r->fd, in, sizeof(in) - 1, 0, (struct sockaddr *)&from, &fl);
		if (n <= 0)
			break;
		in[n] = 0;
		if (n == 4 && memcmp(in, "STOP", 4) == 0)
			break;
		if (strncmp(in, "REGISTER ", 9) != 0)
			continue;
		r->rng = r->rng * 1103515245u + 12345u;
		if ((r->rng >> 16) % 100 < r->drop_pct) {
			__atomic_add_fetch(&r->dropped, 1, __ATOMIC_RELAXED);
			continue;
		}

		struct hv callid, auth, to;
		if (!sip_hdr(in, (size_t)n, "Call-ID", "i", 0, &callid) ||
		    !sip_hdr(in, (size_t)n, "To", "t", 0, &to))
			continue;
		char nonce[33];
		nonce_for(r, callid, nonce);
		int len;

		if (!sip_hdr(in, (size_t)n, "Authorization", NULL, 0, &auth)) {
			snprintf(extra, sizeof(extra),
				 "WWW-Authenticate: Digest realm=\"%s\", nonce=\"%s\", "
				 "qop=\"auth\", algorithm=MD5\r\n", REALM, nonce);
			len = reply(in, (size_t)n, 401, "Unauthorized", extra, out, sizeof(out));
			__atomic_add_fetch(&r->challenged, 1, __ATOMIC_RELAXED);
		} else {
			char user[64], rn[96], uri[128], resp[40], nc[16], cn[64], pw[80], want[33];
			int ok = digest_param(auth.p, auth.n, "username", user, sizeof(user)) == 0 &&
				 digest_param(auth.p, auth.n, "nonce", rn, sizeof(rn)) == 0 &&
				 digest_param(auth.p, auth.n, "uri", uri, sizeof(uri)) == 0 &&
				 digest_param(auth.p, auth.n, "response", resp, sizeof(resp)) == 0 &&
				 digest_param(auth.p, auth.n, "nc", nc, sizeof(nc)) == 0 &&
				 digest_param(auth.p, auth.n, "cnonce", cn, sizeof(cn)) == 0 &&
				 strcmp(rn, nonce) == 0;
			if (ok) {
				snprintf(pw, sizeof(pw), "pw-%s", user);
				digest_response(user, REALM, pw, "REGISTER", uri, nonce, nc, cn, 1, want);
				ok = strcmp(want, resp) == 0;
			}
			if (ok) {
				struct hv ct;
				if (sip_hdr(in, (size_t)n, "Contact", "m", 0, &ct))
					snprintf(extra, sizeof(extra), "Contact: %.*s;expires=600\r\n",
						 (int)ct.n, ct.p);
				else
					extra[0] = 0;
				len = reply(in, (size_t)n, 200, "OK", extra, out, sizeof(out));
				__atomic_add_fetch(&r->registered, 1, __ATOMIC_RELAXED);
			} else {
				len = reply(in, (size_t)n, 403, "Forbidden", "", out, sizeof(out));
				__atomic_add_fetch(&r->forbidden, 1, __ATOMIC_RELAXED);
			}
		}
		if (len > 0)
			sendto(r->fd, out, (size_t)len, 0, (struct sockaddr *)&from, fl);
	}
	return NULL;
}

struct registrar *registrar_start(int *port, unsigned drop_pct)
{
	struct registrar *r = calloc(1, sizeof(*r));
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	socklen_t l = sizeof(a);
	int sz = 4 << 20;
	char seed[64];

	if (!r)
		return NULL;
	r->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	setsockopt(r->fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	if (r->fd < 0 || bind(r->fd, (struct sockaddr *)&a, sizeof(a)) < 0 ||
	    getsockname(r->fd, (struct sockaddr *)&a, &l) < 0)
		goto fail;
	*port = ntohs(a.sin_port);
	r->drop_pct = drop_pct;
	r->rng = (unsigned)getpid();
	snprintf(seed, sizeof(seed), "%d-%p", getpid(), (void *)r);
	md5_hex(seed, strlen(seed), r->secret);
	if (pthread_create(&r->thr, NULL, serve, r))
		goto fail;
	return r;
fail:
	if (r->fd >= 0)
		close(r->fd);
	free(r);
	return NULL;
}

void registrar_stop(struct registrar *r)
{
	struct sockaddr_in a;
	socklen_t l = sizeof(a);
	getsockname(r->fd, (struct sockaddr *)&a, &l);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	sendto(fd, "STOP", 4, 0, (struct sockaddr *)&a, l);
	close(fd);
	pthread_join(r->thr, NULL);
	close(r->fd);
	free(r);
}

void registrar_stats(struct registrar *r, unsigned long *c, unsigned long *g,
		     unsigned long *f, unsigned long *d)
{
	*c = __atomic_load_n(&r->challenged, __ATOMIC_RELAXED);
	*g = __atomic_load_n(&r->registered, __ATOMIC_RELAXED);
	*f = __atomic_load_n(&r->forbidden, __ATOMIC_RELAXED);
	*d = __atomic_load_n(&r->dropped, __ATOMIC_RELAXED);
}
