/* SPDX-License-Identifier: MIT */
/* Open-loop IMS registration load: UE i starts at t0 + i/rate whether or
 * not earlier UEs have finished (a closed loop would hide queueing delay).
 * Each UE: REGISTER -> 401 (digest challenge) -> REGISTER + Authorization
 * -> 200 OK. Requests are retransmitted on T1, 2*T1, 4*T1... as a UDP UAC
 * would, and every response is checked against the request it answers. */
#define _GNU_SOURCE
#include "loadgen.h"
#include "digest.h"
#include "sipmini.h"

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { IDLE, WAIT_401, WAIT_200, DONE, FAILED };

struct ue {
	int state;
	unsigned cseq, tries;
	double t_first, t_sent;
	size_t msg_len;
	char msg[1024];     /* last request, kept for retransmission */
};

static double now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static size_t build_register(char *out, size_t cap, size_t i, unsigned cseq,
			     const char *auth)
{
	int n = snprintf(out, cap,
		"REGISTER sip:" "ims.example SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK-%zu-%u;rport\r\n"
		"Max-Forwards: 70\r\n"
		"From: <sip:ue%zu@ims.example>;tag=ue%zu\r\n"
		"To: <sip:ue%zu@ims.example>\r\n"
		"Call-ID: reg-%zu@regtest\r\n"
		"CSeq: %u REGISTER\r\n"
		"Contact: <sip:ue%zu@127.0.0.1:5070>\r\n"
		"Expires: 600\r\n"
		"%s"
		"Content-Length: 0\r\n\r\n",
		i, cseq, i, i, i, i, cseq, i, auth);
	return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

static int cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

int loadgen_run(const struct lg_config *c, struct lg_result *res)
{
	memset(res, 0, sizeof(*res));
	if (c->ues == 0 || c->rate <= 0)
		return -1;

	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_in to = { .sin_family = AF_INET, .sin_port = htons((uint16_t)c->port) };
	int sz = 4 << 20;
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	if (fd < 0 || inet_pton(AF_INET, c->host, &to.sin_addr) != 1 ||
	    connect(fd, (struct sockaddr *)&to, sizeof(to)) < 0)
		return -1;

	struct ue *u = calloc(c->ues, sizeof(*u));
	double *lat = calloc(c->ues, sizeof(*lat));
	if (!u || !lat) {
		close(fd);
		return -1;
	}

	size_t started = 0, finished = 0, nlat = 0;
	double t0 = now_ms(), interval = 1000.0 / c->rate;
	char in[4096];

	while (finished < c->ues) {
		double now = now_ms();

		/* start new UEs on schedule */
		while (started < c->ues && now >= t0 + started * interval) {
			struct ue *e = &u[started];
			e->cseq = 1;
			e->msg_len = build_register(e->msg, sizeof(e->msg), started, e->cseq, "");
			e->t_first = e->t_sent = now;
			e->tries = 1;
			e->state = WAIT_401;
			send(fd, e->msg, e->msg_len, 0);
			started++;
		}

		/* responses */
		ssize_t n;
		while ((n = recv(fd, in, sizeof(in) - 1, 0)) > 0) {
			in[n] = 0;
			struct hv cid;
			size_t i;
			if (!sip_hdr(in, (size_t)n, "Call-ID", "i", 0, &cid) ||
			    sscanf(cid.p, "reg-%zu@", &i) != 1 || i >= started)
				continue;
			struct ue *e = &u[i];
			int st = sip_status(in, (size_t)n);
			if ((e->state != WAIT_401 && e->state != WAIT_200) ||
			    sip_cseq(in, (size_t)n) != (long)e->cseq)
				continue; /* stale or duplicate (e.g. answer to a retransmission) */

			if (e->state == WAIT_401 && st == 401) {
				struct hv w;
				struct challenge ch;
				if (!sip_hdr(in, (size_t)n, "WWW-Authenticate", NULL, 0, &w) ||
				    digest_parse_challenge(w.p, w.n, &ch) < 0) {
					e->state = FAILED;
					res->other++;
					finished++;
					continue;
				}
				char user[32], pw[48], cnonce[24], resp[33], auth[512];
				snprintf(user, sizeof(user), "ue%zu", i);
				snprintf(pw, sizeof(pw), c->wrong_password ? "wrong-%s" : "pw-%s", user);
				snprintf(cnonce, sizeof(cnonce), "%08zx", i * 2654435761u);
				digest_response(user, ch.realm, pw, "REGISTER", "sip:ims.example",
						ch.nonce, "00000001", cnonce, ch.qop_auth, resp);
				snprintf(auth, sizeof(auth),
					 "Authorization: Digest username=\"%s\", realm=\"%s\", "
					 "nonce=\"%s\", uri=\"sip:ims.example\", response=\"%s\", "
					 "algorithm=MD5, qop=auth, nc=00000001, cnonce=\"%s\"\r\n",
					 user, ch.realm, ch.nonce, resp, cnonce);
				e->cseq++;
				e->msg_len = build_register(e->msg, sizeof(e->msg), i, e->cseq, auth);
				e->t_sent = now_ms();
				e->tries = 1;
				e->state = WAIT_200;
				send(fd, e->msg, e->msg_len, 0);
			} else if (e->state == WAIT_200 && st == 200) {
				e->state = DONE;
				lat[nlat++] = now_ms() - e->t_first;
				res->ok++;
				finished++;
			} else if (st >= 200) {
				e->state = FAILED;
				if (st == 403)
					res->forbidden++;
				else
					res->other++;
				finished++;
			}
		}

		/* retransmissions and timeouts */
		now = now_ms();
		for (size_t i = 0; i < started; i++) {
			struct ue *e = &u[i];
			if (e->state != WAIT_401 && e->state != WAIT_200)
				continue;
			double wait = (double)c->t1_ms * (1u << (e->tries - 1));
			if (now - e->t_sent < wait)
				continue;
			if (e->tries >= c->max_tries) {
				e->state = FAILED;
				res->timed_out++;
				finished++;
				continue;
			}
			e->tries++;
			e->t_sent = now;
			res->retransmits++;
			send(fd, e->msg, e->msg_len, 0);
		}

		struct pollfd p = { .fd = fd, .events = POLLIN };
		poll(&p, 1, started < c->ues ? 0 : 1);
		if (started < c->ues && now < t0 + started * interval - 1)
			usleep(200);
	}

	res->elapsed_s = (now_ms() - t0) / 1000.0;
	res->achieved_rate = res->ok / res->elapsed_s;
	if (nlat) {
		qsort(lat, nlat, sizeof(*lat), cmp);
		res->p50_ms = lat[nlat / 2];
		res->p95_ms = lat[nlat * 95 / 100];
		res->p99_ms = lat[nlat * 99 / 100];
		res->max_ms = lat[nlat - 1];
	}
	free(u);
	free(lat);
	close(fd);
	return 0;
}
