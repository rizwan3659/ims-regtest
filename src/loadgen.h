/* SPDX-License-Identifier: MIT */
#ifndef LOADGEN_H
#define LOADGEN_H

#include <stddef.h>

struct lg_config {
	const char *host;       /* registrar address (IPv4) */
	int port;
	size_t ues;             /* number of simulated UEs, one registration each */
	double rate;            /* registrations started per second (open loop) */
	unsigned t1_ms;         /* retransmission timer T1 (RFC 3261: 500 ms) */
	unsigned max_tries;     /* sends per request before giving up */
	int wrong_password;     /* negative test: every UE uses a bad password */
};

struct lg_result {
	size_t ok, forbidden, timed_out, other;
	size_t retransmits;
	double elapsed_s, achieved_rate;
	double p50_ms, p95_ms, p99_ms, max_ms; /* REGISTER sent -> 200 OK, successes only */
};

/* Runs the whole load test. Returns 0 if it ran (check the result for
 * failures), -1 on a setup error. */
int loadgen_run(const struct lg_config *c, struct lg_result *r);

#endif
