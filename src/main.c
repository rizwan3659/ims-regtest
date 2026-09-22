/* SPDX-License-Identifier: MIT */
/* ims-regtest: IMS registration load test.
 *   ims-regtest --target 10.0.0.5:5060 --ues 5000 --rate 500
 * Without --target, a stub registrar is started in-process (--loss N drops
 * N%% of the requests it receives). */
#include "loadgen.h"
#include "registrar.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct lg_config c = { .host = "127.0.0.1", .ues = 2000, .rate = 1000,
			       .t1_ms = 500, .max_tries = 7 };
	unsigned loss = 0;
	char host[64] = "";
	int ch;
	static const struct option o[] = {
		{ "target", required_argument, 0, 't' }, { "ues", required_argument, 0, 'n' },
		{ "rate", required_argument, 0, 'r' }, { "t1", required_argument, 0, '1' },
		{ "loss", required_argument, 0, 'l' }, { "wrong-password", no_argument, 0, 'w' },
		{ 0, 0, 0, 0 },
	};
	while ((ch = getopt_long(argc, argv, "", o, NULL)) != -1) {
		switch (ch) {
		case 't': if (sscanf(optarg, "%63[^:]:%d", host, &c.port) != 2) return 2; c.host = host; break;
		case 'n': c.ues = strtoul(optarg, NULL, 10); break;
		case 'r': c.rate = atof(optarg); break;
		case '1': c.t1_ms = (unsigned)atoi(optarg); break;
		case 'l': loss = (unsigned)atoi(optarg); break;
		case 'w': c.wrong_password = 1; break;
		default:
			fprintf(stderr, "usage: %s [--target ip:port] [--ues N] [--rate R] "
				"[--t1 MS] [--loss PCT] [--wrong-password]\n", argv[0]);
			return 2;
		}
	}

	struct registrar *reg = NULL;
	if (!host[0] && !(reg = registrar_start(&c.port, loss))) {
		fprintf(stderr, "cannot start stub registrar\n");
		return 1;
	}
	struct lg_result r;
	if (loadgen_run(&c, &r) < 0) {
		fprintf(stderr, "load test setup failed\n");
		return 1;
	}
	printf("target %s:%d%s, %zu UEs at %.0f/s, T1 %u ms\n", c.host, c.port,
	       reg ? " (stub registrar)" : "", c.ues, c.rate, c.t1_ms);
	printf("registered %zu, forbidden %zu, timed out %zu, other %zu, retransmits %zu\n",
	       r.ok, r.forbidden, r.timed_out, r.other, r.retransmits);
	printf("elapsed %.2f s, %.0f registrations/s\n", r.elapsed_s, r.achieved_rate);
	if (r.ok)
		printf("latency (REGISTER to 200 OK): p50 %.2f ms, p95 %.2f ms, p99 %.2f ms, max %.2f ms\n",
		       r.p50_ms, r.p95_ms, r.p99_ms, r.max_ms);
	if (reg) {
		unsigned long a, b, f, d;
		registrar_stats(reg, &a, &b, &f, &d);
		printf("stub registrar: challenged %lu, registered %lu, forbidden %lu, dropped %lu\n",
		       a, b, f, d);
		registrar_stop(reg);
	}
	return r.ok == c.ues ? 0 : 1;
}
