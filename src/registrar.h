/* SPDX-License-Identifier: MIT */
/* A stub S-CSCF registrar for testing: challenges every REGISTER with a
 * digest 401, verifies the answer, and replies 200 OK or 403. The password
 * for user U is "pw-U". It can drop a percentage of incoming requests to
 * simulate packet loss. Runs on its own thread. */
#ifndef REGISTRAR_H
#define REGISTRAR_H

struct registrar;

struct registrar *registrar_start(int *port, unsigned drop_pct);
void registrar_stop(struct registrar *r);
void registrar_stats(struct registrar *r, unsigned long *challenged,
		     unsigned long *registered, unsigned long *forbidden,
		     unsigned long *dropped);

#define REALM "ims.example"

#endif
